/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.servlet;

import it.unicam.cs.saml.SAML2;
import it.unicam.cs.saml.SAML2.AttributeInfo;
import it.unicam.cs.saml.SAML2.ServiceSessionInfo;
import it.unicam.cs.sp.config.Configuration;
import it.unicam.cs.utils.Base64Fast;
import it.unicam.cs.utils.NETUtils;
import it.unicam.cs.utils.Utils;
import it.unicam.cs.utils.X509Utils;
import it.unicam.cs.utils.Utils.LogType;

import java.io.IOException;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LOGOUT extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private Configuration cfg;
	
	public void init(ServletConfig config) throws ServletException {
		try{
			cfg = new Configuration(config.getServletContext().getInitParameter("configFile"));
		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
	}

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try{
			HashMap<String, ServiceSessionInfo> ssiList = new HashMap<String, ServiceSessionInfo>();

			String sessionAttrib = null;
			Enumeration<String> sessionNameList = request.getSession().getAttributeNames();
			while(sessionNameList.hasMoreElements()){
				sessionAttrib = sessionNameList.nextElement();
				if(request.getSession().getAttribute(sessionAttrib) instanceof ServiceSessionInfo)
					ssiList.put(sessionAttrib, (ServiceSessionInfo) request.getSession().getAttribute(sessionAttrib));
			}
			
			PrivateKeyEntry privateKey = X509Utils.readPrivateKey(cfg.getKeystorePath(), cfg.getKeystoreType(), cfg.getPwdKeystore(), cfg.getAliasCertificate(), cfg.getPwdCertificate());
			String spEntityID = SAML2.saml_getEntityIDFromSingleMetadata(cfg.getSpMetadataPath());
			
			if(request.getParameter("ReturnUrl")!=null && !request.getParameter("ReturnUrl").isEmpty()){
				/*
				 mi arriva una richiesta di logout dal servizio
				 1) controllare che in sessione ci sia un ssi con quel url di ritorno come logouturl; se no eccezione
				 2) creare una logoutRequest e inviarla all'idp
				*/
				String serviceLogoutURL = request.getParameter("ReturnUrl");
				String idpEntityId = null;
				AttributeInfo attribNameID = null;
				
				for(ServiceSessionInfo ssi: ssiList.values())
					if(ssi.serviceLogoutURL.equals(serviceLogoutURL)){
						idpEntityId = ssi.idpEntityID;
						attribNameID = SAML2.saml_getAttributeInfo(ssi.attributesObtained, "NameID");
					}
				if(idpEntityId==null)
					throw new Exception("ERROR: Logged-in IdP Infos not present in session for the LogoutUrl: "+serviceLogoutURL);
				
				request.getSession().setAttribute("currentLogoutUrl", serviceLogoutURL);
				
				String federationToUseMetadataUrl = SAML2.saml_chooseFederationToUse(idpEntityId, spEntityID, cfg.getAllFederationMetadataURI());
				String idpLogoutUrl = SAML2.saml_getIdPSingleLogoutServiceLocation(federationToUseMetadataUrl, idpEntityId, true); //TODO leggere il postbinding da file di config?
				if(idpLogoutUrl.isEmpty())
					throw new Exception("ERROR: The IdP " + idpEntityId+ " doesn't support Single Logout");
				
				String relayState = "";
				String samlLogoutRequest = SAML2.sp_generateSamlLogoutRequest(federationToUseMetadataUrl, spEntityID, idpEntityId, attribNameID.name, attribNameID.nameFormat, privateKey);
				Utils.log(samlLogoutRequest, cfg, LogType.requests);
				String samlLogoutRequestB64 = Base64Fast.encodeToString(samlLogoutRequest.getBytes(), false);
				response.getWriter().println(NETUtils.getPOSTRedirectPage(idpLogoutUrl+"?SAMLRequest="+samlLogoutRequestB64+"&RelayState="+relayState));
			}
			
			
			if(request.getParameter("SAMLResponse")!=null && !request.getParameter("SAMLResponse").isEmpty()){
				/*
				 2) se la risposta va bene allora :
				 2.1) leggere da sessione tutti i servizi loggati con lo stesso idp del servizio
				 2.2) aprire la loro pagina di logout con parametro remoteLogout=true
				 2.3) rimuovere da sessione i servizi sloggati
				*/
				String samlResponseB64 = request.getParameter("SAMLResponse");
				String samlResponse = new String(Base64Fast.decode(samlResponseB64));
				Utils.log(samlResponse, cfg, LogType.responses);
				
				String idpEntityID = SAML2.saml_getSamlResponseIssuer(samlResponse);
				
				SAML2.sp_validateSamlResponse(samlResponse, SAML2.saml_chooseFederationToUse(idpEntityID, spEntityID, cfg.getAllFederationMetadataURI()), spEntityID, true); //TODO leggere il postbinding da file di config?
				ArrayList<String> urlLogoutList = new ArrayList<String>();
				for(String ssiKey: ssiList.keySet()){
					ServiceSessionInfo ssi = ssiList.get(ssiKey);
					if(ssi.idpEntityID.equals(idpEntityID)){
						urlLogoutList.add(ssi.serviceLogoutURL+((ssi.serviceLogoutURL.contains("?"))?"&remoteLogout=true":"?remoteLogout=true"));
						request.getSession().removeAttribute(ssiKey);
					}
				}
				String currentLogoutUrl = (String) request.getSession().getAttribute("currentLogoutUrl");
				response.getWriter().println(NETUtils.getPOSTRedirectPageLoadingLogoutUrl(currentLogoutUrl, null, urlLogoutList));
			}
			
			if(request.getParameter("SAMLRequest")!=null && !request.getParameter("SAMLRequest").isEmpty()){
				/*
				 1) leggere da sessione tutti i servizi loggati con lo stesso idp del servizio
				 2) aprire in una nuova scheda la loro pagina di logout con parametro remoteLogout=true
				 3) rimuovere da sessione i servizi sloggati 
				 4) ritornare una risposta di logout
				 */
				String samlRequestB64 = request.getParameter("SAMLRequest");
				String samlRequest = new String(Base64Fast.decode(samlRequestB64));
				Utils.log(samlRequest, cfg, LogType.requests);
				
				String idpEntityID = SAML2.saml_getSamlResponseIssuer(samlRequest);
				
				String federationToUseMetadataUrl = SAML2.saml_chooseFederationToUse(idpEntityID, spEntityID, cfg.getAllFederationMetadataURI());
	
				String idpLogoutUrl = SAML2.saml_getIdPSingleLogoutServiceLocation(federationToUseMetadataUrl, idpEntityID, true); //TODO leggere il postbinding da file di config?
				if(idpLogoutUrl.isEmpty())
					throw new Exception("ERROR: The IdP " + idpEntityID+ " doesn't provide a Single Logout Location");
				
				ArrayList<String> urlLogoutList = new ArrayList<String>();
				
				for(String ssiKey: ssiList.keySet()){
					ServiceSessionInfo ssi = ssiList.get(ssiKey);
					if(ssi.idpEntityID.equals(idpEntityID)){
						urlLogoutList.add(ssi.serviceLogoutURL+((ssi.serviceLogoutURL.contains("?"))?"&remoteLogout=true":"?remoteLogout=true"));
						request.getSession().removeAttribute(ssiKey);
					}
				}
				
				String relayState = request.getParameter("RelayState")!=null?request.getParameter("RelayState"):"";
				String samlLogoutResponse = SAML2.sp_generateSamlLogoutResponse(federationToUseMetadataUrl, spEntityID, idpEntityID, samlRequest, true, null, privateKey);
				Utils.log(samlLogoutResponse, cfg, LogType.responses);
				String samlLogoutResponseB64 = Base64Fast.encodeToString(samlLogoutResponse.getBytes(), false);
				
				response.getWriter().println(NETUtils.getPOSTRedirectPageLoadingLogoutUrl(idpLogoutUrl, "SAMLResponse="+samlLogoutResponseB64+"&RelayState="+relayState, urlLogoutList));
			}
			
		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

	public static void main(String[] args) {
		
	}
}
