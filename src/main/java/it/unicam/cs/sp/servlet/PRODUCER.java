/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.servlet;

import it.unicam.cs.saml.SAML2;
import it.unicam.cs.saml.SAML2.AuthnContext;
import it.unicam.cs.saml.SAML2.AuthnContextComparison;
import it.unicam.cs.saml.SAML2.ServiceSessionInfo;
import it.unicam.cs.sp.config.Configuration;
import it.unicam.cs.utils.Base64Fast;
import it.unicam.cs.utils.IOUtils;
import it.unicam.cs.utils.NETUtils;
import it.unicam.cs.utils.Utils;
import it.unicam.cs.utils.X509Utils;
import it.unicam.cs.utils.XMLUtils;
import it.unicam.cs.utils.Utils.LogType;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.KeyStore.PrivateKeyEntry;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.xpath.XPathConstants;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class PRODUCER extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private Configuration cfg;
	
	public void init(ServletConfig config) throws ServletException {
		try{
			cfg = new Configuration(config.getServletContext().getInitParameter("configFile"));
		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
	}

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try{
			String idpEntityID = request.getParameter("entityID");
			if(idpEntityID == null || idpEntityID.isEmpty())
				throw new Exception("ERROR: entityID not defined");
			
			String currentRelyState = (String)request.getSession().getAttribute("currentRelyState");
			if(currentRelyState==null || currentRelyState.isEmpty())
				throw new Exception("ERROR: Invalid Session State");
			
			ServiceSessionInfo ssi = (ServiceSessionInfo)request.getSession().getAttribute(currentRelyState);

			String serviceURL = ssi.serviceURL;
			String host = NETUtils.getHost(serviceURL);
			int hostId = cfg.isHostAllowed(host);
			if(hostId == -1)
				throw new Exception("ERROR: Host " + host + " is not allowed");
			
			String relayState =  currentRelyState;
			int attributeConsumingServiceIndex = cfg.getAttributeConsumingServiceIndex(hostId);
			boolean signRequest = cfg.getSignSamlRequests(hostId);
			boolean postBinding = cfg.getUsePostBinding(hostId);
			AuthnContext[] authnContextList = ssi.authnContextList;
			AuthnContextComparison authnContextComparisonType = ssi.authnContextComparisonType;
			
			//SPID: in cui si richieda livelli di autenticazione superiori a SPIDL1 ( SPIDL2 o SPIDL3), forceAuthn deve essere true
			boolean forceAuthn = true;
			if(authnContextList!=null)
			    for(AuthnContext authnContext:authnContextList)
			        if(authnContext.equals(AuthnContext.SpidL1))
			            forceAuthn = false;
			
			String spEntityID = SAML2.saml_getEntityIDFromSingleMetadata(cfg.getSpMetadataPath());
			String fedMetadataPath = SAML2.saml_chooseFederationToUse(idpEntityID, spEntityID, cfg.getAllFederationMetadataURI());
			
			PrivateKeyEntry privateKey = null;
			if(signRequest)
				privateKey = X509Utils.readPrivateKey(cfg.getKeystorePath(), cfg.getKeystoreType(), cfg.getPwdKeystore(), cfg.getAliasCertificate(), cfg.getPwdCertificate());
			
			String samlRequest = SAML2.sp_generateSamlAuthnRequest(fedMetadataPath, spEntityID, idpEntityID, attributeConsumingServiceIndex, privateKey, postBinding, forceAuthn, authnContextList, authnContextComparisonType);			
			String samlRequestB64 = Base64Fast.encodeToString(samlRequest.getBytes(), false);
			
			Utils.log(samlRequest, cfg, LogType.requests);
			
			String idpUrl = SAML2.saml_getIdPSingleSignOnServiceLocation(fedMetadataPath, idpEntityID, postBinding);
			
			java.io.PrintWriter out = response.getWriter();
			if(postBinding)
				out.println(NETUtils.getPOSTRedirectPage(idpUrl+"?SAMLRequest="+samlRequestB64+"&RelayState="+relayState));
			else{
				Document samlRequestXml = XMLUtils.getXmlDocFromString(samlRequest);
				String signatureAlg = (String) XMLUtils.execXPath(samlRequestXml.getDocumentElement(), "//*[local-name()='SignatureMethod']/@Algorithm", XPathConstants.STRING);
				
				Node signatureNode =  (Node) XMLUtils.execXPath(samlRequestXml.getDocumentElement(), "//*[namespace-uri()='http://www.w3.org/2000/09/xmldsig#' and local-name()='Signature']", XPathConstants.NODE);
				if(signatureNode!=null)
					samlRequestXml.getDocumentElement().removeChild(signatureNode);
				
				samlRequest = XMLUtils.getStringFromXmlDoc(samlRequestXml);				
				samlRequestB64 = Base64Fast.encodeToString(IOUtils.compressToDeflate(samlRequest.getBytes("UTF-8")), false);

				if(!signRequest){
					response.sendRedirect(idpUrl+"?SAMLRequest="+URLEncoder.encode(samlRequestB64, "UTF-8")+"&RelayState="+URLEncoder.encode(relayState, "UTF-8"));
					return;
				}
				
				String toSign = "SAMLRequest="+URLEncoder.encode(samlRequestB64, "UTF-8")+"&RelayState="+URLEncoder.encode(relayState, "UTF-8")+"&SigAlg="+URLEncoder.encode(signatureAlg, "UTF-8");
				String signature = SAML2.saml_generateDetachedSignature(toSign, privateKey);
				response.sendRedirect(idpUrl+"?"+toSign+"&Signature="+URLEncoder.encode(signature, "UTF-8"));
			}
			
		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

}
