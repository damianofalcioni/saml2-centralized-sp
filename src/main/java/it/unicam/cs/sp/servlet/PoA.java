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
import it.unicam.cs.utils.NETUtils;
import it.unicam.cs.utils.Utils;
import it.unicam.cs.utils.Utils.LogType;
import it.unicam.cs.utils.XMLUtils;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.xpath.XPathConstants;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class PoA extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private Configuration cfg;
	
	public void init(ServletConfig config) throws ServletException {
		try{
			cfg = new Configuration(config.getServletContext().getInitParameter("configFile"));
		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
	}
	
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		try{
			/*
			 Formato xmlAuth
			 <auth>
			 	<serviceURL>http://localhost/Service/validateFE.jsp</serviceURL>
			 	<logoutURL>http://localhost/Service/logoutFE.jsp</logoutURL>
			 	<authnContextList>
			 		<authnContext>SpidL1</authnContext>
			 		<authnContext>SpidL2</authnContext>
			 		<authnContext>SpidL3</authnContext>
			 	</authnContextList>
			 </auth>
			 */
			String authB64 = request.getParameter("xmlAuth");
			if(authB64==null || authB64=="")
				throw new Exception("ERROR: xmlAuth is null");

			String auth = new String(Base64Fast.decode(authB64.getBytes()));
			Document authXml = XMLUtils.getXmlDocFromString(auth);
			
			String serviceURL = (String) XMLUtils.execXPath(authXml.getDocumentElement(), "//serviceURL", XPathConstants.STRING);
			
			String serviceLogoutURL = (String) XMLUtils.execXPath(authXml.getDocumentElement(), "//logoutURL", XPathConstants.STRING);
			
			NodeList AuthnContextNodeList = (NodeList) XMLUtils.execXPath(authXml.getDocumentElement(), "//authnContext", XPathConstants.NODESET);
			AuthnContext[] authnContextList = new AuthnContext[AuthnContextNodeList.getLength()];
			for(int i=0;i<AuthnContextNodeList.getLength();i++)
				authnContextList[i] = AuthnContext.valueOf(AuthnContextNodeList.item(i).getTextContent());
			if(authnContextList.length==0)
				authnContextList = null;
				
			String host = NETUtils.getHost(serviceURL);
			int hostId = cfg.isHostAllowed(host);
			if(hostId == -1)
				throw new Exception("ERROR: Host " + host + " is not allowed");
			
			boolean wayfLoadIdP = cfg.getWayfLoadIdP(hostId);
			boolean wayfIsPassive = cfg.getWayfIsPassive(hostId);
			
			HttpSession session = request.getSession();
			String relayState = java.util.UUID.randomUUID() + "";
			ServiceSessionInfo toSave = new ServiceSessionInfo();
			toSave.authnContextComparisonType = AuthnContextComparison.minimum;
			toSave.authnContextList = authnContextList; 
			toSave.serviceURL = serviceURL;
			toSave.serviceLogoutURL = serviceLogoutURL;
			session.setAttribute(relayState, toSave);
			
			session.setAttribute("currentRelyState", relayState);
			
			String spEntityId = SAML2.saml_getEntityIDFromSingleMetadata(cfg.getSpMetadataPath());
			String spReturnUrl = SAML2.saml_getDiscoveryReturnUrl(spEntityId, null, SAML2.saml_chooseFederationToUse(spEntityId, cfg.getAllFederationMetadataURI())); 
			
			response.sendRedirect("./wayf.jsp?entityID="+URLEncoder.encode(spEntityId, "UTF-8")+"&return="+URLEncoder.encode(spReturnUrl, "UTF-8")+"&loadIdP="+URLEncoder.encode(wayfLoadIdP+"", "UTF-8")+"&isPassive="+URLEncoder.encode(wayfIsPassive+"", "UTF-8"));
		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

}
