/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.servlet;

import it.unicam.cs.saml.SAML2;
import it.unicam.cs.saml.SAML2.AttributeInfo;
import it.unicam.cs.saml.SAML2.ServiceSessionInfo;
import it.unicam.cs.sp.config.Configuration;
import it.unicam.cs.utils.Base64Fast;
import it.unicam.cs.utils.IOUtils;
import it.unicam.cs.utils.Utils;
import it.unicam.cs.utils.Utils.LogType;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CONSUMER extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private Configuration cfg;
	private boolean isPost = false;
	
	public void init(ServletConfig config) throws ServletException {
		try{
			cfg = new Configuration(config.getServletContext().getInitParameter("configFile"));
		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
	}

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try{
			String samlResponseB64 = request.getParameter("SAMLResponse");
			String relayState = request.getParameter("RelayState");
			
			if(samlResponseB64==null || samlResponseB64.isEmpty())
				throw new Exception("ERROR: SAMLResponse is null");
			if(relayState==null || relayState.isEmpty())
				throw new Exception("ERROR: RelayState is null");
			
			ServiceSessionInfo ssi = (ServiceSessionInfo)request.getSession().getAttribute(relayState);
			if(ssi==null)
				throw new Exception("ERROR: Invalid Session State");
			
			String samlResponse = new String(Base64Fast.decode(samlResponseB64));
			Utils.log(samlResponse, cfg, LogType.responses);
			if(!isPost){
				samlResponse = new String(IOUtils.uncompressFromDeflate(Base64Fast.decode(samlResponseB64)));
				Utils.log(samlResponse, cfg, LogType.responses);
				if(request.getParameter("Signature")!=null){
					String signature = request.getParameter("Signature");
					String alg = request.getParameter("SigAlg");
					String toVerify = request.getQueryString().split("&Signature")[0];
					SAML2.verifyDetachedSignature(toVerify, alg, signature, samlResponse, cfg);
				}
			}
			
			String spEntityID = SAML2.saml_getEntityIDFromSingleMetadata(cfg.getSpMetadataPath());
			String idpEntityID = SAML2.saml_getSamlResponseIssuer(samlResponse);
			
			SAML2.sp_validateSamlResponse(samlResponse, SAML2.saml_chooseFederationToUse(idpEntityID, spEntityID, cfg.getAllFederationMetadataURI()), spEntityID, isPost);
			
			AttributeInfo[] attributeList = SAML2.sp_getObtainedAttributes(samlResponse);
			ssi.attributesObtained = attributeList;
			ssi.idpEntityID = idpEntityID;
			request.getSession().setAttribute(relayState, ssi);
			
			response.sendRedirect("./AGGREGATOR?relayState="+URLEncoder.encode(relayState, "UTF-8"));
			
		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		isPost = true;
		doGet(request, response);
	}

}
