/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.servlet;

import it.unicam.cs.saml.SAML2;
import it.unicam.cs.sp.config.Configuration;
import it.unicam.cs.utils.Utils;
import it.unicam.cs.utils.X509Utils;
import it.unicam.cs.utils.XMLUtils;
import it.unicam.cs.utils.Utils.LogType;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStore.PrivateKeyEntry;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Document;

public class METADATA extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private Configuration cfg;
	
	public void init(ServletConfig config) throws ServletException {
		try{
			cfg = new Configuration(config.getServletContext().getInitParameter("configFile"));
		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
	}

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		try{
			PrivateKeyEntry key = X509Utils.readPrivateKey(cfg.getKeystorePath(), cfg.getKeystoreType(), cfg.getPwdKeystore(), cfg.getAliasCertificate(), cfg.getPwdCertificate());
			Document spMetadata = XMLUtils.getXmlDocFromURI(cfg.getSpMetadataPath());
			
			if(cfg.getSignSpMetadata()){
				if(spMetadata.getDocumentElement().getAttribute("ID").isEmpty())
					spMetadata.getDocumentElement().setAttribute("ID", spMetadata.getDocumentElement().getAttribute("entityID"));
				
				Document spMetadataSigned = SAML2.saml_signXML(spMetadata.getDocumentElement(), key).getOwnerDocument();
				if(!SAML2.saml_verifyXMLSignatures(spMetadataSigned.getDocumentElement(), spMetadata))
					throw new Exception("ERROR: Digital Signature invalid \nCheck if the signing certificate is the same you have provided in the metadata");
				spMetadata = spMetadataSigned;
			}
			response.setContentType("text/xml");
			PrintWriter out = response.getWriter(); 
			out.print(XMLUtils.getStringFromXmlDoc(spMetadata));
			
		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general); throw new ServletException(ex);}
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

}
