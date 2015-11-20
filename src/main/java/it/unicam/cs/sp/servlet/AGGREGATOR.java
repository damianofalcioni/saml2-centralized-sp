/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.servlet;

import it.unicam.cs.saml.SAML2;
import it.unicam.cs.saml.SAML2.AttributeInfo;
import it.unicam.cs.saml.SAML2.NameIDFormat;
import it.unicam.cs.saml.SAML2.ServiceSessionInfo;
import it.unicam.cs.sp.config.Configuration;
import it.unicam.cs.utils.NETUtils;
import it.unicam.cs.utils.Utils;
import it.unicam.cs.utils.X509Utils;
import it.unicam.cs.utils.Utils.LogType;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.KeyStore.PrivateKeyEntry;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AGGREGATOR extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private Configuration cfg;
	
	public void init(ServletConfig config) throws ServletException {
		try{
			cfg = new Configuration(config.getServletContext().getInitParameter("configFile"));
		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
	}
	
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try{			
			String relayState = request.getParameter("relayState");
			if(relayState==null || relayState.isEmpty())
				throw new Exception("ERROR: relayState is null");
			
			ServiceSessionInfo ssi = (ServiceSessionInfo)request.getSession().getAttribute(relayState);
			if(ssi==null)
				throw new Exception("ERROR: Invalid Session State");
			
			String idpEntityID = ssi.idpEntityID;
			String serviceURL = ssi.serviceURL;
			String host = NETUtils.getHost(serviceURL);
			int hostId = cfg.isHostAllowed(host);
			if(hostId == -1)
				throw new Exception("ERROR: Host " + host + " is not allowed");
			
			int attributeConsumingServiceIndex = cfg.getAttributeConsumingServiceIndex(hostId);
			AttributeInfo[] attributesObtained = ssi.attributesObtained;
			AttributeInfo[] attributesRequired = SAML2.saml_getRequiredAttributes(cfg.getSpMetadataPath(), attributeConsumingServiceIndex);
			AttributeInfo[] attributesMissing = SAML2.saml_getMissingAttributes(attributesRequired, attributesObtained);
			
			//TODO: cercare se in sessione su altri relayStetes c'è l'attributo che manca?
			
			if(attributesMissing.length!=0) {
				String spEntityID = SAML2.saml_getEntityIDFromSingleMetadata(cfg.getSpMetadataPath());
				String nameID = SAML2.saml_getAttributeInfo(attributesObtained, "spidCode").valueList[0]; //SPID richiede attributo codice fiscale (spidCode), altrimenti c'è da usare NameID TODO: impostarlo da config
				NameIDFormat nameIDFormat = NameIDFormat.unspecified;
				PrivateKeyEntry privateKey = X509Utils.readPrivateKey(cfg.getKeystorePath(), cfg.getKeystoreType(), cfg.getPwdKeystore(), cfg.getAliasCertificate(), cfg.getPwdCertificate());
				
				String[] usableFederationPathList = SAML2.saml_getUsableFederations(idpEntityID, spEntityID, cfg.getAllFederationMetadataURI());
				for(AttributeInfo attributeMissing:attributesMissing){
					for(String usableFederationPath:usableFederationPathList){
						String[] idpIdList = SAML2.saml_getIdPsProvidingAttribute(usableFederationPath, attributeMissing.name, attributeMissing.nameFormat);
						for(String idpId:idpIdList){
							try{
								String attributeQuery = SAML2.sp_generateSamlAttributeQuery(usableFederationPath, spEntityID, idpId, nameID, nameIDFormat, privateKey, new AttributeInfo[]{attributeMissing});
								Utils.log(attributeQuery, cfg, LogType.requests);
								String samlResp = SAML2.sp_sendRequestUsingSoap(attributeQuery, idpId, usableFederationPath);
								Utils.log(samlResp, cfg, LogType.responses);
								SAML2.sp_validateSamlResponse(samlResp, usableFederationPath, spEntityID, true);
								AttributeInfo[] aaAttrList = SAML2.sp_getObtainedAttributes(samlResp);
								
								for(AttributeInfo aaAttr:aaAttrList)
								    if(aaAttr.name.equals(attributeMissing.name) && aaAttr.nameFormat.equals(attributeMissing.nameFormat))
								        if(aaAttr.valueList.length!=0){
								            attributeMissing.valueList = aaAttr.valueList;
								            break;
								        }
								if(attributeMissing.valueList.length==0)
                                    throw new Exception("AA "+idpId+" returned no values for missing attribute "+attributeMissing.name+" format: "+attributeMissing.nameFormat);
								
								/*
								if(aaAttrList.length!=1)
									throw new Exception("AA "+idpId+" returned more than 1 attribute. Required only one.");
								if(!(aaAttrList[0].name.equals(attributeMissing.name) && aaAttrList[0].nameFormat.equals(attributeMissing.nameFormat)))
									throw new Exception("AA "+idpId+" returned attribute: "+aaAttrList[0].name+" format: "+aaAttrList[0].nameFormat+".\nExpected attribute: "+attributeMissing.name+" format: "+attributeMissing.nameFormat);
								if(aaAttrList[0].valueList.length==0)
									throw new Exception("AA "+idpId+" returned no values for attribute "+aaAttrList[0].name+" format: "+aaAttrList[0].nameFormat);
								attributeMissing.valueList = aaAttrList[0].valueList;
								*/
								
								break;
							}catch(Exception ex){
								ex.printStackTrace();
								Utils.log(ex.getMessage(), cfg, LogType.general);
								continue;
							}
						}
						if(attributeMissing.valueList.length!=0)
							break;
					}
				}
				AttributeInfo[] attributeObtainedList = new AttributeInfo[attributesObtained.length+attributesMissing.length];
				for(int i=0;i<attributesObtained.length;i++)
					attributeObtainedList[i] = attributesObtained[i];
				for(int i=0;i<attributesMissing.length;i++)
					attributeObtainedList[attributesObtained.length+i] = attributesObtained[i];
				attributesObtained = attributeObtainedList;
				
				ssi.attributesObtained = attributesObtained;
				request.getSession().setAttribute(relayState, ssi);
			}

			response.sendRedirect("./PoR?relayState="+URLEncoder.encode(relayState, "UTF-8"));

		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

}
