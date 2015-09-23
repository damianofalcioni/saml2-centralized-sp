/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.utils;

import javax.xml.xpath.XPathConstants;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;


public class AGIDUtils {

	public static String generateFederatedMetadata(String agidUrl) throws Exception{
		String url = agidUrl+"?entityId=*";
		String agidResponse = new String(NETUtils.sendHTTPGET(url, null, false, false));
		Document agidResponseXml = XMLUtils.getXmlDocFromString(agidResponse);
		NodeList metadataUrlList =  (NodeList) XMLUtils.execXPath(agidResponseXml.getDocumentElement(), "//*[local-name()='MetadataProviderURL']", XPathConstants.NODESET);
		
		Document doc = XMLUtils.createNewDocument();
		Element entitiesDescriptorNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:metadata", "md:EntitiesDescriptor");
		doc.appendChild(entitiesDescriptorNode);
		for(int i=0;i<metadataUrlList.getLength();i++){
			try{
				Document metadataXml = XMLUtils.getXmlDocFromURI(metadataUrlList.item(i).getTextContent());
				entitiesDescriptorNode.appendChild(doc.importNode(metadataXml.getDocumentElement(), true));
			}catch(Exception ex){ex.printStackTrace();}
		}
		String ret = XMLUtils.getStringFromXmlDoc(doc);
		return ret;
	}
}
