/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.config;

import java.net.URLDecoder;
import java.net.URLEncoder;

import javax.xml.xpath.XPathConstants;

import it.unicam.cs.utils.XMLUtils;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class Configuration {
	
	public String defaultConfigFile = "config.xml";
	private Document configXml=null;
	
	public Configuration() throws Exception{
		this(null);
	}
	
	public Configuration(String filePath) throws Exception{
		if(filePath==null || "".equals(filePath))
			configXml = XMLUtils.getXmlDocFromURI(Configuration.class.getResourceAsStream(defaultConfigFile));
		else
			configXml = XMLUtils.getXmlDocFromURI(filePath);
	}
	
	public String getSpMetadataPath() throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "/Config/SpMetadataPath", XPathConstants.STRING);
	}
	
	public String getLogFilePath() throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "/Config/Log/FileGeneral", XPathConstants.STRING);
	}
	
	public String getLogSamlRequestsFilePath() throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "/Config/Log/FileSamlRequests", XPathConstants.STRING);
	}
	
	public String getLogSamlResponsesFilePath() throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "/Config/Log/FileSamlResponses", XPathConstants.STRING);
	}
	
	public boolean isLogSamlRequestsEnabled() throws Exception{
		return (Boolean) XMLUtils.execXPath(configXml.getDocumentElement(), "/Config/Log/@logSamlRequests", XPathConstants.BOOLEAN);
	}
	
	public boolean isLogSamlResponsesEnabled() throws Exception{
		return (Boolean) XMLUtils.execXPath(configXml.getDocumentElement(), "/Config/Log/@logSamlResponses", XPathConstants.BOOLEAN);
	}
	
	public boolean getSignSpMetadata() throws Exception{
		return (Boolean) XMLUtils.execXPath(configXml.getDocumentElement(), "/Config/SignSpMetadata", XPathConstants.BOOLEAN);
	}
	
	public String[] getAllFederationMetadataURI() throws Exception{
		NodeList federationNodeList = (NodeList) XMLUtils.execXPath(configXml.getDocumentElement(), "//LocalMetadataURI", XPathConstants.NODESET);
		String[] ret = new String[federationNodeList.getLength()];
		for(int i=0;i<federationNodeList.getLength();i++)
			ret[i] = federationNodeList.item(i).getTextContent();
		return ret;
	}
	
	public String getLocalFederationMetadataURI(String fedId) throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "//Federations/*[@ID='"+fedId+"']/LocalMetadataURI", XPathConstants.STRING);
	}
	
	public String getRemoteFederationMetadataURI(String fedId) throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "//Federation[@ID='"+fedId+"']/RemoteMetadataURI", XPathConstants.STRING);
	}
	
	public String getFederationId(String LocalMetadataURI) throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "//Federation[./LocalMetadataURI='"+LocalMetadataURI+"']/@ID", XPathConstants.STRING);
	}
	
	public String getFederationWAYFURI(String fedId) throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "//Federation[@ID='"+fedId+"']/WAYF", XPathConstants.STRING);
	}
	
	public String getFederationDesc(String fedId) throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "//Federation[@ID='"+fedId+"']/@Desc", XPathConstants.STRING);
	}
	
	public String getAgidRegistryURI() throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "//RegistryURI", XPathConstants.STRING);
	}
	
	public boolean isAgidRegistryEnabled() throws Exception{
		return (Boolean) XMLUtils.execXPath(configXml.getDocumentElement(), "//Agid/@autoSincronize", XPathConstants.BOOLEAN);
	}
	
	public String[] getFederationToUpdate() throws Exception{
		NodeList federationNodeList = (NodeList) XMLUtils.execXPath(configXml.getDocumentElement(), "//Federation[@autoSincronize='true']", XPathConstants.NODESET);
		String[] ret = new String[federationNodeList.getLength()];
		for(int i=0;i<federationNodeList.getLength();i++)
			ret[i] = federationNodeList.item(i).getAttributes().getNamedItem("ID").getNodeValue();
		return ret;
	}
	
	public int isHostAllowed(String host) throws Exception{
		String hostIdS = (String) XMLUtils.execXPath(configXml.getDocumentElement(), "(//DnsHostName[.='"+host+"'] | //ip[.='"+host+"'])/../@ID", XPathConstants.STRING);
		int hostId = -1;
		if(!hostIdS.isEmpty())
			hostId = Integer.parseInt(hostIdS);
		return hostId;
	}
	
	public String[] getFederationEnabled(int hostId) throws Exception{
		NodeList federationNodeList = (NodeList) XMLUtils.execXPath(configXml.getDocumentElement(), "//Host[@ID='"+hostId+"']/FederationsEnabled", XPathConstants.NODESET);
		if(federationNodeList.getLength()==0)
			throw new Exception("ERROR: No federation allowed for host " + hostId);
		String[] ret = new String[federationNodeList.getLength()];
		for(int i=0;i<federationNodeList.getLength();i++)
			ret[i] = federationNodeList.item(i).getTextContent();
		return ret;
	}
	
	public int getAttributeConsumingServiceIndex(int hostId) throws Exception{
		String ret = (String) XMLUtils.execXPath(configXml.getDocumentElement(), "//Host[@ID='"+hostId+"']/@AttributeConsumingServiceIndex", XPathConstants.STRING);
		return Integer.parseInt(ret);
	}
	
	public boolean getUsePostBinding(int hostId) throws Exception{
		String ret = (String) XMLUtils.execXPath(configXml.getDocumentElement(), "//Host[@ID='"+hostId+"']/@UsePostBinding", XPathConstants.STRING);
		return Boolean.parseBoolean(ret);
	}
	
	public boolean getSignSamlRequests(int hostId) throws Exception{
		String ret = (String) XMLUtils.execXPath(configXml.getDocumentElement(), "//Host[@ID='"+hostId+"']/@SignSamlRequests", XPathConstants.STRING);
		return Boolean.parseBoolean(ret);
	}
	
	public boolean getWayfLoadIdP(int hostId) throws Exception{
		String ret = (String) XMLUtils.execXPath(configXml.getDocumentElement(), "//Host[@ID='"+hostId+"']/@WayfLoadIdP", XPathConstants.STRING);
		return Boolean.parseBoolean(ret);
	}
	
	public boolean getWayfIsPassive(int hostId) throws Exception{
		String ret = (String) XMLUtils.execXPath(configXml.getDocumentElement(), "//Host[@ID='"+hostId+"']/@WayfIsPassive", XPathConstants.STRING);
		return Boolean.parseBoolean(ret);
	}
	
	public String getKeystorePath() throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "/Config/PrivateKeyInfo/KeystorePath", XPathConstants.STRING);
	}
	public String getKeystoreType() throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "/Config/PrivateKeyInfo/KeystoreType", XPathConstants.STRING);
	}
	public String getPwdKeystore() throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "/Config/PrivateKeyInfo/PwdKeystore", XPathConstants.STRING);
	}
	public String getAliasCertificate() throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "/Config/PrivateKeyInfo/AliasCertificate", XPathConstants.STRING);
	}
	public String getPwdCertificate() throws Exception{
		return (String) XMLUtils.execXPath(configXml.getDocumentElement(), "/Config/PrivateKeyInfo/PwdCertificate", XPathConstants.STRING);
	}
	
	public static void main(String[] args) throws Exception {
		Configuration conf = new Configuration();
		/*String[] ret = conf.getFederationToUpdate();
		for(String r:ret)
			System.out.println(r);
		System.out.println(conf.getLocalFederationMetadataURI("test"));
		*/
		System.out.println(conf.isHostAllowed("127.0.0.1"));
		System.out.println(URLDecoder.decode(URLEncoder.encode("asd+dsa", "UTF-8"), "UTF-8"));
	}
}
