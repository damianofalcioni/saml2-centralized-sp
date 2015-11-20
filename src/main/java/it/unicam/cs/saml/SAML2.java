/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.saml;

import java.io.File;
import java.io.RandomAccessFile;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.xpath.XPathConstants;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import it.unicam.cs.sp.config.Configuration;
import it.unicam.cs.utils.Base64Fast;
import it.unicam.cs.utils.NETUtils;
import it.unicam.cs.utils.Utils;
import it.unicam.cs.utils.X509Utils;
import it.unicam.cs.utils.XMLUtils;

public class SAML2 {
    /*
	public static void main(String[] args) {
		try {
		    //String date1 = "2015-11-20T13:07:06.6823694Z";
		    //Date date1D = Utils.stringToDate(date1);
		    //Date currentTime = new Date();
		    //System.out.println("date1: " + date1D.getTime() + " -> "+Utils.getUTCTime(date1D));
		    //System.out.println("curre: " + currentTime.getTime() + " -> "+Utils.getUTCTime(currentTime));
		    
//			Configuration cfg = new Configuration("D:\\TOOLS\\eclipse\\workspace\\SPManager\\config\\config.xml");
//			PrivateKeyEntry key = X509Utils.readPrivateKey(cfg.getKeystorePath(), cfg.getKeystoreType(), cfg.getPwdKeystore(), cfg.getAliasCertificate(), cfg.getPwdCertificate());
//			String spEntityID = "spmanager";
//			String aaEntityID = "https://idp.cs.unicam.it/idp/shibboleth";
//			String subjectID = "damiano.falcioni@unicam.it";
//			AttributeInfo attribute = new AttributeInfo();
//			attribute.name = "urn:oid:0.9.2342.19200300.100.1.1";
//			attribute.nameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
//			AttributeInfo[] attributeList = null;
//			String query = SAML2.sp_generateSamlAttributeQuery(SAML2.saml_chooseFederationToUse(aaEntityID, spEntityID, cfg.getAllFederationMetadataURI()), spEntityID, aaEntityID, subjectID, NameIDFormat.unspecified, key, attributeList);
//			//ritorna gli attributi solo se la sessione sull'idp � ancora buona
//			String ret = SAML2.sp_sendRequestUsingSoap(query, aaEntityID, SAML2.saml_chooseFederationToUse(aaEntityID, cfg.getAllFederationMetadataURI()));
//			SAML2.sp_validateSamlResponse(ret, SAML2.saml_chooseFederationToUse(aaEntityID, spEntityID, cfg.getAllFederationMetadataURI()), spEntityID, true);
//			System.out.println(ret);
			//String samlResponse = new String(readFile(new File("C:\\Users\\Mi0\\Desktop\\respSaml.txt")));
			//sp_validateSamlResponse(samlResponse, "C:\\Users\\Mi0\\Desktop\\cohesion-federated-metadata.xml", "cohesion.regione.marche.it:sp", true);

			//String url = saml_getDiscoveryReturnUrl("cohesion2.regione.marche.it:sp", "https://cohesion2.regione.marche.it/SPManager/SAMLConsumer.aspx", "C:\\Users\\Mi0\\Desktop\\cohesion-federated-metadata.xml");
			//String url = saml_getDiscoveryReturnUrl("cohesion2.regione.marche.it:sp", "", "C:\\Users\\Mi0\\Desktop\\cohesion-federated-metadata.xml");
			//System.out.println(url);
			//PrivateKeyEntry key = X509Utils.readPrivateKey("C:\\Users\\Mi0\\Desktop\\my.p12", "PKCS12", "pwd", "be7446f14507a331c1b5b8ff70a66520_d0e8d7b1-bcb5-4128-9d8e-2fc4dc332132", "pwd");
			//AuthnContext[] AuthnContextList = new AuthnContext[]{AuthnContext.Password, AuthnContext.MobileTwoFactorContract};
			//System.out.println(sp_generateSamlAuthnRequest("C:\\Users\\Mi0\\Desktop\\cohesion-federated-metadata.xml","https://cohesion.regione.marche.it:3443/icar-pa/metadata","cohesion.regione.marche.it:idp",1,key, true, false, AuthnContextList, AuthnContextComparison.better));
			//System.out.println(SAML2.saml_generateDetachedSignature("ciao", key));
			//System.out.println(saml_chooseFederationToUse("cohesion.regione.marche.it:idp", "cohesion.regione.marche.it:sp", new String[]{"C:\\Users\\Mi0\\Desktop\\cohesion-federated-metadata.xml"}));
			//System.out.println(saml_getEntityIDFromMetadata("C:\\Users\\Mi0\\Desktop\\cohesion-sp-metadata.xml"));
			
			//idpInfo[] retList = wayf_getAllIdpInfo("C:\\Users\\Mi0\\Desktop\\cohesion-federated-metadata.xml");
			//for(idpInfo ret:retList)
			//	for(String url:ret.imgUrlList)
			//		System.out.println(ret.id + "->" + url);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	*/
	public enum AuthnContext{
		InternetProtocolPassword("urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"),
        Kerberos("urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"),
        MobileOneFactorUnregistered("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered"),
        MobileTwoFactorUnregistered("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered"),
        MobileOneFactorContract("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract"),
        MobileTwoFactorContract("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"),
        Password("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"),
        PasswordProtectedTransport("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"),
        PreviousSession("urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"),
        X509("urn:oasis:names:tc:SAML:2.0:ac:classes:X509"),
        PGP("urn:oasis:names:tc:SAML:2.0:ac:classes:PGP"),
        SPKI("urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI"),
        XMLDSig("urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig"),
        Smartcard("urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"),
        SmartcardPKI("urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"),
        SoftwarePKI("urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI"),
        Telephony("urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony"),
        NomadTelephony("urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony"),
        PersonalTelephony("urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalTelephony"),
        AuthenticatedTelephony("urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony"),
        SecureRemotePassword("urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword"),
        TLSClient("urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"),
        TimeSyncToken("urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"),
        unspecified("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"),
        //Definiti da Spid
        SpidL1("urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1"),
        SpidL2("urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL2"),
        SpidL3("urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL3");
		
		private final String text;
	    private AuthnContext(String text) { this.text = text; }
	    @Override
	    public String toString() { return text; }
	}
	public enum AuthnContextComparison{
		exact, minimum, better, maximum;
	}

	public static String sp_generateSamlAuthnRequest(String federatedMetadataUrl, String spEntityID, String idpEntityID, Integer attributeConsumingServiceIndex, PrivateKeyEntry privateKey, boolean useHttpPost, boolean forceAuthn, AuthnContext[] authnContextList, AuthnContextComparison authnContextComparisonType) throws Exception{
		
		String bindingToUse = (useHttpPost)?"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
		
		String id = "_" + java.util.UUID.randomUUID();

		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataUrl);

		String assertionConsumerServiceURL =  (String) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='EntityDescriptor'][@entityID='"+spEntityID+"']//*[local-name()='AssertionConsumerService']/@Location", XPathConstants.STRING);
		if(assertionConsumerServiceURL.isEmpty())
			throw new Exception("ERROR: Can not obtain AssertionConsumerService Location for the ID " + spEntityID);
		
		String destinationURL = (String) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='EntityDescriptor'][@entityID='"+idpEntityID+"']//*[local-name()='SingleSignOnService'][@Binding='"+bindingToUse+"']/@Location", XPathConstants.STRING);
		if(destinationURL.isEmpty())
			throw new Exception("ERROR: Can not obtain SingleSignOnService Location for the ID " + idpEntityID);

		Document doc = XMLUtils.createNewDocument();
		Element authnRequestNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:AuthnRequest");
		doc.appendChild(authnRequestNode);
		authnRequestNode.setAttribute("ID", id);
		authnRequestNode.setIdAttribute("ID", true);
		authnRequestNode.setAttribute("Version", "2.0");
		authnRequestNode.setAttribute("IssueInstant", Utils.getUTCTime());
		authnRequestNode.setAttribute("Destination", destinationURL);
		authnRequestNode.setAttribute("ForceAuthn", ""+forceAuthn);
		//authnRequestNode.setAttribute("IsPassive", "false"); non deve essere presente per spid
		authnRequestNode.setAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");// binding da usare al ritorno
		authnRequestNode.setAttribute("AssertionConsumerServiceURL", assertionConsumerServiceURL);
		if(attributeConsumingServiceIndex!=null) 
			authnRequestNode.setAttribute("AttributeConsumingServiceIndex", ""+attributeConsumingServiceIndex);
		
		Element issuerNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Issuer");
		authnRequestNode.appendChild(issuerNode);
		issuerNode.setAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"); //richiesto spid
		issuerNode.setAttribute("NameQualifier", spEntityID); //richiesto spid
		issuerNode.setTextContent(spEntityID);
		
		Element nameIDPolicyNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:NameIDPolicy");
		authnRequestNode.appendChild(nameIDPolicyNode);
		nameIDPolicyNode.setAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
		nameIDPolicyNode.setAttribute("SPNameQualifier", spEntityID);
		//nameIDPolicyNode.setAttribute("AllowCreate", "false"); per spid o non c'e' o e' true
		

		if(authnContextList!=null && authnContextList.length!=0){
			String authnContextComparison = "minimum";
			if(authnContextComparisonType!=null)
				authnContextComparison = authnContextComparisonType.toString();
			Element requestedAuthnContextNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:RequestedAuthnContext");
			authnRequestNode.appendChild(requestedAuthnContextNode);
			requestedAuthnContextNode.setAttribute("Comparison", authnContextComparison);
			for(AuthnContext authnContext:authnContextList){
				Element authnContextClassRef = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:AuthnContextClassRef");
				requestedAuthnContextNode.appendChild(authnContextClassRef);
				authnContextClassRef.setTextContent(authnContext.toString());
			}
		}
		
		if(privateKey!=null){
			Document signedDoc = saml_signXML(doc.getDocumentElement(), privateKey).getOwnerDocument();
			if(!saml_verifyXMLSignatures(XMLUtils.getXmlDocFromString(XMLUtils.getStringFromXmlDoc(signedDoc)).getDocumentElement(), metadataXml))
				throw new Exception("ERROR: Digital Signature invalid \nCheck if the signing certificate is the same you have provided in the federated metadata about SP");
			doc = signedDoc;
		}
		
		String ret = XMLUtils.getStringFromXmlDoc(doc);
		
		return ret;
	}
	
	public static void sp_validateSamlResponse(String samlResponse, String federatedMetadataUrl, String spEntityID, boolean httpPostUsed) throws Exception{
		Document samlResponseXml = XMLUtils.getXmlDocFromString(samlResponse);
		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataUrl);
		
		String bindingToUse = (httpPostUsed)?"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
		String consumerUrl =  (String) XMLUtils.execXPath(metadataXml.getDocumentElement(), "//*[local-name()='EntityDescriptor'][@entityID='"+spEntityID+"']//*[local-name()='AssertionConsumerService'][@Binding='"+bindingToUse+"']/@Location", XPathConstants.STRING);
		
		
		if(!SAML2.saml_verifyXMLSignatures(samlResponseXml, metadataXml))
			throw new Exception("ERROR: Digital Signature invalid");
		
		if(samlResponseXml.getElementsByTagName("EncryptedKey").getLength()!=0)
			throw new Exception("ERROR: Encripted assertions not supported");
		
		if(!samlResponseXml.getDocumentElement().getAttribute("Version").equals("2.0"))
			throw new Exception("ERROR: Unsupported SAML Version");
		
		if(samlResponseXml.getDocumentElement().getAttribute("ID").equals(""))
			throw new Exception("ERROR: Missing ID attribute on SAML Response");
		
		String statusCode =  (String) XMLUtils.execXPath(samlResponseXml.getDocumentElement(), ".//*[local-name()='StatusCode']/@Value", XPathConstants.STRING);
		if(!statusCode.equals("urn:oasis:names:tc:SAML:2.0:status:Success")){
			String statusMessage =  (String) XMLUtils.execXPath(samlResponseXml.getDocumentElement(), ".//*[local-name()='StatusMessage']", XPathConstants.STRING);
			throw new Exception("ERROR: SAML Response status code is: " + statusCode + "\nMessage: " + statusMessage);
		}
		
		String samlResponseDestination = samlResponseXml.getDocumentElement().getAttribute("Destination");
		if(!samlResponseDestination.equals(""))
			if(!consumerUrl.equals(samlResponseDestination))
				throw new Exception("ERROR: SAML Response destination not valid\nExpected: " + consumerUrl + "\nReturned: " + samlResponseDestination);
		
		//if(samlResponseXml.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion").getLength()==0)
			//throw new Exception("ERROR: SAML Response must contain 1 Assertion");
		
		/*
		NodeList audienceList =  (String) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='Audience']", XPathConstants.NODESET);
		for(int i=0;i<audienceList.getLength();i++)
			if(!spEntityID.equals(audienceList.item(i).getTextContent()))
				throw new Exception("ERROR: An assertion audience is not " + spEntityID);
		*/
		
		Element conditions =  (Element) XMLUtils.execXPath(samlResponseXml.getDocumentElement(), "//*[local-name()='Conditions']", XPathConstants.NODE);

		Date currentTime = new Date();
		if(conditions!=null){
            if(conditions.hasAttribute("NotBefore"))
                if(currentTime.getTime() < Utils.stringToDate(conditions.getAttribute("NotBefore")).getTime())
                    throw new Exception("ERROR: SAML Assertion condition NotBefore not valid: " + Utils.getUTCTime(currentTime) + " before " + conditions.getAttribute("NotBefore"));
            if(conditions.hasAttribute("NotOnOrAfter"))
                if(currentTime.getTime() >= Utils.stringToDate(conditions.getAttribute("NotOnOrAfter")).getTime())
                    throw new Exception("ERROR: SAML Assertion condition NotOnOrAfter not valid: " + Utils.getUTCTime(currentTime) + " after " + conditions.getAttribute("NotOnOrAfter"));
        }
		
		NodeList subjectConfirmationDataList =  (NodeList) XMLUtils.execXPath(samlResponseXml.getDocumentElement(), "//*[local-name()='SubjectConfirmationData']", XPathConstants.NODESET);
		for(int i=0;i<subjectConfirmationDataList.getLength();i++){
			Element subjectConfirmationData = (Element)subjectConfirmationDataList.item(i);
			if(subjectConfirmationData.hasAttribute("Recipient"))
				if(!consumerUrl.equals(subjectConfirmationData.getAttribute("Recipient")))
					throw new Exception("ERROR: SAML Assertion Recipient not valid\nExpected: " + consumerUrl + "\nReturned: " + subjectConfirmationData.getAttribute("Recipient"));
			if(subjectConfirmationData.hasAttribute("NotBefore"))
				if(currentTime.getTime() < Utils.stringToDate(subjectConfirmationData.getAttribute("NotBefore")).getTime())
					throw new Exception("ERROR: SAML Assertion NotBefore not valid: " + Utils.getUTCTime(currentTime) + " before " + subjectConfirmationData.getAttribute("NotBefore"));
			if(subjectConfirmationData.hasAttribute("NotOnOrAfter"))
				if(currentTime.getTime() >= Utils.stringToDate(subjectConfirmationData.getAttribute("NotOnOrAfter")).getTime())
					throw new Exception("ERROR: SAML Assertion NotOnOrAfter not valid: " + Utils.getUTCTime(currentTime) + " after " + subjectConfirmationData.getAttribute("NotOnOrAfter"));
		}
	}
	
	public final static class AttributeInfo{
		public String name = "";
		public String friendlyName = "";
		public String nameFormat = "";
		public boolean isRequired = false;
		public String[] valueList = new String[0];
	}
	
	public static AttributeInfo[] sp_getObtainedAttributes(String samlResponse) throws Exception{
		Document samlResponseXml = XMLUtils.getXmlDocFromString(samlResponse);
		NodeList attributeList =  (NodeList) XMLUtils.execXPath(samlResponseXml.getDocumentElement(), "//*[local-name()='Attribute']", XPathConstants.NODESET);
		AttributeInfo[] ret = new AttributeInfo[attributeList.getLength()+2];
		
		for(int i=0;i<attributeList.getLength();i++){
			AttributeInfo attributeInfo = new AttributeInfo();
			attributeInfo.name = attributeList.item(i).getAttributes().getNamedItem("Name").getNodeValue();
			attributeInfo.friendlyName = attributeList.item(i).getAttributes().getNamedItem("FriendlyName").getNodeValue();
			attributeInfo.nameFormat =  attributeList.item(i).getAttributes().getNamedItem("NameFormat").getNodeValue();
			NodeList attributeValueList = attributeList.item(i).getChildNodes();

			ArrayList<String> valList = new ArrayList<String>();
			for(int j=0;j<attributeValueList.getLength();j++)
				if(!attributeValueList.item(j).getTextContent().trim().equals(""))
					valList.add(attributeValueList.item(j).getTextContent());
			
			String[] val = new String[valList.size()];
			valList.toArray(val);
			attributeInfo.valueList = val;
			ret[i] = attributeInfo;
		}
		
		AttributeInfo lastlastAttributeInfo = new AttributeInfo();
		lastlastAttributeInfo.name = "SAMLResponseB64";
		lastlastAttributeInfo.friendlyName = "SAMLResponseB64";
		lastlastAttributeInfo.nameFormat = "Base64";
		lastlastAttributeInfo.valueList = new String[]{Base64Fast.encodeToString(samlResponse.getBytes(), false)};
		ret[ret.length-2] = lastlastAttributeInfo;
		
		AttributeInfo lastAttributeInfo = new AttributeInfo();
		lastAttributeInfo.name = "NameID";
		lastAttributeInfo.friendlyName = "NameID";
		String nameID =  (String) XMLUtils.execXPath(samlResponseXml.getDocumentElement(), "//*[local-name()='NameID']", XPathConstants.STRING);
		String nameIDFormat =  (String) XMLUtils.execXPath(samlResponseXml.getDocumentElement(), "//*[local-name()='NameID']/@Format", XPathConstants.STRING);
		if(nameIDFormat.isEmpty())
		    nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameidformat:unspecified";
		lastAttributeInfo.nameFormat = nameIDFormat;
		
		lastAttributeInfo.valueList = new String[]{nameID};
		ret[ret.length-1] = lastAttributeInfo;
		
		return ret;
	}
	
	public static AttributeInfo[] saml_getRequiredAttributes(String spMetadataPath, int attributeConsumingServiceIndex) throws Exception{
		Document metadataXml = XMLUtils.getXmlDocFromURI(spMetadataPath);
		
		NodeList attributeList =  (NodeList) XMLUtils.execXPath(metadataXml.getDocumentElement(), "//*[local-name()='AttributeConsumingService' and @index='"+attributeConsumingServiceIndex+"']/RequestedAttribute", XPathConstants.NODESET);
		AttributeInfo[] ret = new AttributeInfo[attributeList.getLength()];
		
		for(int i=0;i<attributeList.getLength();i++){
			AttributeInfo attributeInfo = new AttributeInfo();
			attributeInfo.name = attributeList.item(i).getAttributes().getNamedItem("Name").getNodeValue();
			attributeInfo.friendlyName = attributeList.item(i).getAttributes().getNamedItem("FriendlyName").getNodeValue();
			attributeInfo.nameFormat =  attributeList.item(i).getAttributes().getNamedItem("NameFormat").getNodeValue();
			attributeInfo.isRequired =  attributeList.item(i).getAttributes().getNamedItem("isRequired").getNodeValue().equals("true");
			ret[i] = attributeInfo;
		}
		
		return ret;
	}
	
	public static AttributeInfo[] saml_getMissingAttributes(AttributeInfo[] attributesRequired, AttributeInfo[] attributesObtained){
		
		ArrayList<AttributeInfo> attributeMissingList = new ArrayList<SAML2.AttributeInfo>();
		for(AttributeInfo attributeRequired:attributesRequired){
			if(!attributeRequired.isRequired)
				continue;
			
			boolean isPresent = false;
			for(AttributeInfo attributeObtained:attributesObtained)
				if(attributeRequired.name.equals(attributeObtained.name) && attributeRequired.nameFormat.equals(attributeObtained.nameFormat)){
					isPresent = true;
					break;
				}
			if(!isPresent)
				attributeMissingList.add(attributeRequired);
		}
		
		AttributeInfo[] ret = new AttributeInfo[attributeMissingList.size()];
		attributeMissingList.toArray(ret);
		return ret;
	}

	public static String sp_generateXML(AttributeInfo[] attributesObtained, PrivateKeyEntry privateKey, String spMetadataPath) throws Exception{
		Document ret = XMLUtils.createNewDocument();
		Element attribList = ret.createElement("attributeList");
		ret.appendChild(attribList);
		attribList.setAttribute("ID", "1");
		attribList.setAttribute("entityID", saml_getEntityIDFromSingleMetadata(spMetadataPath));
		for(AttributeInfo attributeObtained:attributesObtained){
			Element attrib = ret.createElement("attribute");
			attribList.appendChild(attrib);
			attrib.setAttribute("name", attributeObtained.name.replaceAll("(\\W|_)+", ""));
			attrib.setAttribute("friendlyName", attributeObtained.friendlyName.replaceAll("(\\W|_)+", ""));
			for(String value:attributeObtained.valueList){
				Element valueEl = ret.createElement("value");
				attrib.appendChild(valueEl);
				valueEl.setTextContent(value);
			}
		}
		
		if(privateKey!=null && spMetadataPath!=null && !spMetadataPath.isEmpty()){
		    Document metadataXml = XMLUtils.getXmlDocFromURI(spMetadataPath);
            Document signedDoc = saml_signXML(ret.getDocumentElement(), privateKey).getOwnerDocument();
            if(!saml_verifyXMLSignatures(XMLUtils.getXmlDocFromString(XMLUtils.getStringFromXmlDoc(signedDoc)).getDocumentElement(), metadataXml))
                throw new Exception("ERROR: Digital Signature invalid \nCheck if the signing certificate is the same you have provided in the federated metadata about SP");
            ret = signedDoc;
        }
		
		return XMLUtils.getStringFromXmlDoc(ret);
	}
	
	public enum NameIDFormat{
		unspecified("urn:oasis:names:tc:SAML:1.1:nameidformat:unspecified"),
		saml2transient("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
		private final String text;
	    private NameIDFormat(String text) { this.text = text; }
	    @Override
	    public String toString() { return text; }
	}
	//Attribute Query in Direct Mode
	public static String sp_generateSamlAttributeQuery(String federatedMetadataUrl, String spEntityID, String aaEntityID, String nameID, NameIDFormat nameIDFormat, PrivateKeyEntry privateKey, AttributeInfo[] attributeList) throws Exception{
		String id = "_" + java.util.UUID.randomUUID();

		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataUrl);

		String destinationURL = (String) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='EntityDescriptor'][@entityID='"+aaEntityID+"']//*[local-name()='AttributeService'][@Binding='urn:oasis:names:tc:SAML:2.0:bindings:SOAP']/@Location", XPathConstants.STRING);
		if(destinationURL.isEmpty())
			throw new Exception("ERROR: Can not obtain AttributeService Location for the ID " + aaEntityID);

		Document doc = XMLUtils.createNewDocument();
		Element attributeQueryNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:AttributeQuery");
		doc.appendChild(attributeQueryNode);
		attributeQueryNode.setAttribute("ID", id);
		attributeQueryNode.setIdAttribute("ID", true);
		attributeQueryNode.setAttribute("Version", "2.0");
		attributeQueryNode.setAttribute("IssueInstant", Utils.getUTCTime());
		attributeQueryNode.setAttribute("Destination", destinationURL);

		Element issuerNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Issuer");
		attributeQueryNode.appendChild(issuerNode);
		issuerNode.setAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"); //richiesto spid
		issuerNode.setTextContent(spEntityID);
		
		Element subjectNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Subject");
		attributeQueryNode.appendChild(subjectNode);
		Element nameIDNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:NameID");
		subjectNode.appendChild(nameIDNode);
		nameIDNode.setAttribute("Format", nameIDFormat.toString()); //richiesto da SPID urn:oasis:names:tc:SAML:1.1:nameidformat:unspecified //altrimenti togliere o urn:oasis:names:tc:SAML:2.0:nameid-format:transient
		nameIDNode.setAttribute("NameQualifier", aaEntityID);
		nameIDNode.setTextContent(nameID);
		
		if(attributeList!=null)
			for(AttributeInfo attribute:attributeList){
				Element attributeNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Attribute");
				attributeQueryNode.appendChild(attributeNode);
				attributeNode.setAttribute("Name", attribute.name);
				attributeNode.setAttribute("NameFormat", attribute.nameFormat);
			}
		
		if(privateKey!=null){
			Document signedDoc = saml_signXML(doc.getDocumentElement(), privateKey).getOwnerDocument();
			if(!saml_verifyXMLSignatures(XMLUtils.getXmlDocFromString(XMLUtils.getStringFromXmlDoc(signedDoc)).getDocumentElement(), metadataXml))
				throw new Exception("ERROR: Digital Signature invalid \nCheck if the signing certificate is the same you have provided in the federated metadata about SP");
			doc = signedDoc;
		}
		
		String ret = XMLUtils.getStringFromXmlDoc(doc);
		
		return ret;
	}
	
	public static String sp_sendRequestUsingSoap(String request, String aaEntityID, String federatedMetadataUrl) throws Exception{
		
		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataUrl);
		
		String destinationURL = (String) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='EntityDescriptor'][@entityID='"+aaEntityID+"']//*[local-name()='AttributeService'][@Binding='urn:oasis:names:tc:SAML:2.0:bindings:SOAP']/@Location", XPathConstants.STRING);
		if(destinationURL.isEmpty())
			throw new Exception("ERROR: Can not obtain AttributeService Location for the ID " + aaEntityID);
		
		Document requestXml = XMLUtils.getXmlDocFromString(request);
		Document envelopeXml = XMLUtils.createNewDocument();
		org.w3c.dom.Element envelope = envelopeXml.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "Envelope");
		envelopeXml.appendChild(envelope);
		org.w3c.dom.Element body = envelopeXml.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "Body");
		envelope.appendChild(body);
		body.appendChild(envelopeXml.importNode(requestXml.getDocumentElement(), true));
		
		String dataToSend = XMLUtils.getStringFromXmlDoc(envelopeXml);
		String responseEnvelope = new String(NETUtils.sendHTTPPOST(destinationURL, dataToSend, null, false, false),"UTF-8");
		Document retXml = XMLUtils.getXmlDocFromString(responseEnvelope);
		Node responseNode = retXml.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol","Response").item(0);
		return XMLUtils.getStringFromXmlDoc(responseNode);
	}
	
	public static String sp_generateSamlLogoutRequest(String federatedMetadataUrl, String spEntityID, String idpEntityID, String nameID, String nameIDFormat, PrivateKeyEntry privateKey) throws Exception{
		String id = "_" + java.util.UUID.randomUUID();

		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataUrl);

		String destinationURL = (String) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='EntityDescriptor'][@entityID='"+idpEntityID+"']//*[local-name()='SingleLogoutService'][@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location", XPathConstants.STRING);
		if(destinationURL.isEmpty())
			throw new Exception("ERROR: Can not obtain SingleLogoutService Location for the ID " + idpEntityID);

		Document doc = XMLUtils.createNewDocument();
		Element logoutRequestNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:LogoutRequest");
		doc.appendChild(logoutRequestNode);
		logoutRequestNode.setAttribute("ID", id);
		logoutRequestNode.setIdAttribute("ID", true);
		logoutRequestNode.setAttribute("Version", "2.0");
		logoutRequestNode.setAttribute("IssueInstant", Utils.getUTCTime());
		logoutRequestNode.setAttribute("Destination", destinationURL);

		Element issuerNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Issuer");
		logoutRequestNode.appendChild(issuerNode);
		issuerNode.setAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"); //richiesto spid
		issuerNode.setTextContent(spEntityID);
		
		
		Element nameIDNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:NameID");
		logoutRequestNode.appendChild(nameIDNode);
		nameIDNode.setAttribute("Format", nameIDFormat); //richiesto da SPID urn:oasis:names:tc:SAML:1.1:nameidformat:unspecified //altrimenti togliere o urn:oasis:names:tc:SAML:2.0:nameid-format:transient
		nameIDNode.setAttribute("NameQualifier", idpEntityID);
		nameIDNode.setTextContent(nameID);
		
		if(privateKey!=null){
			Document signedDoc = saml_signXML(doc.getDocumentElement(), privateKey).getOwnerDocument();
			if(!saml_verifyXMLSignatures(XMLUtils.getXmlDocFromString(XMLUtils.getStringFromXmlDoc(signedDoc)).getDocumentElement(), metadataXml))
				throw new Exception("ERROR: Digital Signature invalid \nCheck if the signing certificate is the same you have provided in the federated metadata about SP");
			doc = signedDoc;
		}
		
		String ret = XMLUtils.getStringFromXmlDoc(doc);
		
		return ret;
	}
	
	public static String sp_generateSamlLogoutResponse(String federatedMetadataUrl, String spEntityID, String idpEntityID, String samlRequest, boolean isSuccessResponse, String statusMessage, PrivateKeyEntry privateKey) throws Exception{
		String id = "_" + java.util.UUID.randomUUID();

		String statusCode = "urn:oasis:names:tc:SAML:2.0:status:Success";
		if(!isSuccessResponse)
			statusCode = "urn:oasis:names:tc:SAML:2.0:status:Requester";
		
		Document samlRequestXml = XMLUtils.getXmlDocFromString(samlRequest);
		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataUrl);

		String inResponseTo = (String) XMLUtils.execXPath(samlRequestXml.getDocumentElement(), "//*[local-name()='LogoutRequest']/@ID", XPathConstants.STRING);
		
		String destinationURL = (String) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='EntityDescriptor'][@entityID='"+idpEntityID+"']//*[local-name()='SingleLogoutService'][@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location", XPathConstants.STRING);
		if(destinationURL.isEmpty())
			throw new Exception("ERROR: Can not obtain SingleLogoutService Location for the ID " + idpEntityID);

		Document doc = XMLUtils.createNewDocument();
		Element logoutResponseNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:LogoutResponse");
		doc.appendChild(logoutResponseNode);
		logoutResponseNode.setAttribute("ID", id);
		logoutResponseNode.setIdAttribute("ID", true);
		logoutResponseNode.setAttribute("Version", "2.0");
		logoutResponseNode.setAttribute("IssueInstant", Utils.getUTCTime());
		logoutResponseNode.setAttribute("Destination", destinationURL);
		logoutResponseNode.setAttribute("InResponseTo", inResponseTo);
		
		Element issuerNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Issuer");
		logoutResponseNode.appendChild(issuerNode);
		issuerNode.setAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"); //richiesto spid
		issuerNode.setTextContent(spEntityID);
		
		Element statusNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:Status");
		logoutResponseNode.appendChild(statusNode);
		Element statusCodeNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:StatusCode");
		statusNode.appendChild(statusCodeNode);
		statusCodeNode.setAttribute("Value", statusCode);
		if(statusMessage!=null){
			Element statusMessageNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:StatusMessageNode");
			statusNode.appendChild(statusMessageNode);
			statusMessageNode.setTextContent(statusMessage);
		}
		
		if(privateKey!=null){
			Document signedDoc = saml_signXML(doc.getDocumentElement(), privateKey).getOwnerDocument();
			if(!saml_verifyXMLSignatures(XMLUtils.getXmlDocFromString(XMLUtils.getStringFromXmlDoc(signedDoc)).getDocumentElement(), metadataXml))
				throw new Exception("ERROR: Digital Signature invalid \nCheck if the signing certificate is the same you have provided in the federated metadata about SP");
			doc = signedDoc;
		}
		
		String ret = XMLUtils.getStringFromXmlDoc(doc);
		
		return ret;
	}
	
	public static String[] saml_getIdPsProvidingAttribute(String federatedMetadataPath, String attributeName, String attributeNameFormat) throws Exception{
		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataPath);
		
		NodeList idpEntityList =  (NodeList) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='Attribute' and @Name='"+attributeName+"' and @NameFormat='"+attributeNameFormat+"']/../../.", XPathConstants.NODESET);
		if(idpEntityList.getLength()==0)
			idpEntityList =  (NodeList) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='Attribute' and @Name='"+attributeName+"']/../../.", XPathConstants.NODESET);
		
		String[] ret = new String[idpEntityList.getLength()];
		for(int i=0;i<idpEntityList.getLength();i++)
			ret[i] = idpEntityList.item(i).getAttributes().getNamedItem("entityID").getNodeValue();
		return ret;
	}
	/*
	public static String saml_getAttributeServiceLocation(String federatedMetadataPath, String idpID) throws Exception{
		String bindingToUse = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataPath);
		String location =  (String) XMLUtils.execXPath(metadataXml.getDocumentElement(), "//*[local-name()='EntityDescriptor'][@entityID='"+idpID+"']//*[local-name()='AttributeService'][@Binding='"+bindingToUse+"']/@Location", XPathConstants.STRING);
		return location;
	}
	*/
	public static String saml_getIdPSingleSignOnServiceLocation(String federatedMetadataPath, String idpID, boolean postBinding) throws Exception{
		String bindingToUse = (postBinding)?"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataPath);
		String location =  (String) XMLUtils.execXPath(metadataXml.getDocumentElement(), "//*[local-name()='EntityDescriptor'][@entityID='"+idpID+"']//*[local-name()='SingleSignOnService'][@Binding='"+bindingToUse+"']/@Location", XPathConstants.STRING);
		return location;
	}
	
	public static String saml_getIdPSingleLogoutServiceLocation(String federatedMetadataPath, String idpID, boolean postBinding) throws Exception{
		String bindingToUse = (postBinding)?"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataPath);
		String location =  (String) XMLUtils.execXPath(metadataXml.getDocumentElement(), "//*[local-name()='EntityDescriptor'][@entityID='"+idpID+"']//*[local-name()='SingleLogoutService'][@Binding='"+bindingToUse+"']/@Location", XPathConstants.STRING);
		return location;
	}
	
	public static String saml_getEntityIDFromSingleMetadata(String metadataURI) throws Exception{
		Document metadataXml = XMLUtils.getXmlDocFromURI(metadataURI);
		String entityID =  (String) XMLUtils.execXPath(metadataXml.getDocumentElement(), "//*[local-name()='EntityDescriptor']/@entityID", XPathConstants.STRING);
		return entityID;
	}
	
	public static String saml_getSamlResponseIssuer(String samlResponse) throws Exception{
		Document samlResponseXml = XMLUtils.getXmlDocFromString(samlResponse);
		String issuer =  (String) XMLUtils.execXPath(samlResponseXml.getDocumentElement(), "//*[local-name()='Issuer']", XPathConstants.STRING);
		return issuer;
	}
	
	public static String saml_getSamlResponseNameID(String samlResponse) throws Exception{
		Document samlResponseXml = XMLUtils.getXmlDocFromString(samlResponse);
		String nameID =  (String) XMLUtils.execXPath(samlResponseXml.getDocumentElement(), "//*[local-name()='NameID']", XPathConstants.STRING);
		return nameID;
	}
	
	public static AttributeInfo saml_getAttributeInfo(AttributeInfo[] attributeInfoList, String name, String nameFormat) throws Exception{
		for(AttributeInfo attributeInfo:attributeInfoList)
			if(attributeInfo.name.equals(name) && attributeInfo.nameFormat.equals(nameFormat))
				return attributeInfo;
		throw new Exception("ERROR: attribute "+name+" format "+nameFormat+" not present");
	}
	
	public static AttributeInfo saml_getAttributeInfo(AttributeInfo[] attributeInfoList, String name) throws Exception{
		for(AttributeInfo attributeInfo:attributeInfoList)
			if(attributeInfo.name.equals(name))
				return attributeInfo;
		throw new Exception("ERROR: attribute "+name+" not present");
	}
	
	public static String saml_chooseFederationToUse(String idpID, String spID, String[] federatedMetadataPathList) throws Exception{
		for(String federatedMetadataPath:federatedMetadataPathList){
			Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataPath);
			Node idp = (Node) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='EntityDescriptor'][@entityID='"+idpID+"']", XPathConstants.NODE);
			Node sp = (Node) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='EntityDescriptor'][@entityID='"+spID+"']", XPathConstants.NODE);
			if(idp!=null && sp!=null)
				return federatedMetadataPath;
		}
		throw new Exception("ERROR: Can not find any federation metadata containing both " + idpID + " and " + spID);
	}
	
	public static String saml_chooseFederationToUse(String entityID, String[] federatedMetadataPathList) throws Exception{
		for(String federatedMetadataPath:federatedMetadataPathList){
			Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataPath);
			Node entity = (Node) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='EntityDescriptor'][@entityID='"+entityID+"']", XPathConstants.NODE);
			if(entity!=null)
				return federatedMetadataPath;
		}
		throw new Exception("ERROR: Can not find any federation metadata containing " + entityID);
	}
	
	public static String[] saml_getUsableFederations(String entityID, String[] federatedMetadataPathList) throws Exception{
		return saml_getUsableFederations(entityID, entityID, federatedMetadataPathList);
	}
	
	public static String[] saml_getUsableFederations(String idpID, String spID, String[] federatedMetadataPathList) throws Exception{
		ArrayList<String> ret = new ArrayList<String>();
		for(String federatedMetadataPath:federatedMetadataPathList){
			Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataPath);
			Node idp = (Node) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='EntityDescriptor'][@entityID='"+idpID+"']", XPathConstants.NODE);
			Node sp = (Node) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='EntityDescriptor'][@entityID='"+spID+"']", XPathConstants.NODE);
			if(idp!=null && sp!=null)
				ret.add(federatedMetadataPath);
		}
		if(ret.size()!=0){
			String[] retS = new String[ret.size()];
			ret.toArray(retS);
			return retS;
		}
		throw new Exception("ERROR: Can not find any federation metadata containing both " + idpID + " and " + spID);
	}
	
	public static String saml_getDiscoveryReturnUrl(String spID, String returnUrlToCheck, String federatedMetadataUrl) throws Exception{
		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataUrl);
		Node discoveryResponseNode = null;
		if(returnUrlToCheck == null || returnUrlToCheck.isEmpty())
			discoveryResponseNode = (Node) XMLUtils.execXPath(metadataXml.getDocumentElement(), "//*[local-name()='EntityDescriptor'][@entityID='"+spID+"']//*[local-name()='DiscoveryResponse']", XPathConstants.NODE);
		else
			discoveryResponseNode = (Node) XMLUtils.execXPath(metadataXml.getDocumentElement(), "//*[local-name()='EntityDescriptor'][@entityID='"+spID+"']//*[local-name()='DiscoveryResponse'][@Location='"+returnUrlToCheck+"']", XPathConstants.NODE);
		if(discoveryResponseNode == null)
			throw new Exception("ERROR: Can not find any DiscoveryResponse for in " + federatedMetadataUrl + " for the SP " + spID + " with specified returnUrl: " + returnUrlToCheck);
		
		String location = discoveryResponseNode.getAttributes().getNamedItem("Location").getNodeValue();
		return location;
	}
	
	public final static class idpInfo{
		public String id = "";
		public String[] nameList = new String[0];
		public String[] imgUrlList =  new String[0];
	}
	public static SAML2.idpInfo[] wayf_getAllIdpInfo(String federatedMetadataUrl) throws Exception{
		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataUrl);
		NodeList idpEntityList =  (NodeList) XMLUtils.execXPath(metadataXml.getDocumentElement(), ".//*[local-name()='IDPSSODescriptor']/../.", XPathConstants.NODESET);
		
		SAML2.idpInfo[] idpList = new SAML2.idpInfo[idpEntityList.getLength()];
		for(int i=0;i<idpEntityList.getLength();i++){
			SAML2.idpInfo idpInfo = new SAML2.idpInfo();
			idpInfo.id = idpEntityList.item(i).getAttributes().getNamedItem("entityID").getNodeValue();
			
			String nameIT =  (String) XMLUtils.execXPath(idpEntityList.item(i), ".//*[local-name()='DisplayName' and @*[local-name()='lang']='it']", XPathConstants.STRING);
			if(nameIT.isEmpty())
				nameIT =  (String) XMLUtils.execXPath(idpEntityList.item(i), ".//*[local-name()='OrganizationDisplayName' and @*[local-name()='lang']='it']", XPathConstants.STRING);
			if(nameIT.isEmpty())
				nameIT =  (String) XMLUtils.execXPath(idpEntityList.item(i), ".//*[local-name()='OrganizationName' and @*[local-name()='lang']='it']", XPathConstants.STRING);
			if(nameIT.isEmpty())
				nameIT =  idpInfo.id;
			String nameEN =  (String) XMLUtils.execXPath(idpEntityList.item(i), ".//*[local-name()='DisplayName' and @*[local-name()='lang']='en']", XPathConstants.STRING);
			if(nameEN.isEmpty())
				nameEN =  (String) XMLUtils.execXPath(idpEntityList.item(i), ".//*[local-name()='OrganizationDisplayName' and @*[local-name()='lang']='en']", XPathConstants.STRING);
			if(nameEN.isEmpty())
				nameEN =  (String) XMLUtils.execXPath(idpEntityList.item(i), ".//*[local-name()='OrganizationName' and @*[local-name()='lang']='en']", XPathConstants.STRING);
			if(nameEN.isEmpty())
				nameEN =  idpInfo.id;
			idpInfo.nameList = new String[]{nameIT, nameEN};
			
			
			NodeList logoList =  (NodeList) XMLUtils.execXPath(idpEntityList.item(i), ".//*[local-name()='Logo']", XPathConstants.NODESET);
			String[] imgList = new String[logoList.getLength()];
			for(int j=0;j<logoList.getLength();j++)
				imgList[j] = logoList.item(j).getTextContent().replaceAll("\\s","");
				
			idpInfo.imgUrlList = imgList;
			
			idpList[i] = idpInfo;
		}
		return idpList;
	}
	
	public static boolean saml_verifyXMLSignatures(Node doc, Document metadataXml) throws Exception{
		
		NodeList signatureList =  (NodeList) XMLUtils.execXPath(doc, ".//*[namespace-uri()='http://www.w3.org/2000/09/xmldsig#' and local-name()='Signature']", XPathConstants.NODESET);

		for(int i=0;i<signatureList.getLength();i++){
			Node signatureNode = signatureList.item(i);
			
			if(signatureNode.getParentNode() instanceof Element)
				((Element) signatureNode.getParentNode()).setIdAttribute("ID", true);
			
			String entityID =  (String) XMLUtils.execXPath(signatureNode.getParentNode(), ".//*[local-name()='Issuer']", XPathConstants.STRING);
			if(entityID.length()==0)
				entityID = (String) XMLUtils.execXPath(signatureNode.getParentNode(), "./@entityID", XPathConstants.STRING);
			if(entityID.length()==0)
				throw new Exception("ERROR: Can not find the entityID who have created the signature");
			
			NodeList nodeList =  (NodeList) XMLUtils.execXPath(metadataXml.getDocumentElement(), "//*[local-name()='EntityDescriptor'][@entityID='"+entityID+"']//*[local-name()='X509Certificate']", XPathConstants.NODESET);
			if(nodeList.getLength()==0)
				throw new Exception("ERROR: Can not find X509 Certificates for " + entityID + " in the federated metadata");
			
			X509Certificate[] certificateList = new X509Certificate[nodeList.getLength()];
			for(int j=0;j<nodeList.getLength();j++)
				certificateList[j] = X509Utils.getX509Certificate(nodeList.item(j).getTextContent().trim());
			
			if(!XMLUtils.verifySignature(signatureNode, certificateList))
				return false;
		}
		return true;
	}
	
	public static Node saml_signXML(Node doc, PrivateKeyEntry keyEntry) throws Exception{
		
		doc = XMLUtils.getXmlDocFromString(XMLUtils.getStringFromXmlDoc(doc)).getDocumentElement();
		
		if(doc.getAttributes().getNamedItem("ID") == null)
			throw new Exception("ERROR: ID Attribute is not present");
		
		String nodeID = doc.getAttributes().getNamedItem("ID").getNodeValue();
		String refID = "#" + nodeID;
		
		if(doc instanceof Element)
			((Element) doc).setIdAttribute("ID", true);
		
		DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc);
		
		Node issuerNode =  (Node) XMLUtils.execXPath(doc, ".//*[local-name()='Issuer']", XPathConstants.NODE);
		if(issuerNode!=null)
			dsc.setNextSibling(issuerNode.getNextSibling()); //la firma per asserzioni e richieste/risposte saml va dopo il nodo Issuer
		else
			dsc.setNextSibling(doc.getFirstChild()); //la firma per i metadati va come primo elemento

		X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		List<Transform> trasformList = new ArrayList<Transform>();
		trasformList.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
		trasformList.add(fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null));
		Reference ref = fac.newReference(refID, fac.newDigestMethod(DigestMethod.SHA1, null), trasformList, null, null);		
		SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,(C14NMethodParameterSpec) null), fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));
		KeyInfoFactory kif = fac.getKeyInfoFactory();
		List<Object> x509Content = new ArrayList<Object>();
		x509Content.add(cert.getSubjectX500Principal().getName());
		x509Content.add(cert);
		X509Data xd = kif.newX509Data(x509Content);
		KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
		XMLSignature signature = fac.newXMLSignature(si, ki);
		
		signature.sign(dsc);
		return doc;
	}
	
	public static String saml_generateDetachedSignature(String plaintext, PrivateKeyEntry keyEntry) throws Exception{
		PrivateKey privateKey = keyEntry.getPrivateKey();
		Signature instance = Signature.getInstance("SHA1withRSA");
		instance.initSign(privateKey);
		instance.update(plaintext.getBytes());
		byte[] signature = instance.sign();
		return Base64Fast.encodeToString(signature, false);
	}
	
	public static void verifyDetachedSignature(String toVerify, String algorithm, String signatureS, String samlResponse, Configuration cfg) throws Exception{
		if(algorithm.contains("rsa-sha1"))
			algorithm = "SHA1withRSA";
		else
			algorithm = "SHA1withDSA";
		
		Document samlResponseXml = XMLUtils.getXmlDocFromString(samlResponse);
		String issuer =  (String) XMLUtils.execXPath(samlResponseXml.getDocumentElement(), ".//*[local-name()='Issuer']", XPathConstants.STRING);
		
		String federatedMetadataUrl = SAML2.saml_chooseFederationToUse(issuer, cfg.getAllFederationMetadataURI());
		Document metadataXml = XMLUtils.getXmlDocFromURI(federatedMetadataUrl);
		
		NodeList nodeList =  (NodeList) XMLUtils.execXPath(metadataXml.getDocumentElement(), "//*[local-name()='EntityDescriptor'][@entityID='"+issuer+"']//*[local-name()='X509Certificate']", XPathConstants.NODESET);
		if(nodeList.getLength()==0)
			throw new Exception("ERROR: Can not find X509 Certificates for " + issuer + " in the federated metadata");
		
		X509Certificate[] certificateList = new X509Certificate[nodeList.getLength()];
		for(int j=0;j<nodeList.getLength();j++)
			certificateList[j] = X509Utils.getX509Certificate(nodeList.item(j).getTextContent().trim());
		
		for(X509Certificate certificate:certificateList){
			PublicKey pubKey = certificate.getPublicKey();
			Signature signature = Signature.getInstance(algorithm);
			signature.initVerify(pubKey);
			signature.update(toVerify.getBytes());
			boolean res = signature.verify(Base64Fast.decode(signatureS));
			if(res)
				return;
		}
		
		throw new Exception("ERROR: Signature not valid");
	}
	
	/*
	public static void saml_decryptXML(Node doc) throws Exception{
		String samlResponseEnc = new String(readFile(new File("C:\\Users\\Mi0\\Desktop\\xmlEnc.txt")));
		Document samlResponseEncXml = XMLUtils.getXmlDocFromString(samlResponseEnc);
		Element keyNode = (Element) samlResponseEncXml.getElementsByTagName("EncryptedKey").item(0);
		
	}
	*/
	
	public final static class ServiceSessionInfo{
		public String serviceURL = "";
		
		public String serviceLogoutURL = "";

		public AttributeInfo[] attributesObtained = new AttributeInfo[0];
		public String idpEntityID = "";

		public AuthnContext[] authnContextList = null;
		public AuthnContextComparison authnContextComparisonType = null;
	}
	
	public static byte[] readFile(File file) throws Exception{
		RandomAccessFile raf = new RandomAccessFile(file, "r");
		byte[] ret = new byte[(int)raf.length()];
		raf.read(ret);
		raf.close();
		return ret;
	}
}
