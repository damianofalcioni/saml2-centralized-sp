/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.servlet.test;

import java.io.ByteArrayInputStream;
import java.net.URLEncoder;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;


public class SPConnector {

    private String x509SPCertificate = "-----BEGIN CERTIFICATE-----\nMIIDXzCCAkegAwIBAgIEHkXaHjANBgkqhkiG9w0BAQsFADBgMRAwDgYDVQQGEwdVbmtub3duMRAwDgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMQwwCgYDVQQKEwNvY3AxDDAKBgNVBAsTA29jcDEMMAoGA1UEAxMDb2NwMB4XDTE1MDYwOTE3MjcyMVoXDTE2MDYwMzE3MjcyMVowYDEQMA4GA1UEBhMHVW5rbm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5rbm93bjEMMAoGA1UEChMDb2NwMQwwCgYDVQQLEwNvY3AxDDAKBgNVBAMTA29jcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAITAsN+ivcK/4rHzwIi4TGGf9PyQhKLFRP1O2zUmz9rY5nsRMPUiZsGvdtpzUSoswWyhm8c8KjyyYDE3Ter0kdRlF7jigAyNUAhH6KBP94U+jkIJxHSs53voJG3K3U6VVO+k2VBqISL+tR9a+J0OmIuSQdncJVwVcZIaD2AdeHQoU1DoPo4rUpdj8wKkxbhD464TJPZkVAbIQMeuNP47KOQ0rml0Mt6YbTSN0QE6CpP0+NbVBe8nmSeX5j4+FOuLJlogW1IWXD8tsCjfXvVds0lL7vrFTfeXLHp1ibi7gSeTk5Z8ezBnQZP5tYxYYWD/J8Dr+XXEc4BZgflBH1eh7PECAwEAAaMhMB8wHQYDVR0OBBYEFEdu4lE9VJoEA2ioVROV0uKNCzVvMA0GCSqGSIb3DQEBCwUAA4IBAQAZ9B0xPdaM/MDuObTlumphj4kwJBpvOzt7Q4Kq0B93aVEkjecc1s/RnESLG9ra7bY7vDdod6BKmP1pBoW1nWy9/g2me4WT6sBsZ5DgNp/ZTL7n1EeYSpcMsa4jPL7MsRodcRHo8qgJhit8j5XMkVzDGBCmjpr3jO31KG8cHS/oCLwvlmrzBpl+A7XmWbri1juW9+oOu57qfCaPAo8hwOL/2MKGoJbarhTUw4JDiWAzhxZTc2E3lQ8W43/hrPGyOg/e4AXir41R/te5PrnkDzrwXOoIa05CPnPhs3UeuWdt+vA+ppvv04Dm1qVkfgLHgggi/PAnKG+TTFYOCms8IlXR\n-----END CERTIFICATE-----\n";
    
	private String centralizedSPUrl = null;
	private String serviceLogoutUrl = null;
	private String serviceLoginUrl = null;
	private String[] authenticationMethodList = null;
	
	public SPConnector(String centralizedSPUrl, String serviceLoginUrl, String serviceLogoutUrl, String[] authenticationMethodList){
		this.serviceLogoutUrl = serviceLogoutUrl;
		this.serviceLoginUrl = serviceLoginUrl;
		this.authenticationMethodList = authenticationMethodList;
		this.centralizedSPUrl = centralizedSPUrl;
	}
	
	public void login(HttpServletRequest request, HttpServletResponse response) throws Exception{
		if(serviceLogoutUrl == null || serviceLogoutUrl.isEmpty())
			throw new Exception("ERROR: service Logout Url not defined");
		if(centralizedSPUrl == null || centralizedSPUrl.isEmpty())
			throw new Exception("ERROR: centralized SP Url not defined");
		
		if(request.getParameter("xmlAttrib")==null){
			String serviceUrl = request.getRequestURL().toString()+"?"+request.getQueryString();

			String auth = "<auth><serviceURL>"+serviceUrl+"</serviceURL><logoutURL>"+serviceLogoutUrl+"</logoutURL>";
			if(authenticationMethodList != null && authenticationMethodList.length!=0){
				auth += "<authnContextList>";
				for(String authenticationMethod:authenticationMethodList)
					auth += "<authnContext>"+authenticationMethod+"</authnContext>";
				auth += "</authnContextList>";
			}
			auth += "</auth>";

			String authB64 = DatatypeConverter.printBase64Binary(auth.getBytes("UTF-8"));
			
			response.sendRedirect(centralizedSPUrl+"/PoA?xmlAuth="+URLEncoder.encode(authB64,"UTF-8"));
		} else {

		    String userAttributes = new String(DatatypeConverter.parseBase64Binary(request.getParameter("xmlAttrib")));
		    
		    if(!verifySignature(userAttributes))
			    throw new Exception("ERROR: The attributes have an invalid signature");
			
		    request.getSession().setAttribute("userAttributes", userAttributes);
			if(request.getParameter("ReturnUrl")!=null)
				response.sendRedirect(request.getParameter("ReturnUrl"));
		}
	}
	
	public void logout(boolean invalidateSession, HttpServletRequest request, HttpServletResponse response) throws Exception{
		if(request.getParameter("remoteLogout")!=null){
			request.getSession().removeAttribute("userAttributes");
			if(invalidateSession)
				request.getSession().invalidate();
		} else {
			if(request.getParameter("ReturnUrl")!=null)
				response.sendRedirect(request.getParameter("ReturnUrl"));
		}
	}
	
	public String getLogoutUrl() throws Exception{
		return centralizedSPUrl+"/LOGOUT?ReturnUrl="+URLEncoder.encode(serviceLogoutUrl,"UTF-8");
	}
	
	public void protectPage(HttpServletRequest request, HttpServletResponse response) throws Exception{
		if(request.getSession().getAttribute("userAttributes")==null){
		    String url = serviceLoginUrl+"?ReturnUrl="+URLEncoder.encode(request.getRequestURL().toString(),"UTF-8");
			response.sendRedirect(url);
		}
	}
	
	private boolean verifySignature(String docS){
	    try{
	        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
	        dbf.setNamespaceAware(true);
	        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(docS.getBytes()));
	        
	        Node signatureNode = (Node) XPathFactory.newInstance().newXPath().compile(".//*[namespace-uri()='http://www.w3.org/2000/09/xmldsig#' and local-name()='Signature']").evaluate(doc.getDocumentElement(), XPathConstants.NODE);
	        ((Element) signatureNode.getParentNode()).setIdAttribute("ID", true);
	        
	        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(x509SPCertificate.getBytes()));
	        
	        DOMValidateContext valContext = new DOMValidateContext(certificate.getPublicKey(), signatureNode);
            valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
            XMLSignature signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(valContext);
            if(signature.validate(valContext))
                return true;
	    } catch(Exception ex){ex.printStackTrace();}
	    return false;
	}
}
