/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.Map;

import javax.naming.Context;
import javax.naming.directory.InitialDirContext;

public class X509Utils {
	
	public static PrivateKeyEntry readPrivateKey(String keystorePath, String keystoreType, String keystorePassword, String certificateAlias, String certificatePassword) throws Exception{
		KeyStore ks = KeyStore.getInstance(keystoreType);
		ks.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());
		PrivateKeyEntry keyEntry = (PrivateKeyEntry) ks.getEntry (certificateAlias, new KeyStore.PasswordProtection(certificatePassword.toCharArray()));
		return keyEntry;
	}
	
	public static boolean checkValidity(X509Certificate cert, Date validUntill){
		try{
			if(validUntill!=null)
				cert.checkValidity(validUntill);
			else
				cert.checkValidity();

			return true;
		}catch(Exception e){}
		return false;
	}
	
	public static boolean checkIsForSigning(X509Certificate cert){
		if(cert.getKeyUsage()[0])
			return true;
		return false;
	}
	
	public static boolean checkIsNonRepudiation(X509Certificate cert){
		if(cert.getKeyUsage()[1])
			return true;
		return false;
	}
	
	public static byte[] readFile(File file) throws Exception{
		RandomAccessFile raf = new RandomAccessFile(file, "r");
		byte[] ret = new byte[(int)raf.length()];
		raf.read(ret);
		raf.close();
		return ret;
	}
	public static void writeFile(byte[] data, String filePath, boolean appendData) throws Exception{
		FileOutputStream fos = new FileOutputStream(new File(filePath), appendData);
		fos.write(data);
		fos.flush();
		fos.close();
	}
	public static X509Certificate getX509Certificate(String x509Certificate) throws Exception {
		//String file = new String(readFile(new File("C:\\Users\\Mi0\\Desktop\\test.cer")));
		//x509Certificate= file;
		
		if(!x509Certificate.startsWith("-----BEGIN CERTIFICATE-----"))
			x509Certificate = "-----BEGIN CERTIFICATE-----\n" + x509Certificate.replaceAll("\\s","") + "\n-----END CERTIFICATE-----\n";
		//writeFile(x509Certificate.getBytes(),"C:\\Users\\Mi0\\Desktop\\test2.cer", false);
		return getX509Certificate(x509Certificate.getBytes());
	}
	
	public static X509Certificate getX509Certificate(byte[] x509Certificate) throws Exception {
		return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(x509Certificate));
	}
	
	public static String getCN(X509Certificate cert){
		String certificateSubject = cert.getSubjectDN().getName();
		if(certificateSubject.indexOf("CN=") == -1)
			return "";
		String CN = certificateSubject.substring(certificateSubject.indexOf("CN=")+3);
		int lastIndex = CN.indexOf(',');
		if(lastIndex == -1)
			lastIndex = CN.length();
		CN = CN.substring(0, lastIndex);
		return CN;
	}
	
	public static String getCFFromCertSubject(String certificateSubject){
		String cfRegexPattern = "\\p{Upper}\\p{Upper}\\p{Upper}\\p{Upper}\\p{Upper}\\p{Upper}\\p{Digit}\\p{Digit}\\p{Upper}\\p{Digit}\\p{Digit}\\p{Upper}\\p{Digit}\\p{Digit}\\p{Digit}\\p{Upper}";

		if(certificateSubject.contains("CN=")){
			String CN = certificateSubject.substring(certificateSubject.indexOf("CN=")+3);
			int lastIndex = CN.length();
			if(CN.indexOf(',')!=-1)
				lastIndex = CN.indexOf(',');
			CN = CN.substring(0, lastIndex);
			if(CN.contains("/"))
				CN=CN.split("/")[0].substring(1);
			if(CN.matches(cfRegexPattern))
				return CN;
		}
		
		if(certificateSubject.contains("SERIALNUMBER=")){
			String SERIALNUMBER = certificateSubject.substring(certificateSubject.indexOf("SERIALNUMBER=")+13);
			int lastIndex = SERIALNUMBER.length();
			if(SERIALNUMBER.indexOf(',')!=-1)
				lastIndex = SERIALNUMBER.indexOf(',');
			SERIALNUMBER = SERIALNUMBER.substring(0, lastIndex);
			if(SERIALNUMBER.contains(":"))
				SERIALNUMBER = SERIALNUMBER.split(":")[1];
			if(SERIALNUMBER.matches(cfRegexPattern))
				return SERIALNUMBER;
		}
		return "";
	}
	
	public static ArrayList<String> getDistributionPointUrls(X509Certificate cert){
		
		ArrayList<String> ret = new ArrayList<String>();
		
		try{
			String data = cert.toString();
			
			if(data.indexOf("CRLDistributionPoints") == -1)
				return ret;
			
			data = data.substring(data.indexOf("CRLDistributionPoints"));
			data = data.substring(0, data.indexOf("]]") + 2);
			
			while(data.indexOf("URIName") != -1){
				data = data.substring(data.indexOf("URIName") + 9);
				
				String url = data.substring(0, data.indexOf("]"));
				
				if(url.contains(", URIName: ")){
					String[] urlTmpList = url.split(", URIName: ");
					for(String urlTmp:urlTmpList)
						ret.add(urlTmp);
				}else
					ret.add(url);
				
				data = data.substring(data.indexOf("]") + 1);
			}
		}catch(Exception ex){ex.printStackTrace();}
		
		return ret;
	}
	
	public static X509CRL getX509CRLFromURL(String url){
		try{
			InputStream inStream = null;
			
			if(url.startsWith("ldap")){
				Map<String, String> env = new Hashtable<String, String>();
				env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
				env.put(Context.PROVIDER_URL, url);
	
				byte[] val = (byte[]) new InitialDirContext((Hashtable<String, String>)env).getAttributes("").get("certificateRevocationList;binary").get();
		        
				if ((val == null) || (val.length == 0))
		        	throw new Exception("Can not download CRL from: " + url);
				
		        inStream = new ByteArrayInputStream(val);
		        
			} else{
				try{
					inStream = new URL(url).openStream();
				}catch(Exception e){throw new Exception("Can not download CRL from: " + url + "\n" + e.getMessage());}
			}
	        
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL) cf.generateCRL(inStream);
			inStream.close();
			
			return crl;
			
		}catch(Exception ex){ex.printStackTrace();}
		
		return null;
	}
	
	public static boolean checkIsRevoked(X509Certificate cert){
		ArrayList<String> crlDPUrlList = getDistributionPointUrls(cert);
		X509CRL x509CRL = null;
		for(String crlDPUrl: crlDPUrlList){
			x509CRL = getX509CRLFromURL(crlDPUrl);
			if(x509CRL != null)
				break;
		}
		if(x509CRL == null)
			return false;
		
		return x509CRL.isRevoked(cert);
	}
	
	public static boolean checkIsSelfSigned(X509Certificate cert){
		try{
			cert.verify(cert.getPublicKey());
			return true;
		}catch(Exception ex){}
		return false;
	}
}
