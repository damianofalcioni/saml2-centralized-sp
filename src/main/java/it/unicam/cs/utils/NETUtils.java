/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.utils;

import java.io.DataOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Random;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class NETUtils {
	
	public static String getHost(String url){
		return url.split("/")[2].split(":")[0];
	}
	
	public static byte[] sendHTTPPOST(String url, String dataToSend, ArrayList<String[]> htmlHeaderList, boolean ignoreSSLSelfSigned, boolean ignoreSSLWrongCN) throws Exception{
		return sendHTTP(url, "POST", dataToSend, htmlHeaderList, ignoreSSLSelfSigned, ignoreSSLWrongCN);
	}
	
	public static byte[] sendHTTPGET(String url, ArrayList<String[]> htmlHeaderList, boolean ignoreSSLSelfSigned, boolean ignoreSSLWrongCN) throws Exception{
		return sendHTTP(url, "GET", null, htmlHeaderList, ignoreSSLSelfSigned, ignoreSSLWrongCN);
	}
	
	public static byte[] sendHTTP(String url, String mode, String dataToSend, ArrayList<String[]> htmlHeaderList, boolean ignoreSSLSelfSigned, boolean ignoreSSLWrongCN) throws Exception{
		
		System.setProperty("java.net.useSystemProxies", "true");
		
		if(ignoreSSLSelfSigned){
			TrustManager[] trustAllCerts = new TrustManager[]{
				    new X509TrustManager() {
				        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				            return null;
				        }
				        public void checkClientTrusted(
				            java.security.cert.X509Certificate[] certs, String authType) {
				        }
				        public void checkServerTrusted(
				            java.security.cert.X509Certificate[] certs, String authType) {
				        }
				    }
				};
			SSLContext sc = SSLContext.getInstance("SSL");
		    sc.init(null, trustAllCerts, new java.security.SecureRandom());
		    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		}
		if(ignoreSSLWrongCN){
			HostnameVerifier allHostsValid = new HostnameVerifier() {
				public boolean verify(String hostname, javax.net.ssl.SSLSession session) {
					return true;
				}
			};
			HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
		}
		
		HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
		
		if(htmlHeaderList != null)
			for(String[] htmlHeader:htmlHeaderList)
				if(htmlHeader.length==2)
					connection.setRequestProperty(htmlHeader[0], htmlHeader[1]);

		if(mode.equals("POST") && dataToSend != null){
			connection.setDoOutput(true);
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Content-Length", "" + Integer.toString(dataToSend.getBytes().length));
			
			DataOutputStream wr = new DataOutputStream(connection.getOutputStream());
			wr.writeBytes(dataToSend);
			wr.flush();
			wr.close();
		}
		
		byte[] output = new byte[0];
		if(connection.getResponseCode() >= 400)
			output = IOUtils.toByteArray(connection.getErrorStream());
		else
			output = IOUtils.toByteArray(connection.getInputStream());

		connection.disconnect();
		
		return output;
	}
	
	public static String getPOSTRedirectPage(String urlWithParameters){
		String url = urlWithParameters;
		String parameters = "";
		if(urlWithParameters.contains("?")){
			url = urlWithParameters.substring(0, urlWithParameters.indexOf("?"));
			parameters = urlWithParameters.substring(urlWithParameters.indexOf("?")+1, urlWithParameters.length());
		}
		return getPOSTRedirectPage(url, parameters);
	}
	
	public static String getPOSTRedirectPage(String urlWithParametersToGet, String parametersToPost){
		String url = urlWithParametersToGet;
		ArrayList<String> paramterList = safeSplitParameters(parametersToPost);
		String postRedirect="<html><head><script type=\"text/javascript\">function redirect() {document.myForm.submit();}</script></head><body OnLoad='redirect();'><FORM name=\"myForm\" method=\"POST\" action=\""+url+"\"><input type=\"submit\" value=\"Continue\">";
		
		for(String parameter:paramterList)
			if(parameter.contains("=")){
				String name = parameter.substring(0, parameter.indexOf("="));
				String value = parameter.substring(parameter.indexOf("=")+1, parameter.length());
				postRedirect += "<input type=\"hidden\" name=\""+name+"\" value=\""+value+"\">";
			}
		postRedirect += "</FORM>";
		postRedirect += "</body></html>";
		return postRedirect;
	}
	
	public static String getPOSTRedirectPageLoadingLogoutUrl(String urlWithParametersToGet, String parametersToPost, ArrayList<String> urlToLoadList){
		String url = urlWithParametersToGet;
		ArrayList<String> paramterList = safeSplitParameters(parametersToPost);
		String postRedirect="<html><head><script type=\"text/javascript\">function redirect() {document.myForm.submit();}</script></head><body OnLoad='redirect();'><FORM name=\"myForm\" method=\"POST\" action=\""+url+"\"><input type=\"submit\" value=\"Continue\">";
		
		for(String parameter:paramterList)
			if(parameter.contains("=")){
				String name = parameter.substring(0, parameter.indexOf("="));
				String value = parameter.substring(parameter.indexOf("=")+1, parameter.length());
				postRedirect += "<input type=\"hidden\" name=\""+name+"\" value=\""+value+"\">";
			}
		postRedirect += "</FORM>";
		
		if(urlToLoadList!=null)
			for(String urlToLoad:urlToLoadList)
				postRedirect+= "<iframe src=\""+urlToLoad+"\"></iframe>";
		
		postRedirect += "</body></html>";
		return postRedirect;
	}
	
	public static ArrayList<String> safeSplitParameters(String parameters){
		if(parameters == null || parameters == "")
			return new ArrayList<String>();
		
		ArrayList<String> ret = new ArrayList<String>();
		
		int index = 0;
		do{
			int nextIndex = parameters.indexOf("&", index);
			if(nextIndex == -1)
				nextIndex = parameters.length();
			
			do{
				if(!parameters.substring(nextIndex).startsWith("&amp;"))
					break;
				nextIndex = parameters.indexOf("&", nextIndex+1);
				if(nextIndex == -1)
					nextIndex = parameters.length();
			}while(true);
			
			ret.add(parameters.substring(index, nextIndex));
			
			index = nextIndex +1;
		}while(index < parameters.length());
		
		return ret;
		//return parameters.split("\\&");
	}
	
	public static ArrayList<String[]> safeGetParameters(String parameters){
		
		ArrayList<String[]> ret = new ArrayList<String[]>();
		
		ArrayList<String> parameterList = safeSplitParameters(parameters);
		
		for(String parameter:parameterList)
			if(parameter.contains("=")){
				String name = parameter.substring(0, parameter.indexOf("="));
				String value = parameter.substring(parameter.indexOf("=")+1, parameter.length());
				ret.add(new String[]{name, value});
			} else {
				ret.add(new String[]{parameter, ""});
			}
		return ret;
	}
	
	public String normalizeECommercial(String data){
		String ret = data;
		for(int i=0;i<ret.length();i++)
			if(ret.charAt(i) == '&' && !ret.substring(i).startsWith("&amp;"))
				ret = ret.substring(0,i) + "&amp;" + ret.substring(i+1, ret.length());
		return ret;
	}
	
	public static String getRandomUserAgent(){
		return getUserAgent(-1);
	}
	
	/*
	 * impostare -1 per avere random
	 * se si imposta un indice fuori range ritorna null
	*/
	public static String getUserAgent(int index){
		ArrayList<String> userAgentList = new ArrayList<String>();
		userAgentList.add("Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.4; en-US; rv:1.9.2.2) Gecko/20100316 Firefox/3.6.2");
		userAgentList.add("Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.5 Safari/537.17");
		userAgentList.add("Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)");
		
		userAgentList.add("Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)");
		userAgentList.add("Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5)");
		userAgentList.add("Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19");
		userAgentList.add("Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.7.6) Gecko/20050405 Epiphany/1.6.1 (Ubuntu) (Ubuntu package 1.0.2)");
		userAgentList.add("Mozilla/5.0 (X11; U; Linux i686; en-US; Nautilus/1.0Final) Gecko/20020408");
		userAgentList.add("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:0.9.3) Gecko/20010801");
		userAgentList.add("Mozilla/5.0 (X11; Linux i686; U;rv: 1.7.13) Gecko/20070322 Kazehakase/0.4.4.1");
		userAgentList.add("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.2b) Gecko/20021007 Phoenix/0.3");
		userAgentList.add("Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.1) Gecko/2008092215 Firefox/3.0.1 Orca/1.1 beta 3");
		userAgentList.add("Mozilla/5.0 (X11; U; Linux i686; de-AT; rv:1.8.0.2) Gecko/20060309 SeaMonkey/1.0");
		userAgentList.add("Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.0.1) Gecko/20021219 Chimera/0.6");
		userAgentList.add("Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.0.1) Gecko/20030306 Camino/0.7");

		if(index < 0)
			return userAgentList.get(new Random().nextInt(userAgentList.size()));
		
		if(index >= userAgentList.size())
			return null;
		
		return userAgentList.get(index);
	}
	
	/*
	public static void main(String[] args) {
		try {
			String url = "http://localhost:8080/CohesionServlet2/login.jsp?token=&amp;b&c=&d";
			String res = getPOSTRedirectPage(url);
			System.out.println(res);
			//ArrayList<String[]> params= new ArrayList<String[]>();
			//params.add(new String[]{"User-Agent",getUserAgent(5)});
			//System.out.println(removeAllHTMLTag("<div>asd</div><Br/>aaa<textarea ss>ad</textarea>jj<ddd>"));
			//System.out.println(removeAllHTMLTag(new String(sendHTTPGET("http://stackoverflow.com/questions/704319/how-the-substring-function-of-string-class-works",params,false,false))));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	*/
}
