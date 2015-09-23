/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.servlet.test;

import java.net.URLEncoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;


public class SPConnector {

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
}
