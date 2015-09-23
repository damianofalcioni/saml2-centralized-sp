/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.servlet.test;


import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TestLogin extends HttpServlet {
	private static final long serialVersionUID = 1L;
       

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String url = request.getRequestURL().toString().substring(0, request.getRequestURL().toString().lastIndexOf("/"));
        String centralizedUrl = url;
        String serviceLoginUrl = url+"/TestLogin";
        String serviceLogoutUrl = url+"/TestLogout";
		SPConnector spc = new SPConnector(centralizedUrl, serviceLoginUrl, serviceLogoutUrl, null);
		try {
			spc.login(request, response);
		} catch (Exception e) {
			throw new ServletException(e);
		}
		
		/*
		String url = "http://localhost:8080/SAML2CentralizedSP/TestLogin?ReturnUrl="+URLEncoder.encode("http://www.google.it", "UTF-8");
		String urlLogout = "http://localhost:8080/SAML2CentralizedSP/TestLogout?ReturnUrl="+URLEncoder.encode("http://www.google.it", "UTF-8");
		
		if(request.getParameter("xmlAttrib")==null){
			
			String auth = "<auth><serviceURL>"+url+"</serviceURL><logoutURL>"+urlLogout+"</logoutURL></auth>";
			String authB64 = Base64Fast.encodeToString(auth.getBytes(), false);
			response.getWriter().println("<a href=\"./PoA?xmlAuth="+URLEncoder.encode(authB64,"UTF-8")+"\">login</a>");
			
		} else {
			String attrib = new String(Base64Fast.decode(request.getParameter("xmlAttrib")));
			request.getSession().setAttribute("attrib", attrib);
		}
		
		if(request.getSession().getAttribute("attrib")!=null){
			response.getWriter().println(request.getSession().getAttribute("attrib"));
			response.getWriter().println("<a href=\"./LOGOUT?ReturnUrl="+URLEncoder.encode(urlLogout,"UTF-8")+"\">logout</a>");
			return;
		}
		*/
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

}
