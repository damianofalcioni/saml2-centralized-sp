/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.servlet.test;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TestProtected extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try {
		    String url = request.getRequestURL().toString().substring(0, request.getRequestURL().toString().lastIndexOf("/"));
			String centralizedUrl = url;
			String serviceLoginUrl = url+"/TestLogin";
			String serviceLogoutUrl = url+"/TestLogout";
			SPConnector spc = new SPConnector(centralizedUrl, serviceLoginUrl, serviceLogoutUrl, null);
			
			spc.protectPage(request, response);
			
			//response.getWriter().println("CIAO, SEI NELLA PAGINA PROTETTA");
			response.getWriter().println(request.getSession().getAttribute("userAttributes"));
			response.getWriter().println("<a href=\""+spc.getLogoutUrl()+"\">logout</a>");
		} catch (Exception e) {
			e.printStackTrace();
			throw new ServletException(e);
		}
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
	}

}
