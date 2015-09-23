/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.servlet.test;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TestLogout extends HttpServlet {
	private static final long serialVersionUID = 1L;
       

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String url = request.getRequestURL().toString().substring(0, request.getRequestURL().toString().lastIndexOf("/"));
        String centralizedUrl = url;
        String serviceLoginUrl = url+"/TestLogin";
        String serviceLogoutUrl = url+"/TestLogout";
		SPConnector spc = new SPConnector(centralizedUrl, serviceLoginUrl, serviceLogoutUrl, null);
		try {
			spc.logout(false, request, response);
		} catch (Exception e) {
			e.printStackTrace();
			throw new ServletException(e);
		}
		/*if(request.getParameter("remoteLogout")!=null){
			request.getSession().removeAttribute("attrib");
			return;
		}
		
		response.sendRedirect("./TestLogin");
		*/
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

}
