package it.unicam.cs.sp.servlet;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import it.unicam.cs.saml.SAML2;
import it.unicam.cs.saml.SAML2.ServiceSessionInfo;
import it.unicam.cs.sp.config.Configuration;
import it.unicam.cs.utils.Base64Fast;
import it.unicam.cs.utils.NETUtils;
import it.unicam.cs.utils.Utils;
import it.unicam.cs.utils.Utils.LogType;

public class PoR extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    private Configuration cfg;
    
    public void init(ServletConfig config) throws ServletException {
        try{
            cfg = new Configuration(config.getServletContext().getInitParameter("configFile"));
        }catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
    }
    
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try{
            java.io.PrintWriter out = response.getWriter();
            
            String relayState = request.getParameter("relayState");
            if(relayState==null || relayState=="")
                throw new Exception("ERROR: relayState is null");
            
            ServiceSessionInfo ssi = (ServiceSessionInfo)request.getSession().getAttribute(relayState);
            if(ssi==null)
                throw new Exception("ERROR: Invalid Session State");
            
            String serviceURL = ssi.serviceURL;
            String host = NETUtils.getHost(serviceURL);
            int hostId = cfg.isHostAllowed(host);
            if(hostId == -1)
                throw new Exception("ERROR: Host " + host + " is not allowed");
            
            String xmlAuth = SAML2.sp_generateXML(ssi.attributesObtained);
            String xmlAuthB64 = Base64Fast.encodeToString(xmlAuth.getBytes(), false);
            out.println(NETUtils.getPOSTRedirectPage(serviceURL, "xmlAttrib="+xmlAuthB64));
            
        }catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doGet(request, response);
    }

}
