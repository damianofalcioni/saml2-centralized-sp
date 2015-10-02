/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.servlet;

import it.unicam.cs.saml.SAML2;
import it.unicam.cs.saml.SAML2.ServiceSessionInfo;
import it.unicam.cs.saml.SAML2.idpInfo;
import it.unicam.cs.sp.config.Configuration;
import it.unicam.cs.utils.NETUtils;
import it.unicam.cs.utils.Utils;
import it.unicam.cs.utils.Utils.LogType;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class WAYF extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private Configuration cfg;
	
	public void init(ServletConfig config) throws ServletException {
		try{
			cfg = new Configuration(config.getServletContext().getInitParameter("configFile"));
		}catch(Exception ex){Utils.log(ex.getMessage(), cfg, LogType.general);throw new ServletException(ex);}
	}


	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		java.io.PrintWriter out = response.getWriter();

		try{
			
			if(request.getParameter("op")!= null && request.getParameter("op").equals("getIdPList")){
				String returnList = "";
				String spEntityId = request.getParameter("spEntityId");
				
				String[] fedIdList = new String[0];
				if(spEntityId!=null && !spEntityId.isEmpty()){
					String[] fedURLList = SAML2.saml_getUsableFederations(spEntityId, cfg.getAllFederationMetadataURI());
					fedIdList = new String[fedURLList.length];
					for(int i=0;i<fedURLList.length;i++)
						fedIdList[i] = cfg.getFederationId(fedURLList[i]);
				
					String currentRelyState = (String)request.getSession().getAttribute("currentRelyState");
					if(currentRelyState!=null && !currentRelyState.isEmpty()){
						ServiceSessionInfo ssi = (ServiceSessionInfo)request.getSession().getAttribute(currentRelyState);
						if(ssi!=null){
							String host = NETUtils.getHost(ssi.serviceURL);
							int hostId = cfg.isHostAllowed(host);
							if(hostId == -1)
								throw new Exception("ERROR: Host " + host + " is not allowed");
							fedIdList = cfg.getFederationEnabled(hostId);
						}
					}
				}
				for(String fedId:fedIdList){
					idpInfo[] idpInfoList = SAML2.wayf_getAllIdpInfo(cfg.getLocalFederationMetadataURI(fedId));
					for(idpInfo idpInfo:idpInfoList)
						returnList += "\n"+fedId+","+idpInfo.id+","+((idpInfo.nameList.length!=0)?idpInfo.nameList[0]:idpInfo.id)+","+((idpInfo.imgUrlList.length!=0)?idpInfo.imgUrlList[0]:"");
				}
				out.print("OK"+returnList);
				return;
			}
			
			if(request.getParameter("op")!= null && request.getParameter("op").equals("getWAYFList")){
				String returnList = "";
				
				String spEntityId = request.getParameter("spEntityId");
				
				String[] fedIdList = new String[0];
				if(spEntityId!=null && !spEntityId.isEmpty()){
					String[] fedURLList = SAML2.saml_getUsableFederations(spEntityId, cfg.getAllFederationMetadataURI());
					fedIdList = new String[fedURLList.length];
					for(int i=0;i<fedURLList.length;i++)
						fedIdList[i] = cfg.getFederationId(fedURLList[i]);
				
					String currentRelyState = (String)request.getSession().getAttribute("currentRelyState");
					if(currentRelyState!=null && !currentRelyState.isEmpty()){
						ServiceSessionInfo ssi = (ServiceSessionInfo)request.getSession().getAttribute(currentRelyState);
						String host = NETUtils.getHost(ssi.serviceURL);
						int hostId = cfg.isHostAllowed(host);
						if(hostId == -1)
							throw new Exception("ERROR: Host " + host + " is not allowed");
						fedIdList = cfg.getFederationEnabled(hostId);
					}
				}
				for(String fedId:fedIdList)
					returnList += "\n"+fedId+","+fedId+",,,"; //TODO Ritornare un icona: salvarla o nel metadata della federazione o nel file di config
				
				out.print("OK"+returnList);
				return;
			}
			
			if(request.getParameter("ListSelect")!= null){
				String loadIdP = request.getParameter("loadIdP");
				String id = request.getParameter("ListSelect");
				String isPassive = request.getParameter("isPassive");
				
				if(loadIdP.equals("false")){
					String url = cfg.getFederationWAYFURI(id);
					String spEntityId = SAML2.saml_getEntityIDFromSingleMetadata(cfg.getSpMetadataPath());
					String returnUrl = SAML2.saml_getDiscoveryReturnUrl(spEntityId, null, cfg.getLocalFederationMetadataURI(id));
					response.sendRedirect(url+"?entityID="+URLEncoder.encode(spEntityId, "UTF-8")+"&return="+URLEncoder.encode(returnUrl, "UTF-8")+"&isPassive="+URLEncoder.encode(isPassive, "UTF-8"));
					return;
				} else {
				
					if(request.getParameter("spEntityId")!=null && !request.getParameter("spEntityId").isEmpty()){
						String spEntityId = request.getParameter("spEntityId");
						String spReturnUrl = request.getParameter("spReturnUrl").isEmpty()?null:request.getParameter("spReturnUrl");
						String spReturnParamName = request.getParameter("spReturnParamName").isEmpty()?"entityID":request.getParameter("spReturnParamName");
						spReturnUrl = SAML2.saml_getDiscoveryReturnUrl(spEntityId, spReturnUrl, SAML2.saml_chooseFederationToUse(spEntityId, cfg.getAllFederationMetadataURI())); 
						response.sendRedirect(spReturnUrl+"?"+spReturnParamName+"="+URLEncoder.encode(id, "UTF-8"));
						return;
					} else {
						//caso in cui sono arrivato alla pagina senza passare alcun parametro.
						response.sendRedirect("./wayf.jsp");
					}
				}

			}
			
		}catch(Exception ex){
			out.print("KO\n" + ex.getMessage());
			Utils.log(ex.getMessage(), cfg, LogType.general);
		}
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

}
