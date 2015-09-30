/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

public class SPConnector
{
    private string centralizedSPUrl = null;
    private string serviceLogoutUrl = null;
    private string serviceLoginUrl = null;
    private string[] authenticationMethodList = null;

    public SPConnector(string centralizedSPUrl, string serviceLoginUrl, string serviceLogoutUrl, string[] authenticationMethodList){
        this.serviceLogoutUrl = serviceLogoutUrl;
        this.serviceLoginUrl = serviceLoginUrl;
        this.authenticationMethodList = authenticationMethodList;
        this.centralizedSPUrl = centralizedSPUrl;
    }

    public void login(HttpRequest request, HttpResponse response, System.Web.SessionState.HttpSessionState session){
        if(String.IsNullOrEmpty(serviceLogoutUrl))
            throw new Exception("ERROR: service Logout Url not defined");
        if(String.IsNullOrEmpty(centralizedSPUrl))
            throw new Exception("ERROR: centralized SP Url not defined");
        
        if(String.IsNullOrEmpty(request.Params["xmlAttrib"])){
            string serviceUrl = request.RawUrl;

            string auth = "<auth><serviceURL>"+serviceUrl+"</serviceURL><logoutURL>"+serviceLogoutUrl+"</logoutURL>";
            if(!String.IsNullOrEmpty(authenticationMethodList)){
                auth += "<authnContextList>";
                foreach(string authenticationMethod in authenticationMethodList)
                    auth += "<authnContext>"+authenticationMethod+"</authnContext>";
                auth += "</authnContextList>";
            }
            auth += "</auth>";

            string authB64 = Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes(auth));
            
            response.Redirect(centralizedSPUrl+"/PoA?xmlAuth="+System.Web.HttpUtility.UrlEncode(authB64));
        } else {
            string userAttributes = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(request.Params["xmlAttrib"]));

            session["userAttributes"] = userAttributes;
            
            if(!String.IsNullOrEmpty(request.Params["ReturnUrl"]))
                response.Redirect(request.Params["ReturnUrl"]);
        }
    }

    public void logout(bool invalidateSession, HttpRequest request, HttpResponse response, System.Web.SessionState.HttpSessionState session){
        
        if(!String.IsNullOrEmpty(request.Params["remoteLogout"])){
            session["userAttributes"] = null;
            if(invalidateSession) {
                System.Web.Security.FormsAuthentication.SignOut();
                session.Abandon();
                session.Clear();
            }
        } else {
            if(!String.IsNullOrEmpty(request.Params["ReturnUrl"]))
                response.Redirect(request.Params["ReturnUrl"]);
        }
    }

    public string getLogoutUrl(){
        return centralizedSPUrl+"/LOGOUT?ReturnUrl="+System.Web.HttpUtility.UrlEncode(serviceLogoutUrl);
    }
    
    public void protectPage(HttpRequest request, HttpResponse response, System.Web.SessionState.HttpSessionState session){
        if(String.IsNullOrEmpty(session["userAttributes"])){
            string url = serviceLoginUrl+"?ReturnUrl="+System.Web.HttpUtility.UrlEncode(request.RawUrl);
            response.Redirect(url);
        }
    }
}