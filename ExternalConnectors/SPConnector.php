/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */

class SPConnector {
    private $centralizedSPUrl = null;
    private $serviceLogoutUrl = null;
    private $serviceLoginUrl = null;
    private $authenticationMethodList = null;

    function __construct($centralizedSPUrl, $serviceLoginUrl, $serviceLogoutUrl, $authenticationMethodList){
        $this->serviceLogoutUrl = $serviceLogoutUrl;
        $this->serviceLoginUrl = $serviceLoginUrl;
        $this->authenticationMethodList = $authenticationMethodList;
        $this->centralizedSPUrl = $centralizedSPUrl;
        
        SPConnector::initializeSession();
    }

    public function login(){
        if(!isset($this->serviceLogoutUrl))
            throw new Exception("ERROR: service Logout Url not defined");
        if(!isset($this->centralizedSPUrl))
            throw new Exception("ERROR: centralized SP Url not defined");
        
        if(!isset($_REQUEST['xmlAttrib'])){
            $serviceUrl = ((@$_SERVER['HTTPS'] == "on") ? "https://" : "http://").$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'];

            $auth = "<auth><serviceURL>".$serviceUrl."</serviceURL><logoutURL>".$this->serviceLogoutUrl."</logoutURL>";
            if(isset($authenticationMethodList)){
                $auth .= "<authnContextList>";
                foreach($this->authenticationMethodList as $authenticationMethod)
                    $auth .= "<authnContext>".$authenticationMethod."</authnContext>";
                $auth .= "</authnContextList>";
            }
            $auth .= "</auth>";

            $authB64 = base64_encode($auth);
            
            header("Location: ".$this->centralizedSPUrl."/PoA?xmlAuth=".urlencode($authB64));
        } else {
            $userAttributes = base64_decode($_REQUEST['xmlAttrib']);

            $_SESSION['userAttributes'] = $userAttributes;
            
            if(isset($_REQUEST["ReturnUrl"]))
                header("Location: ".$_REQUEST["ReturnUrl"]);
        }
    }

    public function logout(){
        if(isset($_REQUEST['remoteLogout'])){
            $_SESSION['userAttributes'] = null;
        } else {
            if(isset($_REQUEST["ReturnUrl"]))
                header("Location: ".$_REQUEST["ReturnUrl"]);
        }
    }

    public function getLogoutUrl(){
        return $this->centralizedSPUrl."/LOGOUT?ReturnUrl=".urlencode($this->serviceLogoutUrl);
    }
    
    public function protectPage(){
        if(!isset($_SESSION['userAttributes'])){
            $rawUrl = ((@$_SERVER['HTTPS'] == "on") ? "https://" : "http://").$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'];
            $url = $this->serviceLoginUrl."?ReturnUrl=".urlencode($rawUrl);
            header("Location: ".$url);
        }
    }
    
    private static function initializeSession(){
        if(version_compare(PHP_VERSION,'5.4.0')>=0){
            if(session_status() == PHP_SESSION_NONE)
                session_start();
        }
        else{
            if(session_id() == '')
                session_start();
        }
    }
}