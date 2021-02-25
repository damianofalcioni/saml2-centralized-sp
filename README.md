SAML2 Centralized Service Provider
====================

## Summary
This component is a lightweight and easy to extend Java SAML2 Service Provider specific for a cloud environment. 
The component act like a proxy that give each protected service the capability to talk SAML2 Standard. 
The service only need to integrate the SPConnector (a library provided in different programming languages) in order to communicate with the Centralized Service Provider that will redirect the user to one of the available IdP.

## Functionalities
- Full compliant with the Italian Spid guidelines
- Support for the AgiD registry
- Perform automatic queries to AAs in order to obtain missing attributes
- Support SingleSignOn and SingleLogout 

## Configuration
Edit the web.xml in order to point the parameter 'configFile' to the right configuration file.
Edit the configuration file in order to point to the right paths.

## Support Me <3
[![Buy me a coffee](https://user-images.githubusercontent.com/8982949/109154904-3ccbda80-776f-11eb-8d98-73de102e2e4f.png)](https://www.paypal.me/damianofalcioni/0.99)
