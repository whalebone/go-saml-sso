## Simple SAML authentication service ##

Certificates required can be generated 
```
openssl req -x509 -newkey rsa:2048 -keyout myservice.key -out myservice.cert -days 365 -nodes -subj "/CN=myservice.example.com"
```

ENVs for docker container:
- CERT - string with client CA certificate - `awk 1 ORS='\\n' myservice.cert`
- KEY  - string with private key - `awk 1 ORS='\\n' myservice.key`
- PORT - Port on which service listens, default 8000
- DOMAIN - URL under which service handles requests, default 'http://localhost'
- PATH_PREFIX - Path prefix which should be added to base if it runs under, default '' ( example for portal `/sso` )
- TOKEN_MAX_AGE - Duration of final JWT token - default 10 hours. input as [Golang time.Duration](https://golang.org/pkg/time/#ParseDuration)
- IDP_META_URL - URL of identity provider metadata XML file

Urls:
- **/test** - Requires SAML authentication and outputs resulting Claims
- **/auth?return=&lt;returnUrl&gt;** - Performs SAML authentication, stores result in JWT token with name **`SAMLtoken`** and redirects user back to **`returnUrl`**
