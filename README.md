## Simple SAML authentication service ##

Certificates required can be generated 
```
openssl req -x509 -newkey rsa:2048 -keyout myservice.key -out myservice.cert -days 365 -nodes -subj "/CN=myservice.example.com"
```

ENVs for docker container:
- CERT - string with client CA certificate - `awk 1 ORS='\\n' myservice.cert`
- KEY  - string with private key - `awk 1 ORS='\\n' myservice.key`
- PORT - Port on which service listens, default 8000
- DOMAIN - URL under which service handles requests, default 'http://localhost', must include PATH_PREFIX at the end
- PATH_PREFIX - Path prefix which should be added to base if it runs under, default '' ( example for portal `/sso` )
- COOKIE_DOMAIN - For which domain the cookies are set (can be wider than DOMAIN), default 'localhost'
- TOKEN_MAX_AGE - Duration of final JWT token - default 5 minutes. input as [Golang time.Duration](https://golang.org/pkg/time/#ParseDuration)
- DEBUG - set to 1 to enable the test endpoint, default 0

Urls:
- **/test** - Requires SAML authentication and outputs resulting Claims (Only available if DEBUG=1)
- **/auth?return=&lt;returnUrl&gt;** - Performs SAML authentication, stores result in JWT token with name **`SAMLtoken`** and redirects user back to **`returnUrl`**

**adfs.neon** file contains configuration of allowed IDPs to authorize.
Metadata can be fetched from public metadata url or provided as a local file to the service.

Before using:
- Generate certificates
- Update adfs.neon file with correct values of allowed SAML IDPs
- Optionally uncomment line in Dockerfile to build metadata files directly into the image
