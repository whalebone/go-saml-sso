package http

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml/samlsp"
)

// IdpCookieName defines cookie name for used SAML Ident. Provider.
const IdpCookieName = "SAML_IDP"

// ReturnURLKey Defines parameter name that has return url after SAML auth.
const ReturnURLKey = "return"

func TestAuth(w http.ResponseWriter, r *http.Request) {
	_, err := fmt.Fprintln(w, "<html><body>")
	if err != nil {
		return
	}

	genericSession := samlsp.SessionFromContext(r.Context())
	jwtSession, ok := genericSession.(samlsp.JWTSessionClaims)
	if !ok {
		_, _ = fmt.Fprintf(w, "<p>Invalid claims obtained from context</p></body></html>")
		return
	}

	name := jwtSession.Attributes.Get("sub")
	if name != "" {
		_, _ = fmt.Fprintf(w, "<p>Hello, %s!</p>", name)
	}

	jsonData, err := json.MarshalIndent(jwtSession, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(w, "<pre>Error getting attributes: %s</pre>", err)
	} else {
		_, _ = fmt.Fprintf(w, "<pre>Attrs:\n %s\n</pre>", jsonData)
	}

	_, _ = fmt.Fprintln(w, "</body></html>")
}

func ReturnIDPAfterAuth(idpName string, cookieDomain string, cookieMaxAge time.Duration) func(w http.ResponseWriter, r *http.Request) {
	maxAgeSeconds := int(cookieMaxAge / time.Second)
	return func(w http.ResponseWriter, r *http.Request) {
		returnURL, err := url.Parse(r.URL.Query().Get(ReturnURLKey))
		if err != nil || returnURL.String() == "" {
			http.Error(w, "invalid return url", http.StatusBadRequest)
			return
		}

		cookie := &http.Cookie{
			Name:     IdpCookieName,
			Value:    idpName,
			Domain:   cookieDomain,
			MaxAge:   maxAgeSeconds,
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
		}

		log.Println("Returning after login in '", idpName, "' to ", returnURL.String())

		http.SetCookie(w, cookie)
		w.Header().Add("Location", returnURL.String())
		w.WriteHeader(http.StatusFound)
	}
}
