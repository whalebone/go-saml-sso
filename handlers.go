package main

import (
	"encoding/json"
	"fmt"
	"github.com/crewjam/saml/samlsp"
	"net/http"
	"net/url"
)

const cookieName = "SAMLToken"

func test(w http.ResponseWriter, r *http.Request) {
	_, err := fmt.Fprintln(w, "<html><body>")
	if err != nil {
		return
	}

	genericSession := samlsp.SessionFromContext(r.Context())
	jwtSession := genericSession.(samlsp.JWTSessionClaims)

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

func returnAfterAuth(w http.ResponseWriter, r *http.Request) {
	returnURL, err := url.Parse(r.URL.Query().Get("return"))
	if err != nil || returnURL.String() == "" {
		http.Error(w, "invalid return url", http.StatusBadRequest)
		return
	}

	w.Header().Add("Location", returnURL.String())
	w.WriteHeader(http.StatusFound)
}
