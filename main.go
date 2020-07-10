package main

import (
	"encoding/json"
	"fmt"
	"github.com/crewjam/saml/samlsp"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"net/url"
)

const cookieName = "SAMLToken"

func test(w http.ResponseWriter, r *http.Request) {
	_, err := fmt.Fprintln(w, "<html><body>")
	if err != nil {
		return
	}
	name := samlsp.Token(r.Context()).Attributes.Get("cn")
	if name != "" {
		_, _ = fmt.Fprintf(w, "<p>Hello, %s!</p>", name)
	}

	jsonData, err := json.MarshalIndent(samlsp.Token(r.Context()), "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(w, "<pre>Attrs:\n %s\n</pre>", jsonData)
	}

	_, _ = fmt.Fprintln(w, "</body></html>")
}

func returnAfterAuth(w http.ResponseWriter, r *http.Request) {
	returnURL, err := url.Parse(r.URL.Query().Get("return"))
	if err != nil {
		http.Error(w, "invalid return url", http.StatusBadRequest)
		return
	}
	cook, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "missing saml cookie", http.StatusBadRequest)
		return
	}

	// add saml value
	q := returnURL.Query()
	q.Add("saml", cook.Value)
	returnURL.RawQuery = q.Encode()

	w.Header().Add("Location", returnURL.String())
	w.WriteHeader(http.StatusFound)
	return
}

func main() {
	viper.AutomaticEnv()
	viper.SetDefault("DOMAIN", "http://localhost")
	viper.SetDefault("PATH_PREFIX", "")
	viper.SetDefault("PORT", "8000")
	viper.SetDefault("TOKEN_MAX_AGE", "10h")

	samlProviders, err := configureSaml("adfs.neon")
	if err != nil {
		fmt.Println("Error reading configuration")
		panic(err)
	}

	prefix := viper.GetString("PATH_PREFIX")
	log.Println("Path prefix: ", prefix)

	for name, samlSP := range samlProviders.samls {
		samlPrefix := prefix+"/"+url.PathEscape(name)
		http.Handle(samlPrefix+"/test", samlSP.RequireAccount(http.HandlerFunc(test)))
		http.Handle(samlPrefix+"/auth", samlSP.RequireAccount(http.HandlerFunc(returnAfterAuth)))
		http.Handle(samlPrefix+"/saml/", samlSP)
	}

	fmt.Println("Listening on port: ", viper.GetString("PORT"))
	err = http.ListenAndServe(":"+viper.GetString("PORT"), nil)
	if err != nil {
		panic(err)
	}
}
