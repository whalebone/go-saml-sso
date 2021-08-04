package main

import (
	"fmt"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"net/url"
	"path"
)

// IdpCookieName defines cookie name for used SAML Ident. Provider
const IdpCookieName = "SAML_IDP"

// ReturnURLKey Defines parameter name that has return url after SAML auth
const ReturnURLKey = "return"

// cookieName Defines SAML token cookie name
const cookieName = "SAMLToken"

func main() {
	viper.AutomaticEnv()
	viper.SetDefault("DOMAIN", "http://localhost")
	viper.SetDefault("COOKIE_DOMAIN", "localhost")
	viper.SetDefault("PATH_PREFIX", "")
	viper.SetDefault("PORT", "8000")
	viper.SetDefault("TOKEN_MAX_AGE", "5m")

	prefix := ensureAbsolute(viper.GetString("PATH_PREFIX"))
	log.Println("Path prefix: ", prefix)

	cookieDomain := viper.GetString("COOKIE_DOMAIN")

	samlProviders, err := configureSaml("adfs.neon", cookieDomain)
	if err != nil {
		fmt.Println("Error reading configuration")
		panic(err)
	}

	for name, samlSP := range samlProviders.samls {
		samlPrefix := path.Join(prefix, url.PathEscape(name))
		log.Println("Registering ", name, " to ", samlPrefix)
		// http.Handle(samlPrefix+"/test", samlSP.RequireAccount(http.HandlerFunc(testAuth)))
		http.Handle(samlPrefix+"/auth", samlSP.RequireAccount(http.HandlerFunc(returnIDPAfterAuth(name, cookieDomain))))
		http.Handle(samlPrefix+"/saml/", samlSP)
	}

	fmt.Println("Listening on port: ", viper.GetString("PORT"))
	err = http.ListenAndServe(":"+viper.GetString("PORT"), nil)
	if err != nil {
		panic(err)
	}
}

func ensureAbsolute(path string) string {
	if path[0] == '/' {
		return path
	}
	return "/" + path
}
