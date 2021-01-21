package main

import (
	"fmt"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"net/url"
	"path"
)

func main() {
	viper.AutomaticEnv()
	viper.SetDefault("DOMAIN", "http://localhost")
	viper.SetDefault("COOKIE_DOMAIN", "localhost")
	viper.SetDefault("PATH_PREFIX", "")
	viper.SetDefault("PORT", "8000")
	viper.SetDefault("TOKEN_MAX_AGE", "5m")

	prefix := ensureAbsolute(viper.GetString("PATH_PREFIX"))
	log.Println("Path prefix: ", prefix)

	samlProviders, err := configureSaml("adfs.neon")
	if err != nil {
		fmt.Println("Error reading configuration")
		panic(err)
	}

	for name, samlSP := range samlProviders.samls {
		samlPrefix := path.Join(prefix, url.PathEscape(name))
		log.Println("Registering ", name, " to ", samlPrefix)
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

func ensureAbsolute(path string) string {
	if path[0] == '/' {
		return path
	}
	return "/" + path
}
