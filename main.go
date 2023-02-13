package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/spf13/viper"
)

// IdpCookieName defines cookie name for used SAML Ident. Provider
const IdpCookieName = "SAML_IDP"

// ReturnURLKey Defines parameter name that has return url after SAML auth
const ReturnURLKey = "return"

// cookieName Defines SAML token cookie name
const cookieName = "SAMLToken"

func main() {
	viper.AutomaticEnv()
	viper.SetDefault("DOMAIN", "http://localhost:8000")
	viper.SetDefault("COOKIE_DOMAIN", "localhost")
	viper.SetDefault("PATH_PREFIX", "")
	viper.SetDefault("PORT", "8000")
	viper.SetDefault("TOKEN_MAX_AGE", "5m")
	viper.SetDefault("DEBUG", "0")

	prefix := ensureAbsolute(viper.GetString("PATH_PREFIX"))
	log.Println("Path prefix: ", prefix)

	cookieDomain := viper.GetString("COOKIE_DOMAIN")
	maxDuration, err := time.ParseDuration(viper.GetString("TOKEN_MAX_AGE"))
	if err != nil {
		panic(fmt.Errorf("missing or invalid TOKEN_MAX_AGE environment variable, %w", err))
	}

	debug := viper.GetBool("DEBUG")
	setupHttpHandlers(cookieDomain, maxDuration, prefix, debug)
	var server *http.Server

	termChan := make(chan bool, 1) // For signalling termination from main to go-routine
	// Start server
	go func() {
		addr := ":" + viper.GetString("PORT")
		log.Println("Listening on port", addr)

		server = &http.Server{Addr: addr, Handler: nil}
		err = server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Println("error starting server")
			panic(err)
		}

		termChan <- true
	}()

	// Wait for interrupt signal to gracefully shutdown the app
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		log.Println("signal to shutdown received")
	case <-termChan:
		log.Println("application terminated")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Println("error shutting down app ", err)
	}

	log.Println("bye")
}

func setupHttpHandlers(cookieDomain string, maxDuration time.Duration, prefix string, enableDebug bool) {
	samlProviders, err := configureSaml("adfs.neon", cookieDomain, maxDuration)
	if err != nil {
		log.Println("Error reading configuration")
		panic(err)
	}

	for name, samlSP := range samlProviders.samls {
		samlPrefix := path.Join(prefix, url.PathEscape(name))
		log.Println("Registering ", name, " to ", samlPrefix)
		if enableDebug {
			http.Handle(samlPrefix+"/test", samlSP.RequireAccount(http.HandlerFunc(testAuth)))
		}
		http.Handle(samlPrefix+"/auth", samlSP.RequireAccount(http.HandlerFunc(returnIDPAfterAuth(name, cookieDomain, maxDuration))))
		http.Handle(samlPrefix+"/saml/", samlSP)
	}
}

// Shutdown

func ensureAbsolute(path string) string {
	if len(path) == 0 {
		return "/"
	}

	if path[0] == '/' {
		return path
	}

	return "/" + path
}
