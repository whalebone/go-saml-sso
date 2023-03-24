package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/spf13/viper"
	apphttp "github.com/whalebone/go-saml-sso/http"
	"github.com/whalebone/go-saml-sso/saml"
)

const serverReadTimeout = 20 * time.Second

func main() {
	config, err := saml.NewSAMLConfig()
	if err != nil {
		panic(err)
	}

	routerGeneratorFc := routerGenerator(config)
	router, err := routerGeneratorFc()
	if err != nil {
		panic(err)
	}

	mainHandler := apphttp.NewRouterSwapper(router)
	var server *http.Server

	termChan := make(chan struct{}, 1) // For signalling termination from main to go-routine

	// start periodic refresh of metadata and handlers
	go mainHandler.PeriodicRefresh(config.RefreshInterval, termChan, routerGeneratorFc)

	// Start server
	go func() {
		addr := ":" + viper.GetString("PORT")
		log.Println("Listening on port", addr)

		server = &http.Server{
			ReadHeaderTimeout: serverReadTimeout,
			ReadTimeout:       serverReadTimeout,
			Addr:              addr,
			Handler:           mainHandler,
		}
		err = server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Println("server error", err)
		}

		close(termChan)
	}()

	// Wait for interrupt signal to gracefully shut down the app
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

func routerGenerator(config *saml.ServiceConfig) apphttp.RouterGeneratorFc {
	return func() (*http.ServeMux, error) {
		samlSvc, err := saml.NewSAMLService(config)
		if err != nil {
			return nil, err
		}

		mux := http.NewServeMux()
		for _, provider := range samlSvc.GetProviders() {
			samlPrefix := path.Join(config.RoutePathPrefix, url.PathEscape(provider.Name))
			log.Println("Registering ", provider.Name, " to ", samlPrefix)
			if config.Debug {
				mux.Handle(samlPrefix+"/test", provider.Handler.RequireAccount(http.HandlerFunc(apphttp.TestAuth)))
			}
			mux.Handle(samlPrefix+"/auth", provider.Handler.RequireAccount(http.HandlerFunc(apphttp.ReturnIDPAfterAuth(provider.Name, config.CookieDomain, config.CookieMaxDuration))))
			mux.Handle(samlPrefix+"/saml/", provider.Handler)
		}

		return mux, nil
	}
}
