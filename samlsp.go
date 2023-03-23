package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

func createSAMLService(config *ServiceConfig) (*SAMLService, error) {
	srv := &SAMLService{
		samls: make(map[string]*samlsp.Middleware),
	}

	for _, samlProvider := range config.Providers {
		if _, found := srv.samls[samlProvider.Name]; found {
			return nil, fmt.Errorf("%w with name '%s'", ErrDuplicateIDPProvider, samlProvider.Name)
		}
		samlSP, err := createIDP(samlProvider, config)
		if err != nil {
			return nil, fmt.Errorf("%w with name '%s'", ErrProviderRegistrationFailed, samlProvider.Name)
		}

		srv.samls[samlProvider.Name] = samlSP

		log.Printf("Added provider '%s'\n", samlProvider.Name)
		log.Println("\tSSO Metadata URL: ", samlSP.ServiceProvider.MetadataURL.String())
		log.Println("\tSSO Acs URL: ", samlSP.ServiceProvider.AcsURL.String())
		log.Println("\tSSO NameID Format: ", samlSP.ServiceProvider.AuthnNameIDFormat)
		if sessionProvider, ok := samlSP.Session.(samlsp.CookieSessionProvider); ok {
			log.Println("\tToken max duration: ", sessionProvider.MaxAge)
		}
	}

	return srv, nil
}

func createIDP(samlProvider provider, config *ServiceConfig) (*samlsp.Middleware, error) {
	idpMetadataURL, err := url.Parse(samlProvider.Metadata)
	if err != nil {
		return nil, fmt.Errorf("invalid url %v: %w", samlProvider.Metadata, err)
	}

	idpDescriptor, err := fetchIDPMetadata(idpMetadataURL)
	if err != nil {
		return nil, fmt.Errorf("error fetching idp metadata %v: %w", samlProvider.Metadata, err)
	}

	samlURL, err := config.RootURL.Parse(path.Join(config.RootURL.Path, url.PathEscape(samlProvider.Name)) + "/")
	if err != nil {
		return nil, fmt.Errorf("invalid saml url %s: %w", samlProvider.Name, err)
	}

	opts := samlsp.Options{
		URL:         *samlURL,
		Key:         config.Certificate.rsaPrivateKey,
		Certificate: config.Certificate.keyPair.Leaf,
		IDPMetadata: idpDescriptor,
	}
	samlSP, err := samlsp.New(opts)
	if samlSP == nil || err != nil {
		return nil, fmt.Errorf("%w with name '%s'", ErrProviderRegistrationFailed, samlProvider.Name)
	}

	samlSP.Session = samlsp.CookieSessionProvider{
		Name:     cookieName,
		Domain:   samlURL.Host,
		MaxAge:   config.CookieMaxDuration,
		HTTPOnly: true,
		Secure:   true,
		SameSite: http.SameSiteDefaultMode,
		Codec:    samlsp.DefaultSessionCodec(opts),
	}

	// set NameID format
	samlSP.ServiceProvider.AuthnNameIDFormat = samlProvider.NameIDFormat

	return samlSP, nil
}

func fetchIDPMetadata(metadataURL *url.URL) (*saml.EntityDescriptor, error) {
	if metadataURL == nil {
		return nil, ErrEmptyMetadataURL
	}

	httpClient := http.DefaultClient
	ctx, cancel := context.WithTimeout(context.Background(), metadataFetchTimeout)
	defer cancel()

	metadata, err := samlsp.FetchMetadata(ctx, httpClient, *metadataURL)
	if err != nil {
		return nil, err
	}
	return metadata, nil
}
