package saml

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// cookieName Defines SAML token cookie name.
const cookieName = "SAMLToken"
const fileSchema = "file"

type SAMLService struct {
	samls  map[string]*samlsp.Middleware
	config *ServiceConfig
}

type SAMLProvider struct {
	Name    string
	Handler *samlsp.Middleware
}

func NewSAMLService(config *ServiceConfig) (*SAMLService, error) {
	srv := &SAMLService{
		config: config,
		samls:  make(map[string]*samlsp.Middleware),
	}

	for _, samlProvider := range config.Providers {
		if _, found := srv.samls[samlProvider.Name]; found {
			return nil, fmt.Errorf("%w with name '%s'", ErrDuplicateIDPProvider, samlProvider.Name)
		}
		samlSP, err := createIDP(samlProvider, config)
		if err != nil {
			return nil, fmt.Errorf("%w with name '%s': %w", ErrProviderRegistrationFailed, samlProvider.Name, err)
		}

		srv.samls[samlProvider.Name] = samlSP

		log.Printf("Created provider '%s'\n", samlProvider.Name)
		log.Println("\tSSO Metadata URL: ", samlSP.ServiceProvider.MetadataURL.String())
		log.Println("\tSSO Acs URL: ", samlSP.ServiceProvider.AcsURL.String())
		log.Println("\tSSO NameID Format: ", samlSP.ServiceProvider.AuthnNameIDFormat)
		if sessionProvider, ok := samlSP.Session.(samlsp.CookieSessionProvider); ok {
			log.Println("\tToken max duration: ", sessionProvider.MaxAge)
		}
	}

	return srv, nil
}

func createIDP(samlProvider providerDTO, config *ServiceConfig) (*samlsp.Middleware, error) {
	idpMetadataURL, err := url.Parse(samlProvider.Metadata)
	if err != nil {
		return nil, fmt.Errorf("invalid url %v: %w", samlProvider.Metadata, err)
	}

	var idpDescriptor *saml.EntityDescriptor
	if idpMetadataURL.Scheme == fileSchema {
		idpDescriptor, err = loadIDPMetadata(idpMetadataURL.Path)
		if err != nil {
			return nil, fmt.Errorf("error loading idp metadata %v: %w", samlProvider.Metadata, err)
		}
	} else {
		idpDescriptor, err = fetchIDPMetadata(idpMetadataURL)
		if err != nil {
			return nil, fmt.Errorf("error fetching idp metadata %v: %w", samlProvider.Metadata, err)
		}
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

func loadIDPMetadata(metadataPath string) (*saml.EntityDescriptor, error) {
	log.Println("Loading metadata from file ", metadataPath)
	data, err := readFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("error reading metadata file %s: %w", metadataPath, err)
	}

	metadata, err := samlsp.ParseMetadata(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing metadata file %s: %w", metadataPath, err)
	}
	return metadata, nil
}

func readFile(metadataPath string) ([]byte, error) {
	file, err := os.Open(metadataPath)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	return io.ReadAll(file)
}

func (s *SAMLService) GetProviders() []*SAMLProvider {
	result := make([]*SAMLProvider, 0, len(s.samls))
	for name, samlSP := range s.samls {
		result = append(result, &SAMLProvider{
			Name:    name,
			Handler: samlSP,
		})
	}

	return result
}
