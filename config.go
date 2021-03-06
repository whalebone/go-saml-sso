package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type SAMLService struct {
	samls map[string]*samlsp.Middleware
}

type config struct {
	Parameters struct {
		ADFS struct {
			SSO       sso        `yaml:"sso"`
			Providers []provider `yaml:"providers"`
		} `yaml:"adfs"`
	} `yaml:"parameters"`
}

type sso struct {
	Uri         string `yaml:"uri"`
	ReturnParam string `yaml:"returnParam"`
	IdpParam    string `yaml:"idpParam"`
}

type provider struct {
	Name         string            `yaml:"name"`
	Metadata     string            `yaml:"metadata"`
	NameIDFormat saml.NameIDFormat `yaml:"nameid_format"`
	//CustomerID string   `yaml:"customer_id"`
	//RolesKey   string   `yaml:"roles_key"`
	//Domains    []string `yaml:"domains"`
}

func (p *provider) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawProvider provider
	raw := rawProvider{ // defaults
		NameIDFormat: saml.UnspecifiedNameIDFormat,
	}
	if err := unmarshal(&raw); err != nil {
		return err
	}

	*p = provider(raw)
	return nil
}

func readCert(key string) []byte {
	certHandler := strings.NewReplacer("\\n", "\n")
	return []byte(certHandler.Replace(viper.GetString(key)))
}

func fetchIDPMetadata(IDPMetadataURL *url.URL) (*saml.EntityDescriptor, error) {
	if IDPMetadataURL == nil {
		return nil, fmt.Errorf("must provide non null metadata URL")
	}
	httpClient := http.DefaultClient
	metadata, err := samlsp.FetchMetadata(context.Background(), httpClient, *IDPMetadataURL)
	if err != nil {
		return nil, err
	}
	return metadata, nil
}

func configureSaml(file string) (*SAMLService, error) {
	rootURL, err := url.Parse(viper.GetString("DOMAIN"))
	if err != nil {
		return nil, fmt.Errorf("error parsing root domain, %w", err)
	}

	cookieDomain := viper.GetString("COOKIE_DOMAIN")

	keyPair, err := tls.X509KeyPair(readCert("CERT"), readCert("KEY"))
	if err != nil {
		return nil, fmt.Errorf("missing or invalid CERT and KEY environment variables, %w", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("missing or invalid CERT and KEY environment variables, %w", err)
	}

	log.Println("Certificate for: ", keyPair.Leaf.Subject.String())

	maxDuration, err := time.ParseDuration(viper.GetString("TOKEN_MAX_AGE"))
	if err != nil {
		return nil, fmt.Errorf("missing or invalid TOKEN_MAX_AGE environment variable, %w", err)
	}

	var config config
	srv := &SAMLService{
		samls: make(map[string]*samlsp.Middleware),
	}

	yamlFile, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", file, err)
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, fmt.Errorf("error parsing file %s: %w", file, err)
	}

	for _, provider := range config.Parameters.ADFS.Providers {
		if _, found := srv.samls[provider.Name]; found {
			return nil, fmt.Errorf("duplicate provider with name '%s'", provider.Name)
		}

		idpMetadataURL, err := url.Parse(provider.Metadata)
		if err != nil {
			return nil, fmt.Errorf("invalid url %v: %w", provider.Metadata, err)
		}

		samlUrl, err := rootURL.Parse(path.Join(rootURL.Path, url.PathEscape(provider.Name)) + "/")
		if err != nil {
			return nil, fmt.Errorf("invalid saml url %s: %w", provider.Name, err)
		}
		fmt.Println(samlUrl.String())

		samlSP, _ := samlsp.New(samlsp.Options{
			URL:            *samlUrl,
			Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
			Certificate:    keyPair.Leaf,
			IDPMetadataURL: idpMetadataURL,
			CookieName:     cookieName,
			CookieSecure:   true,
			CookieDomain:   cookieDomain,
			CookieMaxAge:   maxDuration,
		})
		if samlSP == nil {
			return nil, fmt.Errorf("could not configure provider with name '%s'", provider.Name)
		}

		// set NameID format
		samlSP.ServiceProvider.AuthnNameIDFormat = provider.NameIDFormat

		srv.samls[provider.Name] = samlSP

		log.Printf("Added provider '%s'\n", provider.Name)
		log.Println("\tSSO Metadata URL: ", samlSP.ServiceProvider.MetadataURL.String())
		log.Println("\tSSO Acs URL: ", samlSP.ServiceProvider.AcsURL.String())
		log.Println("\tSSO NameID Format: ", samlSP.ServiceProvider.AuthnNameIDFormat)
		sessionProvider, ok := samlSP.Session.(samlsp.CookieSessionProvider)
		if ok {
			log.Println("\tToken max duration: ", sessionProvider.MaxAge)
		}
	}

	return srv, nil
}
