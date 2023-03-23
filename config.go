package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

const metadataFetchTimeout = time.Second * 20

type SAMLService struct {
	samls map[string]*samlsp.Middleware
}

type adfsConfig struct {
	Parameters struct {
		ADFS struct {
			SSO       sso        `yaml:"sso"`
			Providers []provider `yaml:"providers"`
		} `yaml:"adfs"`
	} `yaml:"parameters"`
}

type sso struct {
	URI         string `yaml:"uri"`
	ReturnParam string `yaml:"returnParam"`
	IdpParam    string `yaml:"idpParam"`
}

type provider struct {
	Name         string            `yaml:"name"`
	Metadata     string            `yaml:"metadata"`
	NameIDFormat saml.NameIDFormat `yaml:"nameid_format"`
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

func configureSamlService(config *adfsConfig, cookieMaxDuration time.Duration) (*SAMLService, error) {
	rootURL, err := url.Parse(viper.GetString("DOMAIN"))
	if err != nil {
		return nil, fmt.Errorf("error parsing root domain, %w", err)
	}

	cert, err := parseCertificates()
	if err != nil {
		return nil, err
	}

	return createSAMLService(&ServiceConfig{
		Certificate:       cert,
		Providers:         config.Parameters.ADFS.Providers,
		RootURL:           rootURL,
		CookieMaxDuration: cookieMaxDuration,
	})
}

func parseConfigYaml(file string) (*adfsConfig, error) {
	var config adfsConfig
	yamlFile, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", file, err)
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, fmt.Errorf("error parsing file %s: %w", file, err)
	}

	return &config, nil
}

type certPair struct {
	keyPair       tls.Certificate
	rsaPrivateKey *rsa.PrivateKey
}

func parseCertificates() (certPair, error) {
	cert := certPair{}
	keyPair, err := tls.X509KeyPair(readCert("CERT"), readCert("KEY"))
	if err != nil {
		return cert, fmt.Errorf("missing or invalid CERT and KEY environment variables, %w", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return cert, fmt.Errorf("missing or invalid CERT and KEY environment variables, %w", err)
	}

	privateKey, ok := keyPair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return cert, ErrInvalidKey
	}

	log.Println("Certificate for: ", keyPair.Leaf.Subject.String())

	cert = certPair{
		keyPair:       keyPair,
		rsaPrivateKey: privateKey,
	}
	return cert, nil
}

type ServiceConfig struct {
	Certificate       certPair
	Providers         []provider
	RootURL           *url.URL
	CookieMaxDuration time.Duration
}
