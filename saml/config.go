package saml

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
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

const metadataFetchTimeout = time.Second * 20
const refreshInterval = time.Hour * 2

type adfsConfigDTO struct {
	Parameters struct {
		ADFS struct {
			SSO       ssoDTO        `yaml:"sso"`
			Providers []providerDTO `yaml:"providers"`
		} `yaml:"adfs"`
	} `yaml:"parameters"`
}

type ssoDTO struct {
	URI         string `yaml:"uri"`
	ReturnParam string `yaml:"returnParam"`
	IdpParam    string `yaml:"idpParam"`
}

type providerDTO struct {
	Name         string            `yaml:"name"`
	Metadata     string            `yaml:"metadata"`
	NameIDFormat saml.NameIDFormat `yaml:"nameid_format"`
}

func (p *providerDTO) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawProvider providerDTO
	raw := rawProvider{ // defaults
		NameIDFormat: saml.UnspecifiedNameIDFormat,
	}
	if err := unmarshal(&raw); err != nil {
		return err
	}

	*p = providerDTO(raw)
	return nil
}

func readCert(key string) []byte {
	certHandler := strings.NewReplacer("\\n", "\n")
	return []byte(certHandler.Replace(viper.GetString(key)))
}

func NewSAMLConfig() (*ServiceConfig, error) {
	viper.AutomaticEnv()
	viper.SetDefault("DOMAIN", "http://localhost:8000")
	viper.SetDefault("COOKIE_DOMAIN", "localhost")
	viper.SetDefault("PATH_PREFIX", "")
	viper.SetDefault("PORT", "8000")
	viper.SetDefault("TOKEN_MAX_AGE", "5m")
	viper.SetDefault("DEBUG", "0")

	debug := viper.GetBool("DEBUG")

	prefix := ensureAbsolute(viper.GetString("PATH_PREFIX"))
	log.Println("Path prefix: ", prefix)

	adfsConfig, err := parseConfigYaml("adfs.neon")
	if err != nil {
		log.Println("Error reading configuration")
		return nil, err
	}

	cookieDomain := viper.GetString("COOKIE_DOMAIN")
	maxDuration, err := time.ParseDuration(viper.GetString("TOKEN_MAX_AGE"))
	if err != nil {
		return nil, fmt.Errorf("missing or invalid TOKEN_MAX_AGE environment variable, %w", err)
	}

	rootURL, err := url.Parse(viper.GetString("DOMAIN"))
	if err != nil {
		return nil, fmt.Errorf("error parsing root domain, %w", err)
	}

	cert, err := parseCertificates()
	if err != nil {
		return nil, err
	}

	return &ServiceConfig{
		RoutePathPrefix:   prefix,
		Certificate:       cert,
		Providers:         adfsConfig.Parameters.ADFS.Providers,
		RootURL:           rootURL,
		CookieDomain:      cookieDomain,
		CookieMaxDuration: maxDuration,
		RefreshInterval:   refreshInterval,
		Debug:             debug,
	}, nil
}

func parseConfigYaml(file string) (*adfsConfigDTO, error) {
	var config adfsConfigDTO
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
	Providers         []providerDTO
	RootURL           *url.URL
	CookieMaxDuration time.Duration
	CookieDomain      string
	RefreshInterval   time.Duration
	RoutePathPrefix   string
	Debug             bool
}

func ensureAbsolute(path string) string {
	if len(path) == 0 {
		return "/"
	}

	if path[0] == '/' {
		return path
	}

	return "/" + path
}
