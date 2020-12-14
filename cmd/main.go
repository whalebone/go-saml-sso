package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/spf13/viper"
)

const cookieName = "SAMLToken"


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

func test(w http.ResponseWriter, r *http.Request) {
	_, err := fmt.Fprintln(w, "<html><body>")
	if err != nil {
		return
	}

	genericSession := samlsp.SessionFromContext(r.Context())
	jwtSession := genericSession.(samlsp.JWTSessionClaims)

	name := jwtSession.Attributes.Get("cn")
	if name != "" {
		_, _ = fmt.Fprintf(w, "<p>Hello, %s!</p>", name)
	}

	jsonData, err := json.MarshalIndent(jwtSession, "", "  ")
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
	w.Header().Add("Location", returnURL.String())
	w.WriteHeader(http.StatusFound)
	return
}

func readCert(key string) []byte {
	certHandler := strings.NewReplacer("\\n", "\n")
	return []byte(certHandler.Replace(viper.GetString(key)))
}

func main() {
	viper.AutomaticEnv()
	viper.SetDefault("DOMAIN", "http://localhost")
	viper.SetDefault("PATH_PREFIX", "")
	viper.SetDefault("PORT", "8000")
	viper.SetDefault("TOKEN_MAX_AGE", "10h")

	keyPair, err := tls.X509KeyPair(readCert("CERT"), readCert("KEY"))
	if err != nil {
		fmt.Println("Missing or invalid CERT and KEY environment variables")
		panic(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err)
	}

	fmt.Println("Certificate: ", keyPair.Leaf.Subject.String())

	idpMetadataURL, err := url.Parse(viper.GetString("IDP_META_URL"))
	if err != nil {
		panic(err)
	}
	fmt.Println("Identity Provider URL: ", idpMetadataURL.String())
	idpMetadata, err := fetchIDPMetadata(idpMetadataURL)
	if err != nil {
		panic(err)
	}

	rootURL, err := url.Parse(viper.GetString("DOMAIN"))
	if err != nil {
		panic(err)
	}

	maxDuration, err := time.ParseDuration(viper.GetString("TOKEN_MAX_AGE"))
	if err != nil {
		panic(err)
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		URL:          *rootURL,
		Key:          keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:  keyPair.Leaf,
		IDPMetadata:  idpMetadata,
		CookieName:   cookieName,
		CookieMaxAge: maxDuration,
	})
	// set NameID format
	samlSP.ServiceProvider.AuthnNameIDFormat = saml.UnspecifiedNameIDFormat

	prefix := viper.GetString("PATH_PREFIX")
	fmt.Println("Path prefix: ", prefix)
	fmt.Println("SSO Metadata URL: ", samlSP.ServiceProvider.MetadataURL.String())
	fmt.Println("SSO Acs URL: ", samlSP.ServiceProvider.AcsURL.String())
	fmt.Println("SSO NameID Format: ", samlSP.ServiceProvider.AuthnNameIDFormat)
	sessionProvider, ok := samlSP.Session.(samlsp.CookieSessionProvider)
	if ok {
		fmt.Println("Token max duration: ", sessionProvider.MaxAge)
	}

	test := http.HandlerFunc(test)
	auth := http.HandlerFunc(returnAfterAuth)
	http.Handle(prefix+"/test", samlSP.RequireAccount(test))
	http.Handle(prefix+"/auth", samlSP.RequireAccount(auth))
	http.Handle(prefix+"/saml/", samlSP)

	fmt.Println("Listening on port: ", viper.GetString("PORT"))
	err = http.ListenAndServe(":"+viper.GetString("PORT"), nil)
	if err != nil {
		panic(err)
	}
}
