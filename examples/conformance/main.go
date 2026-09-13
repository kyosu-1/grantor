// Command conformance runs the example provider configured for the OpenID
// Foundation conformance suite: HTTPS with a self-signed certificate, the
// clients the suite expects, and no consent screen.
//
// See README.md in this directory.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/examples/internal/opapp"
)

// Client secrets of the conformance clients. They are public; this server is
// for testing only.
const (
	clientSecret     = "conformance-client-secret-0f6b1c2e9a4d4b7e8c3a5d6f7e8a9b0c"
	client2Secret    = "conformance-client2-secret-1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"
	clientPostSecret = "conformance-post-secret-9f8e7d6c5b4a39281706f5e4d3c2b1a0"
)

func main() {
	addr := flag.String("addr", ":9443", "listen address")
	issuer := flag.String("issuer", "https://host.docker.internal:9443", "issuer URL, reachable from the conformance suite")
	suite := flag.String("suite", "https://localhost.emobix.co.uk:8443", "base URL of the conformance suite")
	alias := flag.String("alias", "grantor", "alias of the conformance suite test configuration")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	redirectURI := *suite + "/test/a/" + *alias + "/callback"
	client := func(id, secret string, method grantor.AuthMethod) grantor.Client {
		return grantor.Client{
			ID:           id,
			AuthMethod:   method,
			SecretHash:   grantor.HashSecret(secret),
			RedirectURIs: []string{redirectURI},
			GrantTypes:   []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
			Scopes:       []string{"openid", "profile", "email", "address", "phone", "offline_access"},
		}
	}

	app, err := opapp.New(opapp.Config{
		Issuer: *issuer,
		Clients: []grantor.Client{
			client("conformance-client", clientSecret, grantor.AuthMethodClientSecretBasic),
			client("conformance-client2", client2Secret, grantor.AuthMethodClientSecretBasic),
			client("conformance-post", clientPostSecret, grantor.AuthMethodClientSecretPost),
		},
		AutoConsent: true,
		Logger:      logger,
	}, opapp.DemoUsers())
	if err != nil {
		logger.Error("start provider", "error", err)
		os.Exit(1)
	}

	cert, err := selfSignedCertificate()
	if err != nil {
		logger.Error("create certificate", "error", err)
		os.Exit(1)
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	logger.Info("conformance provider listening", "issuer", *issuer, "redirect_uri", redirectURI)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		logger.Error("serve", "error", err)
		os.Exit(1)
	}
}

func selfSignedCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "grantor conformance provider"},
		DNSNames:     []string{"host.docker.internal", "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
