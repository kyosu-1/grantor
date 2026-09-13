// Command rp runs the example relying party.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/kyosu-1/grantor/examples/internal/demo"
	"github.com/kyosu-1/grantor/examples/internal/rpapp"
)

func main() {
	addr := flag.String("addr", demo.RelyingPartyAddr, "listen address")
	issuer := flag.String("issuer", demo.Issuer, "issuer URL of the provider")
	baseURL := flag.String("url", demo.RelyingPartyURL, "base URL of this relying party")
	flag.Parse()

	app := rpapp.New(rpapp.Config{
		Issuer:       *issuer,
		ClientID:     demo.ClientID,
		ClientSecret: demo.ClientSecret,
		BaseURL:      *baseURL,
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
	})

	slog.Info("example relying party listening", "url", *baseURL)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
}
