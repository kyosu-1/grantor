// Command op runs the example OpenID Provider.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/kyosu-1/grantor/examples/internal/demo"
	"github.com/kyosu-1/grantor/examples/internal/opapp"
)

func main() {
	addr := flag.String("addr", demo.ProviderAddr, "listen address")
	issuer := flag.String("issuer", demo.Issuer, "issuer URL")
	rpURL := flag.String("rp", demo.RelyingPartyURL, "base URL of the example relying party")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	app, err := opapp.New(opapp.Config{
		Issuer:  *issuer,
		Clients: demo.Clients(*rpURL),
		Logger:  logger,
	}, opapp.DemoUsers())
	if err != nil {
		logger.Error("start provider", "error", err)
		os.Exit(1)
	}

	logger.Info("example OpenID Provider listening", "issuer", *issuer, "discovery", *issuer+"/.well-known/openid-configuration")
	srv := &http.Server{
		Addr:              *addr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("serve", "error", err)
		os.Exit(1)
	}
}
