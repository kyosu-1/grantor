// Command lowlevel runs an example OpenID Provider built from grantor's
// building blocks instead of the all-in-one Provider handler.
package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	const issuer = "http://localhost:9003"
	handler, err := newServer(issuer, logger)
	if err != nil {
		logger.Error("start", "error", err)
		os.Exit(1)
	}
	logger.Info("low-level example listening", "issuer", issuer)
	srv := &http.Server{Addr: "localhost:9003", Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("serve", "error", err)
		os.Exit(1)
	}
}
