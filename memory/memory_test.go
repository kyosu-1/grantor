package memory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
	"github.com/kyosu-1/grantor/storagetest"
)

func TestStorage(t *testing.T) {
	storagetest.Run(t, func(*testing.T) grantor.Storage { return memory.New() })
}

func TestClientsAreScopedToIssuer(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	s.SetClient("https://a.example.com", grantor.Client{ID: "app", RedirectURIs: []string{"https://app.example.com/cb"}})

	c, err := s.Client(ctx, "https://a.example.com", "app")
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	c.RedirectURIs[0] = "https://evil.example.com/cb"
	again, err := s.Client(ctx, "https://a.example.com", "app")
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	if again.RedirectURIs[0] != "https://app.example.com/cb" {
		t.Fatal("Client returned a reference to stored data")
	}
	if _, err := s.Client(ctx, "https://b.example.com", "app"); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("Client for another issuer = %v, want ErrNotFound", err)
	}
}
