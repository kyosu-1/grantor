// Package demo holds the settings shared by the example provider and relying
// party.
package demo

import "github.com/kyosu-1/grantor"

const (
	ProviderAddr = "localhost:9001"
	Issuer       = "http://" + ProviderAddr

	RelyingPartyAddr = "localhost:9002"
	RelyingPartyURL  = "http://" + RelyingPartyAddr

	ClientID = "demo-rp"
	// ClientSecret is public because this is an example. Generate real
	// secrets with grantor.GenerateSecret.
	ClientSecret = "demo-rp-secret-Qm9vZ2llLVdvb2dpZS1CYXJuYWNsZS0yMDI2"
)

// Clients returns the clients registered with the example provider.
func Clients(relyingPartyURL string) []grantor.Client {
	return []grantor.Client{
		{
			ID:           ClientID,
			SecretHash:   grantor.HashSecret(ClientSecret),
			RedirectURIs: []string{relyingPartyURL + "/callback"},
			GrantTypes:   []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
			Scopes:       []string{"openid", "profile", "email", "phone", "offline_access"},
			RequirePKCE:  true,
		},
		{
			// A native app or CLI using a loopback redirect URI on any port.
			ID:           "demo-cli",
			RedirectURIs: []string{"http://127.0.0.1/callback"},
			GrantTypes:   []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
			Scopes:       []string{"openid", "profile", "email", "offline_access"},
		},
	}
}
