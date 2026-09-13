package grantor

import (
	"net/http"
	"slices"
)

// metadata is the OpenID Provider Metadata (OpenID Connect Discovery 1.0)
// and Authorization Server Metadata (RFC 8414) document.
type metadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserInfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValues          []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	IntrospectionEndpointAuthMethodsSupported  []string `json:"introspection_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthSigningAlgValues  []string `json:"introspection_endpoint_auth_signing_alg_values_supported"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	RevocationEndpointAuthSigningAlgValues     []string `json:"revocation_endpoint_auth_signing_alg_values_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ClaimTypesSupported                        []string `json:"claim_types_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	PromptValuesSupported                      []string `json:"prompt_values_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

func (p *Provider) serveDiscovery(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	if !allowMethods(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	secretMethods := []string{string(AuthMethodClientSecretBasic), string(AuthMethodClientSecretPost), string(AuthMethodPrivateKeyJWT)}
	allMethods := append(secretMethods[:len(secretMethods):len(secretMethods)], string(AuthMethodNone))
	signingAlgs := assertionAlgorithmNames()

	m := metadata{
		Issuer:                                     iss.url,
		AuthorizationEndpoint:                      iss.endpoint(p.cfg.Endpoints.Authorization),
		TokenEndpoint:                              iss.endpoint(p.cfg.Endpoints.Token),
		UserInfoEndpoint:                           iss.endpoint(p.cfg.Endpoints.UserInfo),
		JWKSURI:                                    iss.endpoint(p.cfg.Endpoints.JWKS),
		IntrospectionEndpoint:                      iss.endpoint(p.cfg.Endpoints.Introspection),
		RevocationEndpoint:                         iss.endpoint(p.cfg.Endpoints.Revocation),
		ScopesSupported:                            p.supportedScopes(),
		ResponseTypesSupported:                     []string{"code"},
		ResponseModesSupported:                     []string{responseModeQuery, responseModeFragment, responseModeFormPost},
		GrantTypesSupported:                        p.supportedGrantTypes(),
		SubjectTypesSupported:                      []string{"public"},
		IDTokenSigningAlgValuesSupported:           iss.keys.algorithms(),
		TokenEndpointAuthMethodsSupported:          allMethods,
		TokenEndpointAuthSigningAlgValues:          signingAlgs,
		IntrospectionEndpointAuthMethodsSupported:  secretMethods,
		IntrospectionEndpointAuthSigningAlgValues:  signingAlgs,
		RevocationEndpointAuthMethodsSupported:     allMethods,
		RevocationEndpointAuthSigningAlgValues:     signingAlgs,
		CodeChallengeMethodsSupported:              []string{"S256"},
		ClaimsSupported:                            p.supportedClaims(),
		ClaimTypesSupported:                        []string{"normal"},
		ClaimsParameterSupported:                   true,
		RequestParameterSupported:                  false,
		RequestURIParameterSupported:               false,
		PromptValuesSupported:                      []string{"none", "login", "consent", "select_account"},
		AuthorizationResponseIssParameterSupported: true,
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, m)
}

func (p *Provider) supportedGrantTypes() []string {
	types := []string{string(GrantTypeAuthorizationCode), string(GrantTypeRefreshToken), string(GrantTypeClientCredentials)}
	var custom []string
	for gt := range p.cfg.Grants {
		custom = append(custom, string(gt))
	}
	slices.Sort(custom)
	return append(types, custom...)
}

func (p *Provider) serveJWKS(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	if !allowMethods(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	body, err := iss.keys.publicJWKS()
	if err != nil {
		p.logError(r.Context(), "marshal JWKS", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/jwk-set+json")
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
