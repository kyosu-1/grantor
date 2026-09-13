package grantor

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

// SigningKey is a private key that signs ID tokens, JWT access tokens and
// the tokens of custom access token formats that use [SignFunc].
type SigningKey struct {
	// ID is the key ID (kid). It must be unique within an issuer.
	ID string

	// Signer is the private key: an *rsa.PrivateKey (at least 2048 bits),
	// an *ecdsa.PrivateKey, an ed25519.PrivateKey, or any other
	// crypto.Signer with one of those public key types, such as a key held
	// in a KMS or HSM.
	Signer crypto.Signer

	// Algorithm is the JWS algorithm. It defaults to RS256 for RSA keys,
	// ES256, ES384 or ES512 for ECDSA keys depending on the curve, and EdDSA
	// for Ed25519 keys. RSA keys may also use PS256.
	Algorithm string
}

func (k *SigningKey) algorithm() (jose.SignatureAlgorithm, error) {
	if k.Signer == nil {
		return "", fmt.Errorf("signing key %q has no Signer", k.ID)
	}
	switch pub := k.Signer.Public().(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return "", fmt.Errorf("signing key %q: RSA keys must be at least 2048 bits", k.ID)
		}
		switch k.Algorithm {
		case "", "RS256":
			return jose.RS256, nil
		case "PS256":
			return jose.PS256, nil
		}
	case *ecdsa.PublicKey:
		want := map[elliptic.Curve]jose.SignatureAlgorithm{
			elliptic.P256(): jose.ES256,
			elliptic.P384(): jose.ES384,
			elliptic.P521(): jose.ES512,
		}[pub.Curve]
		if want == "" {
			return "", fmt.Errorf("signing key %q: unsupported ECDSA curve", k.ID)
		}
		if k.Algorithm == "" || k.Algorithm == string(want) {
			return want, nil
		}
	case ed25519.PublicKey:
		if k.Algorithm == "" || k.Algorithm == "EdDSA" {
			return jose.EdDSA, nil
		}
	default:
		return "", fmt.Errorf("signing key %q: unsupported key type %T", k.ID, pub)
	}
	return "", fmt.Errorf("signing key %q: algorithm %q does not match the key type", k.ID, k.Algorithm)
}

// keySet is the validated set of signing keys of an issuer.
type keySet struct {
	keys []preparedKey
}

type preparedKey struct {
	id     string
	alg    jose.SignatureAlgorithm
	signer crypto.Signer
}

func newKeySet(keys []SigningKey) (*keySet, error) {
	if len(keys) == 0 {
		return nil, errors.New("issuer has no signing keys")
	}
	ks := &keySet{}
	seen := map[string]bool{}
	for i := range keys {
		k := &keys[i]
		if k.ID == "" {
			return nil, errors.New("signing key has no ID")
		}
		if seen[k.ID] {
			return nil, fmt.Errorf("duplicate signing key ID %q", k.ID)
		}
		seen[k.ID] = true
		alg, err := k.algorithm()
		if err != nil {
			return nil, err
		}
		ks.keys = append(ks.keys, preparedKey{id: k.ID, alg: alg, signer: k.Signer})
	}
	// OpenID Connect Discovery section 3: RS256 must be supported, and it is
	// the default ID token algorithm for clients.
	if _, ok := ks.forAlg("RS256"); !ok {
		return nil, errors.New("issuer needs an RSA signing key with the RS256 algorithm")
	}
	return ks, nil
}

// forAlg returns the first key that signs with alg.
func (ks *keySet) forAlg(alg string) (*preparedKey, bool) {
	for i := range ks.keys {
		if string(ks.keys[i].alg) == alg {
			return &ks.keys[i], true
		}
	}
	return nil, false
}

func (ks *keySet) algorithms() []string {
	var algs []string
	for _, k := range ks.keys {
		if !slices.Contains(algs, string(k.alg)) {
			algs = append(algs, string(k.alg))
		}
	}
	return algs
}

func (ks *keySet) publicJWKS() ([]byte, error) {
	set := jose.JSONWebKeySet{}
	for _, k := range ks.keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:       k.signer.Public(),
			KeyID:     k.id,
			Algorithm: string(k.alg),
			Use:       "sig",
		})
	}
	return json.Marshal(set)
}

// verificationKey returns the public key for kid, used to verify tokens this
// issuer signed, such as id_token_hint.
func (ks *keySet) verificationKey(kid string) (crypto.PublicKey, jose.SignatureAlgorithm, bool) {
	for _, k := range ks.keys {
		if k.id == kid {
			return k.signer.Public(), k.alg, true
		}
	}
	return nil, "", false
}

// sign serializes claims as a compact JWS.
func (k *preparedKey) sign(claims any, typ string) (string, error) {
	var key any
	switch s := k.signer.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		key = s
	default:
		key = cryptosigner.Opaque(s)
	}
	opts := (&jose.SignerOptions{}).
		WithType(jose.ContentType(typ)).
		WithHeader(jose.HeaderKey("kid"), k.id)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: k.alg, Key: key}, opts)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return jws.CompactSerialize()
}
