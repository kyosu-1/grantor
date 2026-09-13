module github.com/kyosu-1/grantor/examples

go 1.26.0

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/kyosu-1/grantor v0.0.0
	golang.org/x/crypto v0.57.0
	golang.org/x/oauth2 v0.37.0
)

require github.com/go-jose/go-jose/v4 v4.1.5 // indirect

replace github.com/kyosu-1/grantor => ../
