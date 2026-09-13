package grantor

import (
	"errors"
	"net/http"
	"strings"
)

// Error codes defined by RFC 6749, RFC 6750, RFC 7009 and OpenID Connect Core.
const (
	CodeInvalidRequest           = "invalid_request"
	CodeInvalidClient            = "invalid_client"
	CodeInvalidGrant             = "invalid_grant"
	CodeUnauthorizedClient       = "unauthorized_client"
	CodeUnsupportedGrantType     = "unsupported_grant_type"
	CodeUnsupportedResponseType  = "unsupported_response_type"
	CodeInvalidScope             = "invalid_scope"
	CodeAccessDenied             = "access_denied"
	CodeServerError              = "server_error"
	CodeTemporarilyUnavailable   = "temporarily_unavailable"
	CodeInvalidToken             = "invalid_token"
	CodeInsufficientScope        = "insufficient_scope"
	CodeUnsupportedTokenType     = "unsupported_token_type"
	CodeInteractionRequired      = "interaction_required"
	CodeLoginRequired            = "login_required"
	CodeAccountSelectionRequired = "account_selection_required"
	CodeConsentRequired          = "consent_required"
	CodeInvalidRequestURI        = "invalid_request_uri"
	CodeInvalidRequestObject     = "invalid_request_object"
	CodeRequestNotSupported      = "request_not_supported"
	CodeRequestURINotSupported   = "request_uri_not_supported"
)

// Error is a protocol error that is sent to clients.
//
// Code and Description are written to the client verbatim, so Description
// must never contain internal details. Internal causes are attached with
// [Error.Unwrap] and only ever logged.
type Error struct {
	Code        string
	Description string

	status int
	cause  error
}

// Sentinel errors an application passes to [Provider.Deny]. They compare
// equal, with [errors.Is], to any *Error that has the same Code.
var (
	ErrAccessDenied             = &Error{Code: CodeAccessDenied}
	ErrLoginRequired            = &Error{Code: CodeLoginRequired}
	ErrConsentRequired          = &Error{Code: CodeConsentRequired}
	ErrInteractionRequired      = &Error{Code: CodeInteractionRequired}
	ErrAccountSelectionRequired = &Error{Code: CodeAccountSelectionRequired}
	ErrTemporarilyUnavailable   = &Error{Code: CodeTemporarilyUnavailable}
)

func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// Unwrap returns the internal cause of the error, if any.
func (e *Error) Unwrap() error { return e.cause }

// Is reports whether target is an *Error with the same Code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// statusCode returns the HTTP status for a token-style JSON error response.
func (e *Error) statusCode() int {
	if e.status != 0 {
		return e.status
	}
	switch e.Code {
	case CodeInvalidClient, CodeInvalidToken:
		return http.StatusUnauthorized
	case CodeInsufficientScope:
		return http.StatusForbidden
	case CodeServerError:
		return http.StatusInternalServerError
	case CodeTemporarilyUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

func newError(code, description string) *Error {
	return &Error{Code: code, Description: description}
}

func errInvalidRequest(description string) *Error {
	return newError(CodeInvalidRequest, description)
}

func errInvalidGrant(description string) *Error {
	return newError(CodeInvalidGrant, description)
}

func errInvalidClient(description string) *Error {
	return newError(CodeInvalidClient, description)
}

// errServer wraps an internal failure. The cause is logged, never sent.
func errServer(cause error) *Error {
	return &Error{Code: CodeServerError, cause: cause}
}

// asProtocolError converts any error into an *Error, hiding unknown causes
// behind server_error.
func asProtocolError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return errServer(err)
}

// sanitizeDescription removes characters that RFC 6749 section 5.2 does not
// allow in error_description (anything outside %x20-21 / %x23-5B / %x5D-7E).
func sanitizeDescription(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, s)
}
