package grantor

import (
	"errors"
	"net/http"
	"strings"
)

// Error codes defined by RFC 6749, RFC 6750, RFC 7009, RFC 8707 and OpenID
// Connect Core.
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
	CodeInvalidTarget            = "invalid_target"
)

// Error is a protocol error that is sent to clients.
//
// Code and Description are written to the client verbatim, so Description
// must never contain internal details. Internal causes are attached with
// [Error.Unwrap] and only ever logged.
type Error struct {
	Code        string
	Description string
	// URI identifies a web page with information about the error. It is
	// sent as error_uri.
	URI string
	// StatusCode is the HTTP status of JSON error responses, such as those
	// of the token endpoint. Zero, or a value outside 400-599, selects the
	// status RFC 6749 and RFC 6750 define for Code.
	StatusCode int

	cause error
}

func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// Unwrap returns the internal cause of the error, if any.
func (e *Error) Unwrap() error { return e.cause }

// Is reports whether target is an *Error with the same Code, so that
// errors.Is(err, &grantor.Error{Code: grantor.CodeAccessDenied}) matches any
// access_denied error.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// HTTPStatus returns the status grantor uses when it writes e as a JSON error
// response or error page: StatusCode if it is a 4xx or 5xx status, otherwise
// the status RFC 6749 and RFC 6750 define for Code.
func (e *Error) HTTPStatus() int {
	if e.StatusCode >= 400 && e.StatusCode <= 599 {
		return e.StatusCode
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
		if e == nil {
			return errServer(errors.New("a nil *grantor.Error was returned as an error"))
		}
		return e
	}
	return errServer(err)
}

// validErrorCode reports whether code only uses the characters RFC 6749
// allows in error codes (%x20-21 / %x23-5B / %x5D-7E).
func validErrorCode(code string) bool {
	if code == "" {
		return false
	}
	for i := 0; i < len(code); i++ {
		if c := code[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// sanitizeURI removes characters RFC 6749 does not allow in error_uri
// (%x21 / %x23-5B / %x5D-7E).
func sanitizeURI(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, s)
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
