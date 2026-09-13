package grantor_test

import (
	"net/http"
	"testing"

	"github.com/kyosu-1/grantor"
)

func TestErrorStatusCode(t *testing.T) {
	if got := grantor.StatusCodeOf(&grantor.Error{Code: "custom", StatusCode: http.StatusTeapot}); got != http.StatusTeapot {
		t.Fatalf("status = %d", got)
	}
	if got := grantor.StatusCodeOf(&grantor.Error{Code: grantor.CodeInvalidClient}); got != http.StatusUnauthorized {
		t.Fatalf("default status = %d", got)
	}
}
