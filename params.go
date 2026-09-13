package grantor

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// maxBodyBytes limits the size of form request bodies.
const maxBodyBytes = 1 << 16

// params holds request parameters. RFC 6749 section 3.1 forbids repeating a
// parameter, so values are single strings and repeated names are recorded.
type params struct {
	values   map[string]string
	repeated []string
}

func newParams(v url.Values) params {
	p := params{values: make(map[string]string, len(v))}
	for name, vals := range v {
		if len(vals) > 1 {
			p.repeated = append(p.repeated, name)
		}
		// Parameters sent without a value are treated as omitted
		// (RFC 6749 section 3.1).
		if len(vals) > 0 && vals[0] != "" {
			p.values[name] = vals[0]
		}
	}
	return p
}

func (p params) get(name string) string { return p.values[name] }

func (p params) has(name string) bool {
	_, ok := p.values[name]
	return ok
}

func (p params) isRepeated(name string) bool {
	return slices.Contains(p.repeated, name)
}

// parseForm reads an application/x-www-form-urlencoded request body.
// Parameters in the query string are ignored.
func parseForm(r *http.Request) (params, *Error) {
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/x-www-form-urlencoded" {
		return params{}, errInvalidRequest("the request body must be application/x-www-form-urlencoded")
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		return params{}, errInvalidRequest("the request body could not be parsed")
	}
	return newParams(r.PostForm), nil
}

// splitSpaces splits a space-delimited parameter such as scope, removing
// duplicates while preserving order.
func splitSpaces(s string) []string {
	var out []string
	for _, f := range strings.Split(s, " ") {
		if f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write(body)
}

// writeTokenError writes an RFC 6749 section 5.2 error response.
func (p *Provider) writeTokenError(w http.ResponseWriter, r *http.Request, err error) {
	e := asProtocolError(err)
	if e.Code == CodeServerError {
		p.logError(r.Context(), "token endpoint", err)
	}
	body := map[string]string{"error": e.Code}
	if e.Description != "" {
		body["error_description"] = sanitizeDescription(e.Description)
	}
	if e.URI != "" {
		body["error_uri"] = sanitizeURI(e.URI)
	}
	noStore(w)
	if e.Code == CodeInvalidClient && strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	writeJSON(w, e.statusCode(), body)
}

func allowMethods(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	if slices.Contains(methods, r.Method) {
		return true
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}
