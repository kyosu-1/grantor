package grantor

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
)

// formPostScript submits the response form. Its hash is allowed by the
// Content-Security-Policy of the page, so no other script can run.
const formPostScript = `document.forms[0].submit();`

var formPostTemplate = template.Must(template.New("form_post").Parse(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Submitting...</title></head>
<body>
<form method="post" action="{{.Action}}">
{{- range $name, $value := .Values}}
<input type="hidden" name="{{$name}}" value="{{$value}}">
{{- end}}
<noscript><button type="submit">Continue</button></noscript>
</form>
<script>` + formPostScript + `</script>
</body>
</html>
`))

var formPostCSP = func() string {
	sum := sha256.Sum256([]byte(formPostScript))
	return "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
		"'; base-uri 'none'; frame-ancestors 'none'"
}()

// writeFormPost implements the OAuth 2.0 Form Post Response Mode.
func writeFormPost(w http.ResponseWriter, action string, v url.Values) {
	values := make(map[string]string, len(v))
	for name := range v {
		values[name] = v.Get(name)
	}
	var buf bytes.Buffer
	data := struct {
		Action string
		Values map[string]string
	}{
		// html/template only lets http and https URLs through.
		Action: action,
		Values: values,
	}
	if err := formPostTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", formPostCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}
