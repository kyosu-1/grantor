package grantor

import "time"

// SetClock replaces the provider's clock in tests.
func SetClock(p *Provider, now func() time.Time) { p.now = now }

// StatusCodeOf exposes the HTTP status chosen for an error.
func StatusCodeOf(e *Error) int { return e.statusCode() }
