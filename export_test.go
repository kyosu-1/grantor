package grantor

import "time"

// SetClock replaces the provider's clock in tests.
func SetClock(p *Provider, now func() time.Time) { p.now = now }
