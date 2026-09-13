package grantor

import "testing"

// Client assertion replay protection is scoped to the issuer and the client,
// and distinct inputs never share a key.
func TestAssertionKey(t *testing.T) {
	keys := map[string][3]string{}
	for _, parts := range [][3]string{
		{"https://a.example.com", "client", "jti"},
		{"https://b.example.com", "client", "jti"},
		{"https://a.example.com", "other", "jti"},
		{"https://a.example.com", "client", "other"},
		{"https://a.example.com", "x", "y\x00z"},
		{"https://a.example.com", "x\x00y", "z"},
		{"https://a.example.com", "clientj", "ti"},
	} {
		key := assertionKey(parts[0], parts[1], parts[2])
		if prev, ok := keys[key]; ok {
			t.Errorf("%q and %q share the key %q", prev, parts, key)
		}
		if len(key) > 128 {
			t.Errorf("key %q is longer than 128 bytes", key)
		}
		keys[key] = parts
	}
	if assertionKey("i", "c", "j") != assertionKey("i", "c", "j") {
		t.Error("assertionKey is not deterministic")
	}
}
