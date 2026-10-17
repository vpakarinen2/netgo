package config

import "encoding/json"

// MarshalJSON renders the timeout as a Go duration string rather than an opaque
// nanosecond count. This is also the representation used by --check-config.
func (s Scan) MarshalJSON() ([]byte, error) {
	type plain Scan
	return json.Marshal(struct {
		plain
		Timeout string `json:"timeout"`
	}{plain: plain(s), Timeout: s.Timeout.String()})
}

func (d DNS) MarshalJSON() ([]byte, error) {
	type plain DNS
	return json.Marshal(struct {
		plain
		Timeout string `json:"timeout"`
	}{plain: plain(d), Timeout: d.Timeout.String()})
}

func (s Service) MarshalJSON() ([]byte, error) {
	type plain Service
	return json.Marshal(struct {
		plain
		Timeout string `json:"timeout"`
	}{plain: plain(s), Timeout: s.Timeout.String()})
}
