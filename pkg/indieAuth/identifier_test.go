package indieAuth

import (
	"net/url"
	"testing"
)

func TestValidateProfileURL(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		valid bool
	}{
		{"Valid URL", "https://example.com", true},
		{"Valid URL", "http://example.com/", true},
		{"Valid URL", "zietlow.io", false},
		{"URL with fragment", "https://example.com#fragment", false},
		{"URL with user info", "https://user:pass@example.com", false},
		{"URL with IP as hostname", "https://192.0.2.0", false},
		{"Invalid scheme", "mailto:user@example.com", false},
		{"URL contains a port", "https://example.com:8081", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("Failed to create a valid url%v", err)
			}
			err = validateProfileURL(u)
			if (err != nil) == tt.valid {
				t.Errorf("validateProfileURL() error = %v, validURL %v", err, tt.valid)
			}
		})
	}
}
