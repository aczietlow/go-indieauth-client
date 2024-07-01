package indieAuth

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestDiscoveryAuthServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<a href="f00"> </a><link href="http://localhost/auth" rel="authorization_endpoint"><link href="http://localhost/token" rel="token_endpoint">`))
	}))
	defer ts.Close()

	type TestUrl struct {
		sourceUrl        string
		authEndpointUrl  string
		tokenEndpointUrl string
	}

	tests := []TestUrl{
		{
			sourceUrl:        ts.URL,
			authEndpointUrl:  "http://localhost/auth",
			tokenEndpointUrl: "http://localhost/token",
		},
		{
			sourceUrl:        "https://zietlow.io/",
			authEndpointUrl:  "https://indieauth.com/auth",
			tokenEndpointUrl: "https://tokens.indieauth.com/token",
		},
	}

	for _, Url := range tests {
		endpoint, err := discoveryAuthServer(Url.sourceUrl)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if endpoint.AuthURL != Url.authEndpointUrl {
			t.Errorf("Parsed %v Expected '%v', got '%s'", Url.sourceUrl, Url.authEndpointUrl, endpoint.AuthURL)
		}
		if endpoint.TokenURL != Url.tokenEndpointUrl {
			t.Errorf("Parsed %v Expected '%v', got '%s'", Url.sourceUrl, Url.tokenEndpointUrl, endpoint.TokenURL)
		}
	}
}

func TestGenerateState(t *testing.T) {
	n := 10
	stateStr, err := generateState(n)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check for expected return encoded length due to base64 encoded.
	expectedLength := ((n + 2) / 3) * 4
	if len(stateStr) != expectedLength {
		t.Errorf("Expected length of '%v', got '%v'", expectedLength, len(stateStr))
	}
}

func TestNew(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name       string
		profileURL string
		wantErr    bool
		wantConfig Config
	}{
		{
			name:       "Valid Profile URL",
			profileURL: "https://zietlow.io",
			wantErr:    false,
			wantConfig: Config{
				ClientID:     "http://localhost:9002/",
				ClientSecret: "",
				Endpoint: Endpoint{
					AuthURL:  "https://indieauth.com/auth",
					TokenURL: "https://tokens.indieauth.com/token",
				},
				Identifier: Identifier{
					ProfileURL: "https://zietlow.io/",
				},
				RedirectURL: "http://localhost:9002/redirect",
			},
		},
		{
			name:       "Invalid Profile URL",
			profileURL: "invalid",
			wantErr:    true,
			wantConfig: Config{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function with the test case parameters
			config, err := New(tc.profileURL)

			// If we want an error and there isn't one, or vice versa, fail the test.
			if (err != nil) != tc.wantErr {
				t.Errorf("New() error = %v\n, wantErr %v\n", err, tc.wantErr)
				return
			}

			// Check the returned config
			if !reflect.DeepEqual(config, tc.wantConfig) {
				t.Errorf("\nNew() = %v\n, want %v\n", config, tc.wantConfig)
			}
		})
	}
}
