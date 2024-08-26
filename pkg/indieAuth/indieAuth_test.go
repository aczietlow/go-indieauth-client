package indieAuth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
				ClientID: "http://localhost:9002/",
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

			// @TODO: Remove hack
			// Hack out state value as this is generated at run time.
			config.State = ""

			// Check the returned config
			if !reflect.DeepEqual(config, tc.wantConfig) {
				t.Errorf("Failure on: %v\n\nNew() = %v\n, want %v\n", tc.name, config, tc.wantConfig)
			}
		})
	}
}

func TestGetTokenURLResponse(t *testing.T) {
	// Mock HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(TokenResponseParams{
			AccessToken:  "test_access_token",
			Me:           "test_me",
			Scope:        "test_scope",
			Expires:      3600,
			RefreshToken: "test_refresh_token",
		})
	}))
	defer ts.Close()

	// Prepare parameters
	params := url.Values{
		"GrantType":    []string{"authorization_code"},
		"Code":         []string{"test_code"},
		"ClientId":     []string{"test_client_id"},
		"RedirectURL":  []string{"test_redirect_url"},
		"CodeVerifier": []string{"test_code_verifier"},
	}

	// Call the function
	resp, err := getTokenURLResponse(ts.URL, params)

	// Check for error
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check the response
	if resp.AccessToken != "test_access_token" {
		t.Errorf("Expected access token 'test_access_token', got '%s'", resp.AccessToken)
	}
	if resp.Me != "test_me" {
		t.Errorf("Expected me 'test_me', got '%s'", resp.Me)
	}
	if resp.Scope != "test_scope" {
		t.Errorf("Expected scope 'test_scope', got '%s'", resp.Scope)
	}
	if resp.Expires != 3600 {
		t.Errorf("Expected expires '3600', got '%d'", resp.Expires)
	}
	if resp.RefreshToken != "test_refresh_token" {
		t.Errorf("Expected refresh token 'test_refresh_token', got '%s'", resp.RefreshToken)
	}
}
