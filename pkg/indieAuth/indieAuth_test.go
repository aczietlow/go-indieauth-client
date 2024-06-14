package indieAuth

import (
	"net/http"
	"net/http/httptest"
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
		//{
		//	sourceUrl:        ts.URL,
		//	authEndpointUrl:  "http://localhost/auth",
		//	tokenEndpointUrl: "http://localhost/token",
		//},
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
