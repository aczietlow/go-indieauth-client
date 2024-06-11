package indieAuthClient

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoveryAuthServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<a href="f00"> </a><link href="http://localhost/auth" rel="authorization_endpoint">`))
	}))
	defer ts.Close()

	type TestUrl struct {
		sourceUrl       string
		authEndpointUrl string
	}

	Urls := []TestUrl{
		{
			sourceUrl:       ts.URL,
			authEndpointUrl: "http://localhost/auth",
		},
		{
			sourceUrl:       "https://zietlow.io/",
			authEndpointUrl: "https://indieauth.com/auth",
		},
	}

	for _, Url := range Urls {
		authEndpoint := DiscoveryAuthServer(Url.sourceUrl)
		if authEndpoint != Url.authEndpointUrl {
			t.Errorf("Expected '%v', got '%s'", Url.authEndpointUrl, authEndpoint)
		}
		t.Logf("AuthEndpount discovered: %v", authEndpoint)
	}
}
