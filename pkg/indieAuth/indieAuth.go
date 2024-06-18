package indieAuth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"net/http"
	"net/url"
)

type Config struct {
	ClientID string
	// @TODO What is the client secret again?
	ClientSecret string
	Endpoint     Endpoint
	Identifier   Identifier
	RedirectURL  string
}

type Endpoint struct {
	AuthURL     string
	TokenURL    string
	MetadataURL string
}

type Token struct {
	AccessToken string `json:"access_token"`
}

func New(ProfileURL string) (Config, error) {
	id, err := newUserIdentifier(ProfileURL)

	if err != nil {
		return Config{}, err
	}

	endpoint, err := discoveryAuthServer(id.ProfileURL)

	if err != nil {
		return Config{}, err
	}

	return Config{
		ClientID:     "indieAuth",
		ClientSecret: "",
		Endpoint:     endpoint,
		Identifier:   id,
		RedirectURL:  "http://localhost:9002/redirect",
	}, nil
}

// @TODO add support for newer metadata endpoints as well.
func discoveryAuthServer(url string) (Endpoint, error) {
	resp, _ := http.Get(url)
	defer resp.Body.Close()
	responseTokens := html.NewTokenizer(resp.Body)
	var endpointURL string
	endpoint := Endpoint{}

	for tokenType := responseTokens.Next(); tokenType != html.ErrorToken; {
		if tokenType == html.StartTagToken {
			token := responseTokens.Token()

			if token.DataAtom != atom.Link {
				tokenType = responseTokens.Next()
				continue
			}
			endpointURL = ""
			isAuthEndpoint := false
			isTokenEndpoint := false
			for _, a := range token.Attr {
				if a.Key == "href" {
					endpointURL = a.Val
					continue
				}
				if a.Key == "rel" && a.Val == "authorization_endpoint" {
					isAuthEndpoint = true
					continue
				}
				if a.Key == "rel" && a.Val == "token_endpoint" {
					isTokenEndpoint = true
					continue
				}
			}
			if isAuthEndpoint {
				endpoint.AuthURL = endpointURL
				isAuthEndpoint = false
			}
			if isTokenEndpoint {
				endpoint.TokenURL = endpointURL
				isAuthEndpoint = false
			}

			if endpoint.AuthURL != "" && endpoint.TokenURL != "" {
				return endpoint, nil
			}

			tokenType = responseTokens.Next()
			continue
		}

		tokenType = responseTokens.Next()
	}
	return Endpoint{}, errors.New("unable to find link header for `indieauth-metadata` or link headers for `rel=authorization_endpoint` and `rel=token_endpoint`")
}

func (c *Config) GetAuthorizationRequestURL() string {
	params := c.getHandshakeParams()
	u, err := url.Parse(c.Endpoint.AuthURL)

	if err != nil {
		// @TODO do something
		fmt.Println(err.Error())
	}
	u.RawQuery = params.Encode()

	return u.String()

}

func (c *Config) getHandshakeParams() url.Values {
	state, err := generateState(10)
	if err != nil {
		// @TODO do something
		fmt.Println(err.Error())
	}

	// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
	verifier, _ := generateCodeVerifier()
	// @TODO Add support for additional code challenge methods in the future.
	codeChallenge := s256CodeChallenge(verifier)

	//request := map[string][]string{
	request := url.Values{
		"response_type":         []string{"code"},
		"client_id":             []string{c.ClientID},
		"redirect_uri":          []string{c.RedirectURL},
		"state":                 []string{state},
		"code_challenge":        []string{codeChallenge},
		"code_challenge_method": []string{"S256"},
		"scope":                 []string{"profile email"},
		"me":                    []string{c.Identifier.ProfileURL},
	}

	return request
}

func generateState(n int) (string, error) {
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func generateCodeVerifier() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func s256CodeChallenge(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
