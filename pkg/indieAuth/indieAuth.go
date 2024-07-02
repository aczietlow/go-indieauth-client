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
	State        string
	Verifier     string
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

	runTimeConf, err := loadConfig("./config.yaml")

	if err != nil {
		return Config{}, err
	}

	state, err := generateState(10)
	if err != nil {
		// @TODO do something
		fmt.Println(err.Error())
	}

	return Config{
		ClientID:     runTimeConf.URL,
		ClientSecret: "",
		Endpoint:     endpoint,
		Identifier:   id,
		RedirectURL:  runTimeConf.RedirectURL,
		State:        state,
		Verifier:     "",
	}, nil
}

// @TODO add support for newer metadata endpoints as well.
func discoveryAuthServer(url string) (Endpoint, error) {
	resp, err := http.Get(url)

	if err != nil {
		return Endpoint{}, err
	}

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
	verifier, _ := generateCodeVerifier()

	c.Verifier = verifier
	params := getHandshakeParams(*c)
	u, err := url.Parse(c.Endpoint.AuthURL)

	if err != nil {
		// @TODO do something
		fmt.Println(err.Error())
	}
	u.RawQuery = params.Encode()

	return u.String()

}

func getHandshakeParams(c Config) url.Values {
	// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))

	// @TODO Add support for additional code challenge methods in the future.
	codeChallenge := s256CodeChallenge(c.Verifier)

	//request := map[string][]string{
	request := url.Values{
		"response_type":         []string{"code"},
		"client_id":             []string{c.ClientID},
		"redirect_uri":          []string{c.RedirectURL},
		"state":                 []string{c.State},
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

func (c *Config) TokenExchange(state string, code string, iss string) string {
	if c.State != state {
		// Freak Out
		fmt.Println(errors.New("state does not match"))
	}

	authURL, _ := url.QueryUnescape(iss)

	if len(iss) > 0 && iss != authURL {
		fmt.Println(errors.New("issuer value does not match does not match"))
	}

	params := getTokenExchangeParams(*c, code)
	u, err := url.Parse(c.Endpoint.TokenURL)

	if err != nil {
		// @TODO do something
		fmt.Println(err.Error())
	}
	u.RawQuery = params.Encode()

	resp, err := http.Get(u.String())

	if err != nil {
		fmt.Println(errors.New("something happened with the token exchange request"))
	}

	defer resp.Body.Close()

	// @TODO process the response to get the query params
	/* {
	  "access_token": "XXXXXX",
	  "token_type": "Bearer",
	  "scope": "create update delete",
	  "me": "https://user.example.net/"
	}
	*/

	return ""
}

func getTokenExchangeParams(c Config, code string) url.Values {
	// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))

	//request := map[string][]string{
	request := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"client_id":     []string{c.ClientID},
		"redirect_uri":  []string{c.RedirectURL},
		"code_verifier": []string{c.Verifier},
	}

	return request
}
