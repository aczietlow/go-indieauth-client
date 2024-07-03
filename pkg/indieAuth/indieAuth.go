package indieAuth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	Token        Token
}

type Endpoint struct {
	AuthURL     string
	TokenURL    string
	MetadataURL string
}

type Token struct {
	AccessToken  string
	Expires      int
	RefreshToken string
	Scope        []string
}

type TokenRequestParams struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	ClientId     string `json:"client_id"`
	RedirectURL  string `json:"redirect_url"`
	CodeVerifier string `json:"code_verifier"`
}

type TokenResponseParams struct {
	AccessToken string `json:"access_token"`
	Me          string `json:"me"`
	Scope       string `json:"scope"`
	//Profiles	any
	Expires      int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
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
		Token:        Token{},
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

func (c *Config) TokenExchange(state string, code string, iss string) (string, error) {
	if c.State != state {
		return "", errors.New("state value does not match")
	}

	authURL, _ := url.QueryUnescape(iss)

	if len(iss) > 0 && iss != authURL {
		return "", errors.New("issuer value does not match does not match")
	}

	params, err := getTokenExchangeParams(*c, code)

	if err != nil {
		return "", err
	}

	tokenResponse, err := getTokenURLResponse(c.Endpoint.TokenURL, params)

	if err != nil {
		return "", err
	}

	c.Token.AccessToken = tokenResponse.AccessToken
	c.Token.Expires = tokenResponse.Expires

	if tokenResponse.RefreshToken != "" {
		c.Token.RefreshToken = tokenResponse.RefreshToken
	}

	if tokenResponse.Scope != "" {
		c.Token.Scope = strings.Split(tokenResponse.Scope, " ")
	}

	return c.Token.AccessToken, nil
}

func getTokenURLResponse(u string, params []byte) (TokenResponseParams, error) {
	resp, err := http.Post(u, "application/json", bytes.NewBuffer(params))
	if err != nil {
		return TokenResponseParams{}, err
	}
	defer resp.Body.Close()

	if r := resp.Header.Get("Content-Type"); r != "application/json" {
		b, _ := io.ReadAll(resp.Body)
		e := fmt.Sprintf("Application type was %v\n\nBody response: %v\n", r, string(b))
		return TokenResponseParams{}, errors.New(e)
	}

	//if resp.StatusCode != http.StatusCreated {
	//	return TokenResponseParams{}, errors.New(fmt.Sprintf("Received status code of %v when expected 201", resp.StatusCode))
	//}

	tokenResponse := &TokenResponseParams{}
	err = json.NewDecoder(resp.Body).Decode(tokenResponse)

	if err != nil {
		return TokenResponseParams{}, err
	}

	return *tokenResponse, nil
}

func getTokenExchangeParams(c Config, code string) ([]byte, error) {
	// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))

	params := &TokenRequestParams{
		GrantType:    "authorization_code",
		Code:         code,
		ClientId:     c.ClientID,
		RedirectURL:  c.RedirectURL,
		CodeVerifier: c.Verifier,
	}

	body, err := json.Marshal(params)
	if err != nil {
		return []byte{}, err
	}

	return body, nil
}
