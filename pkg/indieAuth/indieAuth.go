package indieAuth

import (
	"errors"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"io"
	"net/http"
)

type Config struct {
	ClientID     string
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

type Server struct {
	Server                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	Identity              string
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
		ClientID:     "",
		ClientSecret: "",
		Endpoint:     endpoint,
		Identifier:   id,
		RedirectURL:  "",
	}, nil
}

func NewServer(url string) Server {
	return Server{
		Server: url,
	}
}

func (s *Server) request(uri string) []byte {
	resp, _ := http.Get(uri)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	return body
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
