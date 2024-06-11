package indieAuthClient

import (
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"io"
	"net/http"
)

type Server struct {
	Server                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	Identity              string
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
func DiscoveryAuthServer(url string) string {
	resp, _ := http.Get(url)
	defer resp.Body.Close()
	responseTokens := html.NewTokenizer(resp.Body)
	var authEndpoint string

	for tokenType := responseTokens.Next(); tokenType != html.ErrorToken; {
		if tokenType == html.StartTagToken {
			token := responseTokens.Token()

			if token.DataAtom != atom.Link {
				tokenType = responseTokens.Next()
				continue
			}
			isAuthEndpoint := false
			for _, a := range token.Attr {
				if a.Key == "href" {
					authEndpoint = a.Val
				}
				if a.Key == "rel" && a.Val == "authorization_endpoint" {
					isAuthEndpoint = true
				}
			}
			if isAuthEndpoint {
				return authEndpoint
			}
			tokenType = responseTokens.Next()
			continue
		}

		tokenType = responseTokens.Next()
	}
	return ""
}
