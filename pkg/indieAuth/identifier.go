package indieAuth

import (
	"errors"
	"net"
	"net/url"
)

type Identifier struct {
	ProfileURL string
}

func newUserIdentifier(profileURL string) (Identifier, error) {
	IdURL, err := url.Parse(profileURL)
	if err != nil {
		return Identifier{}, err
	}
	canonicalizeURL(IdURL)

	err = validateProfileURL(IdURL)
	if err != nil {
		// Not a valid URL
		return Identifier{}, err
	}

	return Identifier{ProfileURL: IdURL.String()}, nil
}

func validateProfileURL(u *url.URL) error {
	validSchemes := map[string]bool{
		"http":  true,
		"https": true,
	}

	if !validSchemes[u.Scheme] {
		return errors.New("URL MUST use 'http' or 'https' as a valid scheme")
	}

	if u.Hostname() == "" {
		return errors.New("no Hostname provided")
	}

	if u.Fragment != "" {
		return errors.New("URLs MUST NOT contain a fragment")
	}

	if u.User.String() != "" {
		return errors.New("URLs MUST NOT contain a username and password")
	}

	if u.Port() != "" {
		if u.Hostname() != "localhost" {
			return errors.New("URLs MUST NOT contain a port")
		}
	}

	if net.ParseIP(u.Hostname()) != nil {
		return errors.New("hostnames MUST be domains, and MUST NOT by ipv4 or ipv6 addresses")
	}

	return nil
}

func canonicalizeURL(u *url.URL) {
	if u.Scheme == "" {
		u.Scheme = "https"
		u.Host = u.Path
		u.Path = ""
	}

	if u.Path == "" {
		u.Path = "/"
	}
}
