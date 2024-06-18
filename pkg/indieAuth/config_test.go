package indieAuth

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary file
	tmpfile, err := os.CreateTemp("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	// Write the configuration to the file
	text := []byte("RedirectURL: http://localhost:9001/redirect\nURL: http://localhost:9001/")
	if _, err := tmpfile.Write(text); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Load the configuration
	conf, err := loadConfig(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Check the configuration values
	if conf.RedirectURL != "http://localhost:9001/redirect" {
		t.Errorf("expected redirectURL to be http://localhost:9001/redirect, got %s", conf.RedirectURL)
	}
	if conf.URL != "http://localhost:9001/" {
		t.Errorf("expected URL to be http://localhost:9001/, got %s", conf.URL)
	}
}
