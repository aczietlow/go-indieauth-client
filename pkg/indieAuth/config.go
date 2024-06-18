package indieAuth

import (
	"gopkg.in/yaml.v3"
	"os"
)

type Conf struct {
	RedirectURL string `yaml:"RedirectURL"`
	URL         string `yaml:"URL"`
}

func loadConfig(filepath string) (*Conf, error) {
	configFile, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	c := Conf{}
	err = yaml.Unmarshal(configFile, &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
