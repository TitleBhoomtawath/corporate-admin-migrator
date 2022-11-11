package app

import (
	"corporate-admin-migrator/app/keymaker"

	"gopkg.in/yaml.v3"
)

type (
	STSConfig struct {
		URL     string `yaml:"url"`
		KeyID   string `yaml:"keyID"`
		KeyPath string `yaml:"keyPath"`
	}
	Config struct {
		ClientID string          `yaml:"clientID"`
		STS      STSConfig       `yaml:"sts"`
		SCIM     keymaker.Config `yaml:"keymaker"`
	}
)

func NewConfig(data []byte) (Config, error) {
	conf := Config{}
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return Config{}, err
	}

	conf.SCIM.ClientID = conf.ClientID

	return conf, nil
}
