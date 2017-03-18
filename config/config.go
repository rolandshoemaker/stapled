package config

import (
	"crypto"
	"errors"
	"time"
)

type SupportedHashes []crypto.Hash

func (sh SupportedHashes) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var hashConf struct {
		SHA1   bool
		SHA256 bool
		SHA384 bool
		SHA512 bool
	}
	if err := unmarshal(&hashConf); err != nil {
		return err
	}
	if hashConf.SHA1 {
		sh = append(sh, crypto.SHA1)
	}
	if hashConf.SHA256 {
		sh = append(sh, crypto.SHA256)
	}
	if hashConf.SHA384 {
		sh = append(sh, crypto.SHA384)
	}
	if hashConf.SHA512 {
		sh = append(sh, crypto.SHA512)
	}
	if len(sh) == 0 {
		return errors.New("at least one supported hash must be configured")
	}

	return nil
}

type CertDefinition struct {
	Certificate            string
	ResponseName           string
	Issuer                 string
	Responders             []string
	OverrideGlobalUpstream bool `yaml:"override-global-upstream"`
}

type ConfigDuration struct {
	time.Duration
}

// UnmarshalYAML parses a golang style duration string into a time.Duration
func (d *ConfigDuration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

// Configuration holds... well the confugration data
type Configuration struct {
	Syslog struct {
		Network     string
		Addr        string
		StdoutLevel int `yaml:"stdout-level"`
	}

	HTTP struct {
		Addr string
	}

	Disk struct {
		CacheFolder string `yaml:"cache-folder"`
	}

	SupportedHashes SupportedHashes `yaml:"supported-hashes"`

	Fetcher struct {
		Timeout            ConfigDuration
		Proxies            []string
		UpstreamResponders []string `yaml:"upstream-responders"`
	}

	Definitions struct {
		CertWatchFolder string `yaml:"cert-watch-folder"`
		IssuerFolder    string `yaml:"issuer-folder"`
		Certificates    []struct {
			Certificate string
			Issuer      string
			Responders  []string
		}
	}
}
