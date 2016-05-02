package config

import (
	"crypto"
	"errors"
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

type FetcherConfig struct {
	Timeout            string
	BaseBackoff        string `yaml:"base-backoff"`
	Proxies            []string
	UpstreamResponders []string `yaml:"upstream-responders"`
}

type CertificateDefinitions struct {
	CertWatchFolder string `yaml:"cert-watch-folder"`
	IssuerFolder    string `yaml:"issuer-folder"`
	Certificates    []CertDefinition
}

type Configuration struct {
	Syslog struct {
		Network     string
		Addr        string
		StdoutLevel int `yaml:"stdout-level"`
	}
	StatsAddr string `yaml:"stats-addr"`

	HTTP struct {
		Addr string
	}

	Disk struct {
		CacheFolder string `yaml:"cache-folder"`
	}

	SupportedHashes SupportedHashes `yaml:"supported-hashes"`

	Fetcher FetcherConfig

	Definitions CertificateDefinitions
}
