package config

import (
	"time"
)

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
