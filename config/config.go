package config

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

	Fetcher FetcherConfig

	Definitions CertificateDefinitions
}
