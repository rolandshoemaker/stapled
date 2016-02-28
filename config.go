package stapled

type CertDefinition struct {
	Certificate            string
	Name                   string
	ResponseName           string
	Issuer                 string
	Serial                 string
	Responders             []string
	Proxy                  string
	OverrideGlobalUpstream bool `yaml:"override-global-upstream"`
	OverrideGlobalProxy    bool `yaml:"override-global-proxy"`
}

type FetcherConfig struct {
	Timeout            string
	BaseBackoff        string `yaml:"base-backoff"`
	Proxy              string
	UpstreamResponders []string `yaml:"upstream-responders"`
}

type CertificateDefinitions struct {
	Folder       string
	IssuerFolder string `yaml:"issuer-folder"`
	Certificates []CertDefinition
}

type Configuration struct {
	DontDieOnStaleResponse bool `yaml:"dont-die-on-stale-response"`
	DontSeedCacheFromDisk  bool `yaml:"dont-seed-cache-from-disk"`
	DontCache              bool `yaml:"dont-cache"`

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
