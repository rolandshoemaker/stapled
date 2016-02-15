package stapled

type CertDefinition struct {
	Certificate      string
	Issuer           string
	Serial           string
	Responders       []string
	OverrideUpstream bool
}

type FetcherConfig struct {
	Timeout          string
	BaseBackoff      string `yaml:"base-backoff"`
	Proxy            string
	UpstreamStapleds []string `yaml:"upstream-stapleds"`
}

type CertificateDefinition struct {
	Folder       string
	IssuerFolder string `yaml:"issuer-folder"`
	Certificates []CertDefinition
}

type Configuration struct {
	DontDieOnStaleResponse bool `yaml:"dont-die-on-stale-response"`
	DontSeedCacheFromDisk  bool `yaml:"dont-seed-cache-from-disk"`
	DontCache              bool `yaml:"dont-cache"`

	Syslog struct {
		Network string
		Addr    string
		Level   int
	}
	StatsAddr string `yaml:"stats-addr"`

	HTTP struct {
		Addr string
	}

	Disk struct {
		CacheFolder string `yaml:"cache-folder"`
	}

	Fetcher FetcherConfig

	Definitions CertificateDefinition
}
