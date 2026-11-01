package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

const Version = "0.3.5"

type Transport string

const (
	TLS  Transport = "h2"
	QUIC Transport = "h3"
	WG   Transport = "wg"
	UDP  Transport = "udp"
)

type Strategy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Transport Transport `json:"transport"`
	Args      []string  `json:"args"`
	Countries []string  `json:"countries,omitempty"`
	Custom    bool      `json:"custom,omitempty"`
}

type Profile struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Protocol        string          `json:"protocol"`
	Host            string          `json:"host"`
	Port            uint16          `json:"port"`
	Credential      string          `json:"credential"`
	Network         string          `json:"network"`
	Security        string          `json:"security"`
	SNI             string          `json:"sni,omitempty"`
	ALPN            []string        `json:"alpn,omitempty"`
	Path            string          `json:"path,omitempty"`
	HostHeader      string          `json:"hostHeader,omitempty"`
	ServiceName     string          `json:"serviceName,omitempty"`
	Fingerprint     string          `json:"fingerprint,omitempty"`
	Flow            string          `json:"flow,omitempty"`
	PublicKey       string          `json:"publicKey,omitempty"`
	ShortID         string          `json:"shortID,omitempty"`
	ObfsPassword    string          `json:"obfsPassword,omitempty"`
	ECH             string          `json:"ech,omitempty"`
	Mode            string          `json:"mode,omitempty"`
	Extra           json.RawMessage `json:"extra,omitempty"`
	CertificatePins []string        `json:"certificatePins,omitempty"`
	Insecure        bool            `json:"insecure,omitempty"`
}

func (p Profile) Outer() Transport {
	if p.Protocol == "hysteria2" {
		if p.ObfsPassword != "" {
			return UDP
		}
		return QUIC
	}
	if p.Network == "xhttp" && slices.Equal(p.ALPN, []string{"h3"}) {
		return QUIC
	}
	return TLS
}

func Compatible(s Strategy, p *Profile) bool {
	if len(s.Args) == 0 {
		return false
	}
	if p == nil {
		return s.Transport == TLS || s.Transport == QUIC || s.Transport == WG
	}
	return s.Transport == p.Outer() && (s.Transport != TLS || p.Security == "tls" || p.Security == "reality")
}

type Source struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	URL     string    `json:"url,omitempty"`
	Servers []Profile `json:"servers"`
	Updated time.Time `json:"updated,omitempty"`
}

type Route struct {
	Invert bool     `json:"invert,omitempty"`
	Action string   `json:"action"`
	Kind   string   `json:"kind"`
	Values []string `json:"values"`
}

type Settings struct {
	Source           string   `json:"source"`
	Server           string   `json:"server,omitempty"`
	Countries        []string `json:"countries,omitempty"`
	Endpoints        []string `json:"endpoints,omitempty"`
	QuickCount       int      `json:"quickCount"`
	TimeoutSeconds   int      `json:"timeoutSeconds"`
	IPv6             bool     `json:"ipv6"`
	DNS              string   `json:"dns"`
	AcceptedTerms    bool     `json:"acceptedTerms"`
	AutoReconnect    bool     `json:"autoReconnect"`
	DisconnectOnExit bool     `json:"disconnectOnExit"`
	Language         string   `json:"language"`
	Routes           []Route  `json:"routes,omitempty"`
	Applications     []string `json:"applications,omitempty"`
	PerApp           bool     `json:"perApp"`
	IsolateTests     bool     `json:"isolateTests"`
	AutoUpdateZapret bool     `json:"autoUpdateZapret"`
}

type Result struct {
	ID          string    `json:"id"`
	Fingerprint string    `json:"fingerprint"`
	Strategy    string    `json:"strategy"`
	Server      string    `json:"server,omitempty"`
	OK          bool      `json:"ok"`
	Confirmed   bool      `json:"confirmed"`
	Independent bool      `json:"independent"`
	ConnectMS   int       `json:"connectMS"`
	LatencyMS   int       `json:"latencyMS"`
	Endpoint    string    `json:"endpoint,omitempty"`
	Error       string    `json:"error,omitempty"`
	When        time.Time `json:"when"`
}

func (r Result) Score() int {
	if !r.OK || !r.Confirmed {
		return int(^uint(0) >> 1)
	}
	return r.ConnectMS + 4*r.LatencyMS
}

type Config struct {
	Schema    int               `json:"schema"`
	Settings  Settings          `json:"settings"`
	Sources   []Source          `json:"sources"`
	Custom    []Strategy        `json:"custom,omitempty"`
	Results   map[string]Result `json:"results"`
	Selected  string            `json:"selected,omitempty"`
	Bootstrap map[string]string `json:"bootstrap,omitempty"`
}

func DefaultConfig() Config {
	return Config{Schema: 1, Settings: Settings{Source: "warp", QuickCount: 3, TimeoutSeconds: 12, IPv6: true, DNS: "1.1.1.1", AutoReconnect: true, DisconnectOnExit: true, Language: "ru", IsolateTests: true, AutoUpdateZapret: true}, Sources: []Source{}, Results: map[string]Result{}, Bootstrap: map[string]string{}}
}

func Fingerprint(values ...any) string {
	b, _ := json.Marshal(values)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func ValidateSettings(s Settings, sources []Source) error {
	if s.QuickCount < 1 || s.QuickCount > 20 || s.TimeoutSeconds < 3 || s.TimeoutSeconds > 60 {
		return errors.New("invalid search limits")
	}
	if s.Source != "warp" && !slices.ContainsFunc(sources, func(v Source) bool { return v.ID == s.Source }) {
		return errors.New("unknown source")
	}
	if !slices.Contains([]string{"ru", "en", "de", "es", "fa", "fr", "hi", "pt", "zh"}, s.Language) {
		return errors.New("unsupported interface language")
	}
	if a, err := netip.ParseAddr(s.DNS); err != nil || !PublicIP(a) {
		return errors.New("DNS must be a public IP address")
	}
	for _, c := range s.Countries {
		if !slices.Contains([]string{"ru", "ir", "cn"}, c) {
			return errors.New("invalid country filter")
		}
	}
	if len(s.Endpoints) > 64 || len(s.Routes) > 128 || len(s.Applications) > 64 {
		return errors.New("configuration limit exceeded")
	}
	for _, e := range s.Endpoints {
		a, err := netip.ParseAddrPort(e)
		if err != nil || a.Port() == 0 || !PublicIP(a.Addr()) {
			return errors.New("invalid public WARP endpoint")
		}
	}
	for _, r := range s.Routes {
		if !slices.Contains([]string{"direct", "proxy", "block"}, r.Action) || !slices.Contains([]string{"domain", "domain_suffix", "domain_keyword", "domain_regex", "geoip", "geosite", "ip_cidr"}, r.Kind) || len(r.Values) == 0 || len(r.Values) > 256 {
			return errors.New("unsupported routing rule")
		}
		for _, v := range r.Values {
			if r.Kind == "ip_cidr" {
				if _, err := netip.ParsePrefix(v); err != nil {
					return errors.New("invalid route network")
				}
			} else if r.Kind == "geoip" || r.Kind == "geosite" {
				if !regexp.MustCompile(`^[a-z0-9_.!@-]{1,100}$`).MatchString(v) {
					return errors.New("invalid geographic category")
				}
			} else if r.Kind == "domain_regex" {
				if len(v) > 4096 {
					return errors.New("route expression too long")
				}
				if _, err := regexp.Compile(v); err != nil {
					return errors.New("invalid route expression")
				}
			} else if r.Kind == "domain_keyword" {
				if v == "" || len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") {
					return errors.New("invalid domain keyword")
				}
			} else if !ValidHost(v) {
				return errors.New("invalid route domain")
			}
		}
	}
	for _, app := range s.Applications {
		if !strings.HasPrefix(app, "/") || len(app) > 4096 || strings.ContainsAny(app, "\x00\r\n") {
			return errors.New("invalid application path")
		}
	}
	if s.PerApp && len(s.Applications) == 0 {
		return errors.New("select at least one application")
	}
	if s.Source == "warp" && (s.PerApp || len(s.Routes) > 0) {
		return errors.New("routing and application selection require a custom server")
	}
	return nil
}

func PublicIP(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return false
		}
	}
	return true
}

type Candidate struct {
	Strategy Strategy
	Profile  *Profile
	Source   string
}

func (c Candidate) ID() string {
	if c.Profile != nil {
		return c.Strategy.ID + "@" + c.Profile.ID
	}
	return c.Strategy.ID
}
func (c Candidate) Name() string {
	if c.Profile != nil {
		return c.Strategy.Name + " + " + c.Profile.Name
	}
	return c.Strategy.Name
}

func Candidates(cfg Config) []Candidate {
	strategies := append(Catalog(), cfg.Custom...)
	var profiles []Profile
	if cfg.Settings.Source != "warp" {
		for _, source := range cfg.Sources {
			if source.ID == cfg.Settings.Source {
				for _, p := range source.Servers {
					if cfg.Settings.Server == "" || p.ID == cfg.Settings.Server {
						profiles = append(profiles, p)
					}
				}
			}
		}
	}
	var result []Candidate
	for _, s := range strategies {
		if len(cfg.Settings.Countries) > 0 && !slices.ContainsFunc(s.Countries, func(c string) bool { return slices.Contains(cfg.Settings.Countries, c) }) {
			continue
		}
		if cfg.Settings.Source == "warp" {
			if Compatible(s, nil) {
				result = append(result, Candidate{Strategy: s, Source: "warp"})
			}
			continue
		}
		for i := range profiles {
			if Compatible(s, &profiles[i]) {
				result = append(result, Candidate{Strategy: s, Profile: &profiles[i], Source: cfg.Settings.Source})
			}
		}
	}
	return result
}
