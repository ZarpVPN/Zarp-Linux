package core

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ParseProfile(link string) (Profile, error) {
	var p Profile
	if len(link) > 32768 {
		return p, errors.New("server link exceeds limit")
	}
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.User == nil || u.Hostname() == "" || u.Path != "" && u.Path != "/" {
		return p, errors.New("invalid server link")
	}
	p.Protocol = strings.ToLower(u.Scheme)
	if p.Protocol == "hy2" {
		p.Protocol = "hysteria2"
	}
	if !slices.Contains([]string{"vless", "trojan", "hysteria2"}, p.Protocol) {
		return p, errors.New("supported protocols: VLESS, Trojan, Hysteria2")
	}
	p.Host = strings.ToLower(u.Hostname())
	if a, e := netip.ParseAddr(p.Host); e == nil {
		if !PublicIP(a) {
			return p, errors.New("server address must be public")
		}
	} else if !ValidHost(p.Host) {
		return p, errors.New("invalid server hostname")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return p, errors.New("invalid server port")
	}
	p.Port = uint16(n)
	p.Credential = u.User.Username()
	if password, ok := u.User.Password(); ok {
		p.Credential += ":" + password
	}
	if p.Credential == "" || len(p.Credential) > 1024 || strings.ContainsAny(p.Credential, "\x00\r\n") {
		return p, errors.New("invalid server credential")
	}
	if p.Protocol == "vless" && !uuidPattern.MatchString(p.Credential) {
		return p, errors.New("invalid VLESS UUID")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return p, errors.New("invalid server parameters")
	}
	allowed := []string{"type", "security", "sni", "peer", "alpn", "path", "host", "serviceName", "fp", "flow", "pbk", "sid", "obfs", "obfs-password", "insecure", "allowInsecure", "encryption", "mode", "extra", "ech", "pcs", "x_padding_bytes", "support-x25519mlkem768"}
	for key, values := range q {
		if !slices.Contains(allowed, key) || len(values) != 1 {
			return p, errors.New("unsupported or duplicate server parameter: " + key)
		}
	}
	p.Network = q.Get("type")
	if p.Network == "" {
		p.Network = "tcp"
	}
	if !slices.Contains([]string{"tcp", "ws", "grpc", "httpupgrade", "xhttp"}, p.Network) {
		return p, errors.New("unsupported transport")
	}
	p.Security = q.Get("security")
	if p.Security == "" {
		if p.Protocol == "vless" {
			p.Security = "none"
		} else {
			p.Security = "tls"
		}
	}
	if !slices.Contains([]string{"none", "tls", "reality"}, p.Security) {
		return p, errors.New("unsupported security mode")
	}
	if p.Protocol != "vless" && (p.Security != "tls" || p.Network != "tcp") {
		return p, errors.New("unsupported protocol transport combination")
	}
	if p.Security == "none" {
		return p, errors.New("a TLS or QUIC outer connection is required for the strategy workflow")
	}
	p.SNI = q.Get("sni")
	if p.SNI == "" {
		p.SNI = q.Get("peer")
	}
	if p.SNI == "" {
		p.SNI = p.Host
	}
	if !ValidHost(p.SNI) {
		if _, e := netip.ParseAddr(p.SNI); e != nil {
			return p, errors.New("invalid TLS server name")
		}
	}
	if q.Get("alpn") != "" {
		p.ALPN = strings.Split(q.Get("alpn"), ",")
		for _, a := range p.ALPN {
			if !slices.Contains([]string{"h2", "h3", "http/1.1"}, a) {
				return p, errors.New("unsupported ALPN")
			}
		}
	}
	if p.Protocol != "hysteria2" && p.Network != "xhttp" && slices.Contains(p.ALPN, "h3") {
		return p, errors.New("HTTP/3 requires XHTTP or Hysteria2")
	}
	if p.Network == "xhttp" && slices.Contains(p.ALPN, "h3") && !slices.Equal(p.ALPN, []string{"h3"}) {
		return p, errors.New("mixed XHTTP H2/H3 ALPN cannot guarantee the selected outer strategy")
	}
	p.Path = q.Get("path")
	if p.Path == "" {
		p.Path = "/"
	}
	p.HostHeader = q.Get("host")
	p.ServiceName = q.Get("serviceName")
	p.Fingerprint = q.Get("fp")
	p.Flow = q.Get("flow")
	p.PublicKey = q.Get("pbk")
	p.ShortID = q.Get("sid")
	for _, v := range []string{p.Path, p.HostHeader, p.ServiceName, p.Fingerprint, p.Flow, p.PublicKey, p.ShortID} {
		if len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") {
			return p, errors.New("invalid transport text")
		}
	}
	if p.Flow != "" && (p.Protocol != "vless" || p.Network != "tcp" || p.Flow != "xtls-rprx-vision") {
		return p, errors.New("unsupported VLESS flow")
	}
	if q.Get("encryption") != "" && q.Get("encryption") != "none" {
		return p, errors.New("unsupported VLESS encryption")
	}
	if p.Security == "reality" {
		if p.PublicKey == "" || p.Protocol != "vless" {
			return p, errors.New("Reality public key is required")
		}
		if p.Fingerprint == "" {
			p.Fingerprint = "chrome"
		}
	}
	for _, key := range []string{"insecure", "allowInsecure"} {
		if v := q.Get(key); v != "" && v != "0" && v != "false" {
			if v != "1" && v != "true" {
				return p, errors.New("invalid TLS verification setting")
			}
			p.Insecure = true
		}
	}
	if p.Network == "xhttp" && p.Insecure {
		return p, errors.New("XHTTP requires certificate verification; use a certificate pin")
	}
	if obfs := q.Get("obfs"); obfs != "" {
		if p.Protocol != "hysteria2" || obfs != "salamander" || q.Get("obfs-password") == "" {
			return p, errors.New("unsupported UDP obfuscation")
		}
		p.ObfsPassword = q.Get("obfs-password")
	}
	if ech := q.Get("ech"); ech != "" {
		if p.Security != "tls" {
			return p, errors.New("ECH requires TLS")
		}
		b, e := decode64(ech)
		if e != nil || len(b) < 4 || len(b) > 8192 {
			return p, errors.New("invalid ECH configuration")
		}
		p.ECH = base64.StdEncoding.EncodeToString(b)
	}
	if p.Network == "xhttp" {
		p.Mode = q.Get("mode")
		if p.Mode == "" {
			p.Mode = "auto"
		}
		if !slices.Contains([]string{"auto", "packet-up", "stream-up", "stream-one"}, p.Mode) {
			return p, errors.New("unsupported XHTTP mode")
		}
		if extra := q.Get("extra"); extra != "" {
			if len(extra) > 16384 {
				return p, errors.New("XHTTP extra exceeds limit")
			}
			var m map[string]json.RawMessage
			if json.Unmarshal([]byte(extra), &m) != nil || m == nil {
				return p, errors.New("invalid XHTTP extra")
			}
			for key := range m {
				if !slices.Contains([]string{"xPaddingBytes", "noSSEHeader", "scMaxEachPostBytes", "scMinPostsIntervalMs", "scMaxBufferedPosts", "xmux"}, key) {
					return p, errors.New("unsupported XHTTP extra field: " + key)
				}
			}
			p.Extra = json.RawMessage(extra)
		}
		for _, pin := range strings.Split(q.Get("pcs"), ",") {
			if pin == "" {
				continue
			}
			pin = strings.ReplaceAll(pin, ":", "")
			if !regexp.MustCompile(`(?i)^[0-9a-f]{64}$`).MatchString(pin) {
				return p, errors.New("invalid certificate pin")
			}
			p.CertificatePins = append(p.CertificatePins, pin)
		}
	}
	p.Name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, u.Fragment)
	if len(p.Name) > 128 {
		p.Name = p.Name[:128]
	}
	if p.Name == "" {
		p.Name = strings.ToUpper(p.Protocol) + " " + p.Host
	}
	p.ID = "server-" + Fingerprint(p)[:24]
	return p, nil
}

func decode64(text string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, e := enc.DecodeString(strings.TrimSpace(text)); e == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}

func ParseSubscription(data []byte) ([]Profile, int, error) {
	if len(data) > 2*1024*1024 {
		return nil, 0, errors.New("subscription exceeds 2 MiB")
	}
	text := strings.TrimSpace(string(data))
	if !strings.Contains(text, "://") {
		if b, e := decode64(text); e == nil {
			text = string(b)
		}
	}
	if strings.HasPrefix(text, "<") || strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		return nil, 0, errors.New("subscription must contain server links")
	}
	var result []Profile
	skipped := 0
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, e := ParseProfile(line)
		if e != nil {
			skipped++
			continue
		}
		if !seen[p.ID] {
			result = append(result, p)
			seen[p.ID] = true
		}
		if len(result) > 200 {
			return nil, skipped, errors.New("subscription exceeds 200 servers")
		}
	}
	if len(result) == 0 {
		return nil, skipped, errors.New("subscription has no compatible server links")
	}
	return result, skipped, nil
}
