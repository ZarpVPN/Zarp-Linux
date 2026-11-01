package core

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

func Catalog() []Strategy {
	type entry struct {
		id, name  string
		transport Transport
		args      string
	}
	entries := []entry{
		{"warp-q-google6", "QUIC: fake google x6", QUIC, "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=6"},
		{"warp-q-google3", "QUIC: fake google x3", QUIC, "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=3"},
		{"warp-q-vk6", "QUIC: fake vk x6", QUIC, "--payload=quic_initial --lua-desync=fake:blob=quic_vk:repeats=6"},
		{"warp-t-multidisorder", "TLS: disorder on SNI points", TLS, "--payload=tls_client_hello --lua-desync=multidisorder:pos=1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1"},
		{"warp-q-google11", "QUIC: fake google x11", QUIC, "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=11"},
		{"warp-q-google-vk", "QUIC: google + vk", QUIC, "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=3 --lua-desync=fake:blob=quic_vk:repeats=3"},
		{"warp-t-google-md5", "TLS: fake google md5 + split", TLS, "--payload=tls_client_hello --lua-desync=fake:blob=tls_google:tcp_md5:repeats=6 --lua-desync=multisplit:pos=1,midsld"},
		{"warp-t-seqovl", "TLS: seqovl google", TLS, "--payload=tls_client_hello --lua-desync=multisplit:pos=2:seqovl=681:seqovl_pattern=tls_google"},
		{"warp-q-google-ttl", "QUIC: fake google ttl=4 x6", QUIC, "--payload=quic_initial --lua-desync=fake:blob=quic_google:ip_ttl=4:ip6_ttl=4:repeats=6"},
		{"warp-q-ipfrag8", "QUIC: IP fragmentation", QUIC, "--payload=quic_initial --lua-desync=send:dir=out:ipfrag:ipfrag_pos_udp=8 --lua-desync=drop:dir=out"},
		{"warp-t-disorder-seqovl", "TLS: disorder + seqovl", TLS, "--payload=tls_client_hello --lua-desync=multidisorder:pos=2:seqovl=1:seqovl_pattern=tls_google"},
		{"warp-t-vk-seq", "TLS: fake vk badseq + disorder", TLS, "--payload=tls_client_hello --lua-desync=fake:blob=tls_vk:tcp_seq=-3000:repeats=6 --lua-desync=multidisorder:pos=1,midsld"},
		{"warp-q-fake-ipfrag", "QUIC: fake + fragmentation", QUIC, "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=6 --lua-desync=send:dir=out:ipfrag:ipfrag_pos_udp=16 --lua-desync=drop:dir=out"},
		{"warp-t-hostfake", "TLS: hostfakesplit vk.com", TLS, "--payload=tls_client_hello --lua-desync=hostfakesplit:host=vk.com:tcp_md5"},
		{"warp-t-fake-multi", "TLS: fake gosuslugi + split", TLS, "--payload=tls_client_hello --lua-desync=fake:blob=tls_gosuslugi:tcp_ack=-66000:tcp_ts_up:repeats=6 --lua-desync=multisplit:pos=1,midsld"},
		{"warp-t-split-host", "TLS: split 1,host", TLS, "--payload=tls_client_hello --lua-desync=multisplit:pos=1,host"},
		{"warp-q-google12", "QUIC: fake google x12", QUIC, "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=12"},
		{"warp-t-split-sld", "TLS: split 1,sld", TLS, "--payload=tls_client_hello --lua-desync=multisplit:pos=1,sld"},
		{"warp-t-split-endhost", "TLS: split 1,endhost", TLS, "--payload=tls_client_hello --lua-desync=multisplit:pos=1,endhost"},
		{"udp-stun3", "UDP: fake STUN x3", UDP, "--payload=unknown --lua-desync=fake:blob=stun:repeats=3:payload=unknown"},
		{"udp-google6", "UDP: fake google x6", UDP, "--payload=unknown --lua-desync=fake:blob=quic_google:repeats=6:payload=unknown"},
	}
	result := make([]Strategy, 0, len(entries))
	for _, e := range entries {
		countries := []string{"ru", "ir", "cn"}
		if strings.Contains(e.args, "vk") || strings.Contains(e.args, "gosuslugi") {
			countries = []string{"ru"}
		}
		result = append(result, Strategy{ID: e.id, Name: e.name, Transport: e.transport, Args: strings.Fields(e.args), Countries: countries})
	}
	return result
}

var position = regexp.MustCompile(`^(?:[0-9]{1,4}|(?:sniext|host|midsld|sld|endhost)(?:[+-][0-9]{1,3})?)(?:,(?:[0-9]{1,4}|(?:sniext|host|midsld|sld|endhost)(?:[+-][0-9]{1,3})?))*$`)
var domain = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
var blobs = []string{"quic_google", "quic_vk", "tls_google", "tls_vk", "tls_gosuslugi", "stun"}

func ValidateStrategy(s Strategy) error {
	if len(s.Name) == 0 || len(s.Name) > 128 || strings.ContainsAny(s.Name, "\r\n\x00") || len(s.Args) < 2 || len(s.Args) > 12 {
		return errors.New("invalid strategy")
	}
	expected := map[Transport]string{TLS: "tls_client_hello", QUIC: "quic_initial", WG: "wireguard_initiation", UDP: "unknown"}[s.Transport]
	if expected == "" || s.Args[0] != "--payload="+expected {
		return errors.New("strategy payload does not match its transport")
	}
	for _, arg := range s.Args[1:] {
		if !strings.HasPrefix(arg, "--lua-desync=") || len(arg) > 1024 {
			return errors.New("only packet desync options are permitted")
		}
		parts := strings.Split(strings.TrimPrefix(arg, "--lua-desync="), ":")
		if !slices.Contains([]string{"fake", "multisplit", "multidisorder", "hostfakesplit", "send", "drop"}, parts[0]) {
			return errors.New("unsupported desync function")
		}
		for _, v := range parts[1:] {
			key, value, has := strings.Cut(v, "=")
			switch key {
			case "dir":
				if !has || !slices.Contains([]string{"in", "out", "any"}, value) {
					return errors.New("invalid desync direction")
				}
			case "payload":
				if !has || value != expected {
					return errors.New("desync payload must match strategy transport")
				}
			case "blob", "seqovl_pattern":
				if !has || !slices.Contains(blobs, value) {
					return errors.New("unknown blob")
				}
			case "pos":
				if !has || !position.MatchString(value) {
					return errors.New("invalid split positions")
				}
			case "host":
				if !has || !ValidHost(value) {
					return errors.New("invalid fake hostname")
				}
			case "tcp_md5", "tcp_ts_up", "ipfrag":
				if has {
					return errors.New("unexpected flag value")
				}
			case "repeats", "ip_ttl", "ip6_ttl", "seqovl", "tcp_seq", "tcp_ack", "ipfrag_pos_udp":
				n, err := strconv.Atoi(value)
				if !has || err != nil || n < -100000 || n > 100000 {
					return errors.New("invalid numeric strategy parameter")
				}
				if key == "repeats" && (n < 1 || n > 20) || (key == "ip_ttl" || key == "ip6_ttl") && (n < 1 || n > 255) || key == "seqovl" && (n < 0 || n > 2048) || key == "ipfrag_pos_udp" && (n < 8 || n > 128 || n%8 != 0) {
					return errors.New("strategy parameter exceeds limits")
				}
			default:
				return fmt.Errorf("unsupported desync parameter: %s", key)
			}
		}
	}
	for _, c := range s.Countries {
		if !slices.Contains([]string{"ru", "ir", "cn"}, c) {
			return errors.New("invalid strategy country")
		}
	}
	return nil
}

func ParseStrategies(text string) ([]Strategy, error) {
	if len(text) > 65536 {
		return nil, errors.New("strategy file exceeds 64 KiB")
	}
	var result []Strategy
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 || len(parts) > 4 {
			return nil, fmt.Errorf("line %d: expected name | transport | arguments | countries", i+1)
		}
		s := Strategy{Name: strings.TrimSpace(parts[0]), Transport: Transport(strings.TrimSpace(parts[1])), Args: strings.Fields(parts[2]), Custom: true}
		if len(parts) == 4 {
			for _, c := range strings.Split(parts[3], ",") {
				if c = strings.TrimSpace(strings.ToLower(c)); c != "" {
					s.Countries = append(s.Countries, c)
				}
			}
		}
		if err := ValidateStrategy(s); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		s.ID = "custom-" + Fingerprint(s.Name, s.Transport, s.Args)[:24]
		if !seen[s.ID] {
			result = append(result, s)
			seen[s.ID] = true
		}
		if len(result) > 128 {
			return nil, errors.New("too many custom strategies")
		}
	}
	return result, nil
}

func ValidHost(host string) bool {
	if !domain.MatchString(host) || strings.Contains(host, "..") {
		return false
	}
	for _, s := range strings.Split(host, ".") {
		if len(s) > 63 || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
			return false
		}
	}
	return true
}
