package core

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"
	"strings"
)

type Object = map[string]any

type ProxySession struct {
	Profile                    Profile
	Address                    netip.Addr
	Interface                  string
	ProbeProcess               string
	Port                       int
	User, Password             string
	BridgePort                 int
	BridgeUser, BridgePassword string
	Tun                        bool
	Settings                   Settings
}

const SocketMark = 0x10000000
const DesyncMark = 0x40000000

func CompileSingBox(s ProxySession) ([]byte, error) {
	if !s.Address.IsValid() || s.Port < 1 || s.User == "" || s.Password == "" {
		return nil, errors.New("invalid proxy session")
	}
	p := s.Profile
	var proxy Object
	if p.Network == "xhttp" {
		if s.BridgePort < 1 {
			return nil, errors.New("missing Xray bridge")
		}
		proxy = Object{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": s.BridgePort, "version": "5", "username": s.BridgeUser, "password": s.BridgePassword}
	} else {
		proxy = Object{"type": p.Protocol, "tag": "proxy", "server": s.Address.String(), "server_port": p.Port, "connect_timeout": "15s", "routing_mark": SocketMark, "bind_interface": s.Interface}
		if p.Protocol == "vless" {
			proxy["uuid"] = p.Credential
			proxy["flow"] = p.Flow
			proxy["packet_encoding"] = "xudp"
		} else {
			proxy["password"] = p.Credential
		}
		tls := Object{"enabled": true, "server_name": p.SNI, "insecure": p.Insecure}
		if len(p.ALPN) > 0 {
			tls["alpn"] = p.ALPN
		}
		if p.ECH != "" {
			b, _ := decode64(p.ECH)
			tls["ech"] = Object{"enabled": true, "config": []string{string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: b}))}}
		} else if p.Fingerprint != "" || p.Security == "reality" {
			tls["utls"] = Object{"enabled": true, "fingerprint": p.Fingerprint}
		}
		if p.Security == "reality" {
			tls["reality"] = Object{"enabled": true, "public_key": p.PublicKey, "short_id": p.ShortID}
		}
		proxy["tls"] = tls
		if p.ObfsPassword != "" {
			proxy["obfs"] = Object{"type": "salamander", "password": p.ObfsPassword}
		}
		if p.Network != "tcp" {
			t := Object{"type": p.Network}
			if p.Network == "grpc" {
				t["service_name"] = p.ServiceName
			} else {
				t["path"] = p.Path
				if p.HostHeader != "" {
					if p.Network == "ws" {
						t["headers"] = Object{"Host": p.HostHeader}
					} else {
						t["host"] = p.HostHeader
					}
				}
			}
			proxy["transport"] = t
		}
	}
	inbounds := []Object{{"type": "socks", "tag": "probe", "listen": "127.0.0.1", "listen_port": s.Port, "users": []Object{{"username": s.User, "password": s.Password}}}}
	strategy := "prefer_ipv4"
	if !s.Settings.IPv6 {
		strategy = "ipv4_only"
	}
	rules := []Object{{"inbound": []string{"probe"}, "action": "route", "outbound": "proxy"}}
	if s.Tun {
		if s.ProbeProcess != "" {
			rules = append(rules, Object{"process_path": []string{s.ProbeProcess}, "action": "route", "outbound": "proxy"})
		}
		addresses := []string{"172.29.231.1/30", "fd72:6172:7000::1/126"}
		excluded := []string{s.Address.String() + "/128"}
		if s.Address.Is4() {
			excluded = []string{s.Address.String() + "/32"}
		}
		inbounds = append(inbounds, Object{"type": "tun", "tag": "tun", "interface_name": "zarptun0", "address": addresses, "auto_route": true, "strict_route": true, "stack": "gvisor", "mtu": 1280, "route_exclude_address": excluded})
		if s.Settings.PerApp {
			rules = append(rules, Object{"process_path": s.Settings.Applications, "invert": true, "action": "route", "outbound": "direct"})
		}
		if !s.Settings.IPv6 {
			rules = append(rules, Object{"ip_version": 6, "action": "reject"})
		}
		rules = append(rules, Object{"port": 53, "action": "hijack-dns"})
		if len(s.Settings.Routes) > 0 {
			rules = append(rules, Object{"action": "sniff", "timeout": "300ms"}, Object{"action": "resolve", "strategy": strategy})
		}
		for _, r := range s.Settings.Routes {
			rule := Object{r.Kind: r.Values, "action": "route", "outbound": r.Action}
			if r.Action == "block" {
				rule = Object{r.Kind: r.Values, "action": "reject"}
			}
			if r.Invert {
				rule["invert"] = true
			}
			rules = append(rules, rule)
		}
		rules = append(rules, Object{"ip_is_private": true, "action": "route", "outbound": "direct"})
	}
	config := Object{"log": Object{"level": "error"}, "dns": Object{"servers": []Object{{"type": "local", "tag": "bootstrap"}, {"type": "udp", "tag": "remote", "server": s.Settings.DNS, "detour": "proxy"}}, "final": "remote", "strategy": strategy, "reverse_mapping": len(s.Settings.Routes) > 0}, "inbounds": inbounds, "outbounds": []Object{proxy, {"type": "direct", "tag": "direct", "bind_interface": s.Interface, "domain_resolver": "bootstrap"}}, "route": Object{"auto_detect_interface": true, "default_domain_resolver": "remote", "final": "proxy", "rules": rules}}
	return json.MarshalIndent(config, "", "  ")
}

func CompileXray(s ProxySession) ([]byte, error) {
	p := s.Profile
	if p.Network != "xhttp" || s.BridgePort < 1 || !s.Address.IsValid() {
		return nil, errors.New("invalid Xray session")
	}
	xhttp := Object{"path": p.Path, "mode": p.Mode}
	if p.HostHeader != "" {
		xhttp["host"] = p.HostHeader
	}
	if len(p.Extra) > 0 {
		xhttp["extra"] = p.Extra
	}
	stream := Object{"network": "xhttp", "security": p.Security, "xhttpSettings": xhttp, "sockopt": Object{"mark": SocketMark, "interface": s.Interface}}
	if p.Security == "tls" {
		tls := Object{"serverName": p.SNI}
		if len(p.ALPN) > 0 {
			tls["alpn"] = p.ALPN
		}
		if p.Fingerprint != "" {
			tls["fingerprint"] = p.Fingerprint
		}
		if p.ECH != "" {
			tls["echConfigList"] = p.ECH
		}
		if len(p.CertificatePins) > 0 {
			tls["pinnedPeerCertSha256"] = strings.Join(p.CertificatePins, ",")
		}
		stream["tlsSettings"] = tls
	} else if p.Security == "reality" {
		stream["realitySettings"] = Object{"serverName": p.SNI, "fingerprint": p.Fingerprint, "publicKey": p.PublicKey, "shortId": p.ShortID}
	}
	config := Object{"log": Object{"loglevel": "error", "access": "none"}, "inbounds": []Object{{"tag": "bridge", "listen": "127.0.0.1", "port": s.BridgePort, "protocol": "socks", "settings": Object{"auth": "password", "udp": true, "ip": "127.0.0.1", "users": []Object{{"user": s.BridgeUser, "pass": s.BridgePassword}}}}}, "outbounds": []Object{{"tag": "server", "protocol": "vless", "settings": Object{"vnext": []Object{{"address": s.Address.String(), "port": p.Port, "users": []Object{{"id": p.Credential, "encryption": "none"}}}}}, "streamSettings": stream}}}
	return json.MarshalIndent(config, "", "  ")
}
