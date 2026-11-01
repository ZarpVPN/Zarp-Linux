package linux

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
)

func TestNetnsRealVPNClientsUseTheOuterStrategy(t *testing.T) {
	runtime := requireNetns(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "through selected VPN") }))
	defer origin.Close()
	certificate := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certificate.Close()
	dir := t.TempDir()
	pair := certificate.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := dir+"/cert.pem", dir+"/key.pem"
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600)
	for _, protocol := range []string{"vless", "trojan", "hysteria2", "salamander"} {
		t.Run(protocol, func(t *testing.T) {
			serverPort, _ := freePort()
			probePort, _ := freePort()
			credential := "test-password"
			kind := protocol
			if protocol == "salamander" {
				kind = "hysteria2"
			}
			user := core.Object{"name": "test", "password": credential}
			if protocol == "vless" {
				credential = "7822b3d8-506a-401e-992c-2784c932ead0"
				user = core.Object{"name": "test", "uuid": credential}
			}
			inbound := core.Object{"type": kind, "listen": "127.0.0.1", "listen_port": serverPort, "users": []core.Object{user}, "tls": core.Object{"enabled": true, "certificate_path": certFile, "key_path": keyFile}}
			profile := core.Profile{Protocol: kind, Host: "127.0.0.1", Port: uint16(serverPort), Credential: credential, Network: "tcp", Security: "tls", SNI: "example.com", Insecure: true}
			if protocol == "salamander" {
				inbound["obfs"] = core.Object{"type": "salamander", "password": "obfs-test"}
				profile.ObfsPassword = "obfs-test"
			}
			serverConfig := core.Object{"log": core.Object{"level": "error"}, "inbounds": []core.Object{inbound}, "outbounds": []core.Object{{"type": "direct"}}, "route": core.Object{}}
			serverFile := dir + "/" + protocol + "-server.json"
			data, _ := json.Marshal(serverConfig)
			_ = os.WriteFile(serverFile, data, 0600)
			server, err := Start(runtime.Path("sing-box"), "run", "-c", serverFile)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Stop(context.Background())
			if kind != "hysteria2" {
				if err = waitPort(context.Background(), serverPort, server); err != nil {
					t.Fatalf("server: %v\n%s", err, server.Output.String())
				}
			} else {
				time.Sleep(100 * time.Millisecond)
				if !server.Alive() {
					t.Fatal(server.Output.String())
				}
			}
			strategy := core.Catalog()[0]
			for _, candidate := range core.Catalog() {
				if profile.Outer() == core.TLS && candidate.ID == "warp-t-split-host" || profile.Outer() == core.UDP && candidate.ID == "udp-stun3" {
					strategy = candidate
				}
			}
			filter := testFilter(t, runtime, Target{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(serverPort), UDP: profile.Outer() != core.TLS}, strategy)
			session := core.ProxySession{Profile: profile, Address: netip.MustParseAddr("127.0.0.1"), Interface: "lo", Port: probePort, User: "probe", Password: "private-test-password", Settings: core.DefaultConfig().Settings}
			data, err = core.CompileSingBox(session)
			if err != nil {
				t.Fatal(err)
			}
			clientFile := dir + "/" + protocol + "-client.json"
			_ = os.WriteFile(clientFile, data, 0600)
			child, err := Start(runtime.Path("sing-box"), "run", "-c", clientFile)
			if err != nil {
				t.Fatal(err)
			}
			defer child.Stop(context.Background())
			if err = waitPort(context.Background(), probePort, child); err != nil {
				t.Fatal(child.Output.String())
			}
			transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return socksConnect(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(probePort)), session.User, session.Password, address)
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
			response, err := client.Get(origin.URL)
			if err != nil {
				t.Fatalf("actual %s client failed: %v\nclient=%s\nserver=%s\nfilter=%s", protocol, err, child.Output.String(), server.Output.String(), filter.Process.Output.String())
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if string(body) != "through selected VPN" {
				t.Fatal("wrong backend traffic")
			}
			deadline := time.Now().Add(time.Second)
			for !filter.Applied() && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if !filter.Applied() {
				t.Fatalf("%s carried traffic without actual outer strategy evidence", protocol)
			}
		})
	}
}
