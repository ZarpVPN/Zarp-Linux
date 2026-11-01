package linux

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
)

func TestCompatScopeCannotWidenOrInject(t *testing.T) {
	plan := FilterPlan{Table: "zarp_0123456789abcdef", WarpCgroup: "system.slice/warp-svc.service", CgroupCompat: true, ProtectAPI: true, Payload: core.TLS, Interface: "eth0", Queue: 22700, Targets: []Target{{Address: netip.MustParseAddr("1.1.1.1"), Port: 443}}}
	for _, remove := range []bool{false, true} {
		rules, err := compatRules(plan, remove)
		if err != nil || strings.Contains(rules, "-F OUTPUT") || !strings.Contains(rules, "--path system.slice/warp-svc.service") || !strings.Contains(rules, "ZARP_0123456789abcdef") {
			t.Fatal(rules, err)
		}
	}
	rules, err := NftRules(plan)
	if err != nil || strings.Contains(rules, "socket cgroupv2") || !strings.Contains(rules, "priority mangle + 1") || !strings.Contains(rules, "tcp dport 443") {
		t.Fatal(rules, err)
	}
	for _, group := range []string{"", "system.slice/warp\n-A OUTPUT -j ACCEPT", "../other", "/system.slice/warp-svc.service"} {
		plan.WarpCgroup = group
		if _, err := compatRules(plan, false); err == nil {
			t.Fatal("invalid cgroup accepted", group)
		}
	}
}

func TestNetnsCgroupCompatProtectsUnknownAPIsAndRecovers(t *testing.T) {
	runtime := requireNetns(t)
	group, err := currentCgroup()
	if err != nil {
		t.Fatal(err)
	}
	emptyGroup := "zarp_test_" + randomToken(8)
	emptyPath := "/sys/fs/cgroup/" + emptyGroup
	if err = os.Mkdir(emptyPath, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(emptyPath)
	strategy := core.Catalog()[0]
	for _, candidate := range core.Catalog() {
		if candidate.ID == "warp-t-split-host" {
			strategy = candidate
		}
	}
	for _, family := range []string{"tcp4", "tcp6"} {
		t.Run(family, func(t *testing.T) {
			address := "127.0.0.1:443"
			if family == "tcp6" {
				address = "[::1]:443"
			}
			listener, err := net.Listen(family, address)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "protected API") }))
			server.Listener.Close()
			server.Listener = listener
			server.StartTLS()
			defer server.Close()
			pool := x509.NewCertPool()
			pool.AddCert(server.Certificate())
			transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			for _, selected := range []string{emptyGroup, group} {
				state := t.TempDir()
				queue, err := FreeQueue()
				if err != nil {
					t.Fatal(err)
				}
				// The API listener is deliberately absent from the target snapshot.
				plan := FilterPlan{Table: "zarp_" + randomToken(8), Queue: queue, Interface: "lo", WarpCgroup: selected, CgroupCompat: true, ProtectAPI: true, Targets: []Target{{Address: netip.MustParseAddr("1.1.1.1"), Port: 443}}}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				filter, err := StartFilter(ctx, runtime, state, plan, strategy)
				if err != nil {
					t.Fatal(err)
				}
				response, requestErr := client.Get(server.URL)
				if requestErr != nil {
					filter.Close(context.Background())
					t.Fatal(requestErr, filter.Process.Output.String())
				}
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				if string(body) != "protected API" || filter.Applied() != (selected == group) {
					filter.Close(context.Background())
					t.Fatal("cgroup isolation or real desync evidence failed", selected, filter.Process.Output.String())
				}
				if selected == group {
					filter.Process.Stop(ctx)
					if response, err := client.Get(server.URL); err == nil {
						response.Body.Close()
						t.Fatal("API connection bypassed stopped nfqws2")
					}
					if err = RecoverFilter(ctx, state); err != nil {
						t.Fatal(err)
					}
				} else if err = filter.Close(ctx); err != nil {
					t.Fatal(err)
				}
				for _, toolName := range []string{"iptables-nft", "ip6tables-nft"} {
					tool, _ := SystemPath(toolName)
					if _, err = Run(ctx, tool, nil, "-t", "mangle", "-S", compatChain(plan)); err == nil {
						t.Fatal("owned cgroup classifier survived cleanup", toolName)
					}
				}
			}
		})
	}
}

func TestNetnsCgroupCompatPreservesTunnelRoutingMarks(t *testing.T) {
	_ = requireNetns(t)
	group, err := currentCgroup()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	plan := FilterPlan{Table: "zarp_" + randomToken(8), WarpCgroup: group, CgroupCompat: true}
	if err = installCompatScope(ctx, plan); err != nil {
		t.Fatal(err)
	}
	defer removeCompatScope(context.Background(), plan)
	nft, _ := SystemPath("nft")
	const tunnelMark = 0x100cafe
	rules := fmt.Sprintf("add table inet %s\nadd chain inet %s after { type filter hook output priority mangle + 1; policy accept; }\nadd rule inet %s after meta l4proto udp meta mark 0x%x ct mark & 0x%x != 0 counter\n", plan.Table, plan.Table, plan.Table, tunnelMark, core.SocketMark)
	if out, err := Run(ctx, nft, []byte(rules), "-f", "-"); err != nil {
		t.Fatal(err, out)
	}
	defer Run(context.Background(), nft, nil, "delete", "table", "inet", plan.Table)
	for _, family := range []string{"udp4", "udp6"} {
		address := "127.0.0.1:0"
		if family == "udp6" {
			address = "[::1]:0"
		}
		server, err := net.ListenPacket(family, address)
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		dialer := &net.Dialer{Control: func(network, address string, raw syscall.RawConn) error {
			var setErr error
			if err := raw.Control(func(fd uintptr) {
				setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, tunnelMark)
			}); err != nil {
				return err
			}
			return setErr
		}}
		client, err := dialer.DialContext(ctx, family, server.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = client.Write([]byte("routing mark probe")); err != nil {
			t.Fatal(err)
		}
		client.Close()
		server.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, err = server.ReadFrom(make([]byte, 64)); err != nil {
			t.Fatal(err)
		}
	}
	out, err := Run(ctx, nft, nil, "list", "table", "inet", plan.Table)
	if err != nil || !strings.Contains(out, "counter packets 2 ") {
		t.Fatal("cgroup classification changed the tunnel's own routing mark", err, out)
	}
}
