package linux

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
)

func requireNetns(t *testing.T) *Runtime {
	t.Helper()
	if os.Getenv("ZARP_NETNS_TEST") != "1" {
		t.Skip("requires scripts/test-netns.sh")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated root required")
	}
	current, _ := os.Readlink("/proc/self/ns/net")
	initial, _ := os.Readlink("/proc/1/ns/net")
	if current == initial {
		t.Fatal("refusing a test in the initial network namespace")
	}
	runtime, err := LoadRuntime(runtimeRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func TestNetnsAllStrategies(t *testing.T) {
	_ = requireNetns(t)
	TestAllStrategiesAcceptedByRealNfqws(t)
}

func TestNetnsOfficialUpdateLuaValidation(t *testing.T) {
	_ = requireNetns(t)
	TestOfficialUpdateCanBeStagedWithoutReplacingTheBundledRuntime(t)
}

func TestNetnsAPICgroupFilterSyntax(t *testing.T) {
	_ = requireNetns(t)
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	group := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::/") {
			group = strings.TrimPrefix(line, "0::/")
			break
		}
	}
	if group == "" {
		t.Skip("no named cgroup v2 scope")
	}
	plan := FilterPlan{Table: "zarp_" + randomToken(8), Queue: 22700, Interface: "lo", WarpCgroup: group, ProtectAPI: true, Payload: core.TLS, Targets: []Target{{Address: netip.MustParseAddr("1.1.1.1"), Port: 443}}}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	plan.CgroupCompat, err = warpScope(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := NftRules(plan)
	if err != nil {
		t.Fatal(err)
	}
	nft, _ := SystemPath("nft")
	if out, err := Run(ctx, nft, []byte(rules), "--check", "--file", "-"); err != nil {
		t.Fatal(err, out)
	}
}

func testFilter(t *testing.T, runtime *Runtime, target Target, strategy core.Strategy) *Filter {
	t.Helper()
	queue, err := FreeQueue()
	if err != nil {
		t.Fatal(err)
	}
	plan := FilterPlan{Table: "zarp_" + randomToken(8), Queue: queue, Interface: "lo", Targets: []Target{target}}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	filter, err := StartFilter(ctx, runtime, t.TempDir(), plan, strategy)
	if err != nil {
		rules, _ := NftRules(plan)
		nft, _ := SystemPath("nft")
		out, _ := Run(ctx, nft, []byte(rules), "--check", "--file", "-")
		t.Fatalf("filter start: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := filter.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return filter
}

func TestNetnsTLSDesyncAndFailClosed(t *testing.T) {
	runtime := requireNetns(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "protected request") }))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "https://")
	host, port, _ := net.SplitHostPort(address)
	number, _ := strconv.Atoi(port)
	strategy := core.Catalog()[0]
	for _, s := range core.Catalog() {
		if s.ID == "warp-t-split-host" {
			strategy = s
		}
	}
	filter := testFilter(t, runtime, Target{Address: netip.MustParseAddr(host), Port: uint16(number)}, strategy)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	transport := &http.Transport{DialContext: markedDialer().DialContext, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("TLS through nfqws2: %v\n%s", err, filter.Process.Output.String())
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "protected request" {
		t.Fatal("TLS stream was corrupted")
	}
	deadline := time.Now().Add(time.Second)
	for !filter.Applied() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !filter.Applied() {
		t.Fatalf("TLS request passed without desync evidence\n%s", filter.Process.Output.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_ = filter.Process.Stop(ctx)
	cancel()
	time.Sleep(150 * time.Millisecond)
	client.Timeout = 500 * time.Millisecond
	if response, err = client.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("managed connection continued after nfqws2 died")
	}
	unmarked := server.Client()
	unmarked.Timeout = time.Second
	if response, err = unmarked.Get(server.URL); err != nil {
		t.Fatal("filter affected an unmanaged connection")
	}
	response.Body.Close()
}

func TestNetnsQUICFakesAreActuallySent(t *testing.T) {
	runtime := requireNetns(t)
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	addr := server.LocalAddr().(*net.UDPAddr)
	strategy := core.Catalog()[1]
	filter := testFilter(t, runtime, Target{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(addr.Port), UDP: true}, strategy)
	listener := net.ListenConfig{Control: markedDialer().Control}
	client, err := listener.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// A later Initial on an existing UDP tuple must still be processed.
	buffer := make([]byte, 4096)
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	for i := 0; i < 32; i++ {
		if _, err = client.WriteTo([]byte{0x40, byte(i), 0, 0}, addr); err != nil {
			t.Fatal(err)
		}
		if _, _, err = server.ReadFrom(buffer); err != nil {
			t.Fatal(err)
		}
	}
	blob, err := os.ReadFile(runtime.Path("blobs/quic_google.bin"))
	if err != nil {
		t.Fatal(err)
	}
	real := append(append([]byte{}, blob...), []byte("ZARP_ORIGINAL")...)
	if _, err = client.WriteTo(real, addr); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	received := 0
	original := false
	for received < 4 {
		n, _, readErr := server.ReadFrom(buffer)
		if readErr != nil {
			t.Fatalf("only %d packets arrived, original=%t: %v\n%s", received, original, readErr, filter.Process.Output.String())
		}
		received++
		original = original || bytes.Equal(buffer[:n], real)
	}
	if !original {
		t.Fatal("original QUIC datagram was lost")
	}
	deadline := time.Now().Add(time.Second)
	for !filter.Applied() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !filter.Applied() {
		t.Fatal("no raw send evidence for actual fake packets")
	}
}
