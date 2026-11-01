package linux

import (
	"bytes"
	"context"
	"fmt"
	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"github.com/ZarpVPN/Zarp-Linux/internal/storage"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNetnsWarpFirewallFragmentsAndRecovery(t *testing.T) {
	runtime := requireNetns(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	nft, _ := SystemPath("nft")
	group, err := currentCgroup()
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	address := server.LocalAddr().(*net.UDPAddr)
	// Reproduce WARP's endpoint-by-port exception and deny non-initial fragments.
	rules := fmt.Sprintf("add table inet cloudflare-warp\nadd chain inet cloudflare-warp output {type filter hook output priority filter; policy accept;}\nadd rule inet cloudflare-warp output ip daddr 127.0.0.1 udp dport %d accept\nadd rule inet cloudflare-warp output ip daddr 127.0.0.1 meta l4proto udp drop\n", address.Port)
	if out, err := Run(ctx, nft, []byte(rules), "-f", "-"); err != nil {
		t.Fatal(err, out)
	}
	defer Run(context.Background(), nft, nil, "delete", "table", "inet", "cloudflare-warp")
	queue, err := FreeQueue()
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	plan := FilterPlan{Table: "zarp_" + randomToken(8), Queue: queue, Interface: "lo", WarpCgroup: group, Targets: []Target{{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(address.Port), UDP: true}}}
	filter, err := StartFilter(ctx, runtime, state, plan, core.Catalog()[9])
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Close(context.Background())
	if !filter.Plan.FragmentCompat {
		t.Fatal("fragment protection not journaled")
	}
	if err = syscall.Kill(-filter.Process.PID(), syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	listener := net.ListenConfig{Control: markedDialer().Control}
	client, err := listener.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	original, err := os.ReadFile(runtime.Path("blobs/quic_google.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.WriteTo(original, address); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	_ = server.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	if _, _, err = server.ReadFrom(buffer); err == nil {
		t.Fatal("paused listener allowed unprocessed Initial")
	}
	if err = enableWarpFragments(ctx, filter.Plan); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Kill(-filter.Process.PID(), syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := server.ReadFrom(buffer)
	if err != nil || !bytes.Equal(buffer[:n], original) {
		t.Fatal("WARP firewall lost fragmented Initial", err, filter.Process.Output.String())
	}
	end := time.Now().Add(time.Second)
	for !filter.Applied() && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	if !filter.Applied() {
		t.Fatal("fragments not emitted")
	}
	// A normal, unmarked application cannot use the nfqws-only exception.
	outsider, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", address.Port+1))
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := outsider.Write([]byte("ordinary traffic"))
	outsider.Close()
	if writeErr == nil {
		t.Fatal("compatibility exception bypassed the firewall for ordinary traffic")
	}
	if err = filter.Process.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err = RecoverFilter(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err = RecoverFilter(ctx, state); err != nil {
		t.Fatal("recovery not idempotent", err)
	}
	out, err := Run(ctx, nft, nil, "list", "chain", "inet", "cloudflare-warp", "output")
	if err != nil || strings.Contains(out, fragmentComment(filter.Plan)) || !strings.Contains(out, fmt.Sprintf("udp dport %d accept", address.Port)) {
		t.Fatal("recovery changed WARP-owned rules", err, out)
	}
	// Keep the in-memory object's cleanup idempotent after recovery.
	filter.mu.Lock()
	filter.closed = true
	filter.removed = true
	filter.mu.Unlock()
	var recovered FilterPlan
	if err = storage.Read(state+"/filter.json", &recovered); !os.IsNotExist(err) {
		t.Fatal("recovery left a journal", err)
	}
}
