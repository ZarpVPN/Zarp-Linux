package linux

import (
	"bytes"
	"context"
	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestNetnsQUICProfilePacketHandling(t *testing.T) {
	runtime := requireNetns(t)
	ip, _ := SystemPath("ip")
	defer Run(context.Background(), ip, nil, "link", "set", "lo", "mtu", "65536")
	for _, mtu := range []int{1500, 1280} {
		if out, err := Run(context.Background(), ip, nil, "link", "set", "lo", "mtu", strconv.Itoa(mtu)); err != nil {
			t.Fatal(out, err)
		}
		for _, index := range []int{0, 2, 5, 9, 12} {
			strategy := core.Catalog()[index]
			t.Run(strconv.Itoa(mtu)+"/"+strategy.ID, func(t *testing.T) {
				server, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				addr := server.LocalAddr().(*net.UDPAddr)
				target := Target{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(addr.Port), UDP: true}
				filter := testFilter(t, runtime, target, strategy)
				paths, err := strategyBlobPaths(runtime, FilterPlan{Interface: "lo", Targets: []Target{target}}, strategy)
				if err != nil {
					t.Fatal(err)
				}
				var expectedFake []byte
				if index == 2 || index == 5 {
					expectedFake, err = os.ReadFile(paths["quic_vk"])
					if err != nil {
						t.Fatal(err)
					}
				}
				listener := net.ListenConfig{Control: markedDialer().Control}
				client, err := listener.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				blob, err := os.ReadFile(runtime.Path("blobs/quic_google.bin"))
				if err != nil {
					t.Fatal(err)
				}
				real := append(append([]byte{}, blob...), []byte("ZARP_ORIGINAL")...)
				if _, err = client.WriteTo(real, addr); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 4096)
				receivedOriginal := false
				receivedVK := false
				_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
				for !receivedOriginal {
					n, _, readErr := server.ReadFrom(buffer)
					if readErr != nil {
						t.Fatal("original UDP packet was lost", readErr, filter.Process.Output.String())
					}
					receivedOriginal = bytes.Equal(buffer[:n], real)
					if expectedFake != nil && bytes.Equal(buffer[:n], expectedFake) {
						receivedVK = true
					}
				}
				if expectedFake != nil && !receivedVK {
					t.Fatal("VK fake was not actually emitted")
				}
				deadline := time.Now().Add(time.Second)
				for !filter.Applied() && filter.Alive() && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if !filter.Alive() || !filter.Applied() {
					t.Fatal("strategy packet handling failed", filter.Process.Output.String())
				}
			})
		}
	}
}
