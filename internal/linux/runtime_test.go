package linux

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
)

func runtimeRoot(t *testing.T) string {
	t.Helper()
	if root := os.Getenv("ZARP_TEST_RUNTIME"); root != "" {
		return root
	}
	root, err := filepath.Abs("../../vendor/runtime")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(root + "/nfqws2"); err != nil {
		t.Skip("prepare pinned runtime with tools/fetch-runtime.py")
	}
	return root
}
func TestAllStrategiesAcceptedByRealNfqws(t *testing.T) {
	root := runtimeRoot(t)
	for _, s := range core.Catalog() {
		t.Run(s.ID, func(t *testing.T) {
			mode := "--dry-run"
			if os.Geteuid() == 0 && os.Getenv("ZARP_NETNS_TEST") == "1" {
				mode = "--intercept=0"
			}
			args := []string{mode, "--qnum=22700", "--lua-init=@" + root + "/lua/zapret-lib.lua", "--lua-init=@" + root + "/lua/zapret-antidpi.lua", "--lua-init=@" + root + "/lua/zarp-observe.lua"}
			for _, blob := range []string{"quic_google", "quic_vk", "tls_google", "tls_vk", "tls_gosuslugi", "stun"} {
				args = append(args, "--blob="+blob+":@"+root+"/blobs/"+blob+".bin")
			}
			args = append(args, s.Args...)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			output, err := Run(ctx, root+"/nfqws2", nil, args...)
			if err != nil {
				t.Fatalf("Lua init failed: %v\n%s", err, output)
			}
		})
	}
}
func TestRealEngineConfigurationChecks(t *testing.T) {
	root := runtimeRoot(t)
	links := []string{
		"vless://7822b3d8-506a-401e-992c-2784c932ead0@example.com:443?security=tls&type=tcp",
		"vless://7822b3d8-506a-401e-992c-2784c932ead0@example.com:443?security=tls&type=ws&host=example.com&path=%2Fedge",
		"vless://7822b3d8-506a-401e-992c-2784c932ead0@example.com:443?security=tls&type=grpc&serviceName=edge",
		"vless://7822b3d8-506a-401e-992c-2784c932ead0@example.com:443?security=tls&type=httpupgrade&path=%2Fedge",
		"trojan://test-password@example.com:443?security=tls",
		"hy2://test-password@example.com:443",
		"hy2://test-password@example.com:443?obfs=salamander&obfs-password=opaque",
	}
	for _, mode := range []string{"auto", "packet-up", "stream-up", "stream-one"} {
		links = append(links, "vless://7822b3d8-506a-401e-992c-2784c932ead0@example.com:443?security=tls&type=xhttp&mode="+mode)
	}
	links = append(links, "vless://7822b3d8-506a-401e-992c-2784c932ead0@example.com:443?security=tls&type=xhttp&alpn=h3")
	for i, link := range links {
		p, err := core.ParseProfile(link)
		if err != nil {
			t.Fatal(err)
		}
		for _, tun := range []bool{false, true} {
			s := core.ProxySession{Profile: p, Address: netip.MustParseAddr("1.1.1.1"), Interface: "lo", Port: 18971, User: "probe", Password: "random-password", BridgePort: 18972, BridgeUser: "bridge", BridgePassword: "random-bridge", Tun: tun, Settings: core.DefaultConfig().Settings}
			data, err := core.CompileSingBox(s)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			file := dir + "/box.json"
			_ = os.WriteFile(file, data, 0600)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			output, err := Run(ctx, root+"/sing-box", nil, "check", "-c", file)
			cancel()
			if err != nil {
				t.Fatalf("case %d tun=%t sing-box: %v\n%s", i, tun, err, output)
			}
			if p.Network == "xhttp" {
				data, err = core.CompileXray(s)
				if err != nil {
					t.Fatal(err)
				}
				file = dir + "/xray.json"
				_ = os.WriteFile(file, data, 0600)
				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				output, err = Run(ctx, root+"/xray", nil, "run", "-test", "-c", file)
				cancel()
				if err != nil {
					t.Fatalf("case %d xray: %v\n%s", i, err, output)
				}
			}
		}
	}
}
func TestNftScopeCannotWidenOrInject(t *testing.T) {
	base := FilterPlan{Table: "zarp_0123456789abcdef", Queue: 22700, Interface: "eth0", Targets: []Target{{Address: netip.MustParseAddr("1.1.1.1"), Port: 443}}}
	rules, err := NftRules(base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rules, "bypass") || strings.Contains(rules, "flush ruleset") || !strings.Contains(rules, "ct mark") || !strings.Contains(rules, "1.1.1.1 . 443") {
		t.Fatal("unsafe filtering scope")
	}
	for _, field := range []string{"eth0\"; flush ruleset", "", "eth0\n"} {
		p := base
		p.Interface = field
		if _, err = NftRules(p); err == nil {
			t.Fatal("interface injection accepted")
		}
	}
	p := base
	p.WarpCgroup = "system.slice/warp-svc.service"
	rules, err = NftRules(p)
	if err != nil || !strings.Contains(rules, `socket cgroupv2 level 2 "system.slice/warp-svc.service"`) {
		t.Fatal("WARP traffic must be selected by the service cgroup")
	}
	p.Targets = nil
	if _, err = NftRules(p); err == nil {
		t.Fatal("empty target list must not capture everything")
	}
}
