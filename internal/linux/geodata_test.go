package linux

import (
	"context"
	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCountryPresetProducesValidPinnedEngineConfiguration(t *testing.T) {
	b := NewBackend(nil, t.TempDir())
	routes, err := b.expandRoutes([]core.Route{{Action: "block", Kind: "domain_keyword", Values: []string{"advert"}}, {Action: "proxy", Kind: "domain_regex", Values: []string{`^video\.`}}, {Action: "direct", Kind: "geoip", Values: []string{"private", "ru"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 4 || len(routes[3].Values) < 100 {
		t.Fatal("country ranges were not expanded")
	}
	profile, err := core.ParseProfile("vless://7822b3d8-506a-401e-992c-2784c932ead0@example.com:443?security=tls")
	if err != nil {
		t.Fatal(err)
	}
	settings := core.DefaultConfig().Settings
	settings.Routes = routes
	s := core.ProxySession{Profile: profile, Address: netip.MustParseAddr("1.1.1.1"), Interface: "lo", Port: 18971, User: "probe", Password: "fixture", Tun: true, Settings: settings}
	data, err := core.CompileSingBox(s)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "box.json")
	if err = os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if output, err := Run(ctx, filepath.Join(runtimeRoot(t), "sing-box"), nil, "check", "-c", file); err != nil {
		t.Fatal(err, output)
	}
}
