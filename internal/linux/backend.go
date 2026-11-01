package linux

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"github.com/ZarpVPN/Zarp-Linux/internal/storage"
)

type Backend struct {
	bundledFingerprint string
	warpRun            func(context.Context, ...string) (string, error)
	apiProtect         func(context.Context, core.Config, func(string), func(context.Context) error) error
	registrationPause  time.Duration
	warpReadyTimeout   time.Duration
	warpReadyPause     time.Duration
	pendingCleanup     []core.Tunnel
	Runtime            *Runtime
	State              string
	mu                 sync.Mutex
	warpOwned          bool
	proxyOwned         bool
	serverMode         bool
	caps               core.Inspection
}

func NewBackend(runtime *Runtime, state string) *Backend {
	b := &Backend{Runtime: runtime, State: state}
	if runtime == nil {
		return b
	}
	b.bundledFingerprint = runtime.Fingerprint
	var reference runtimeReference
	if storage.Read(filepath.Join(state, "runtime-active.json"), &reference) == nil && reference.Base == runtime.Fingerprint && runtimeDirectory.MatchString(reference.Directory) {
		if active, err := LoadRuntime(filepath.Join(b.runtimeUpdatesDir(), reference.Directory)); err == nil {
			b.Runtime = active
		}
	}
	return b
}

func (b *Backend) SelectSource(source string) {
	b.mu.Lock()
	b.serverMode = source != "warp"
	b.mu.Unlock()
}

func (b *Backend) Inspect(ctx context.Context) (core.Inspection, error) {
	b.mu.Lock()
	fingerprint := b.Runtime.Fingerprint
	b.mu.Unlock()
	info := core.Inspection{Runtime: fingerprint, Warnings: []string{}}
	ip, err := SystemPath("ip")
	if err != nil {
		return info, err
	}
	limit, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := Run(limit, ip, nil, "-j", "route", "show", "default")
	if err != nil {
		return info, errors.New("network_routes_unavailable")
	}
	linkOutput, linkErr := Run(limit, ip, nil, "-j", "-details", "link", "show")
	if linkErr != nil {
		return info, errors.New("network_links_unavailable")
	}
	var linkDetails []struct {
		Name string `json:"ifname"`
		Info struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if json.Unmarshal([]byte(linkOutput), &linkDetails) != nil {
		return info, errors.New("network_links_invalid")
	}
	vpnKinds := map[string]bool{}
	for _, link := range linkDetails {
		switch link.Info.Kind {
		case "tun", "wireguard", "ppp", "ipip", "ip6tnl", "gre", "gretap", "ip6gre", "l2tp":
			vpnKinds[link.Name] = true
		}
	}
	var routes []struct {
		Device  string `json:"dev"`
		Gateway string `json:"gateway"`
		Metric  int    `json:"metric"`
	}
	if json.Unmarshal([]byte(out), &routes) != nil {
		return info, errors.New("network_routes_invalid")
	}
	var gateway string
	for _, r := range routes {
		if physical(r.Device) && !vpnKinds[r.Device] {
			info.Interface = r.Device
			gateway = r.Gateway
			break
		}
	}
	if info.Interface == "" {
		return info, errors.New("physical_interface_unavailable")
	}
	addresses, err := Run(limit, ip, nil, "-j", "address", "show", "dev", info.Interface)
	if err != nil {
		return info, errors.New("network_addresses_unavailable")
	}
	// Hash only stable identity fields, not counters, address lifetimes or tunnel routes.
	var links []struct {
		Address   string `json:"address"`
		Addresses []struct {
			Local  string `json:"local"`
			Family string `json:"family"`
		} `json:"addr_info"`
	}
	if json.Unmarshal([]byte(addresses), &links) != nil {
		return info, errors.New("network_addresses_invalid")
	}
	info.Network = core.Fingerprint(info.Interface, gateway, links)
	if route, routeErr := Run(limit, ip, nil, "-j", "route", "get", "1.1.1.1"); routeErr == nil {
		var selected []struct {
			Device string `json:"dev"`
		}
		if json.Unmarshal([]byte(route), &selected) == nil && len(selected) > 0 {
			dev := selected[0].Device
			b.mu.Lock()
			owned := b.warpOwned
			proxyOwned := b.proxyOwned
			b.mu.Unlock()
			if (!physical(dev) || vpnKinds[dev]) && !(proxyOwned && dev == "zarptun0") && !(owned && (strings.Contains(strings.ToLower(dev), "warp") || strings.Contains(strings.ToLower(dev), "cloudflare"))) {
				info.ForeignVPN = true
			}
		}
	} else {
		return info, errors.New("network_path_unavailable")
	}
	cli, err := SystemPath("warp-cli")
	if err == nil {
		info.WarpInstalled = true
		if version, ve := Run(limit, cli, nil, "--version"); ve == nil {
			info.WarpVersion = strings.TrimSpace(version)
		}
		if help, he := Run(limit, cli, nil, "tunnel", "masque-options", "set", "--help"); he == nil {
			info.H2 = strings.Contains(help, "h2-only")
			info.H3 = strings.Contains(help, "h3-only")
		}
		if help, he := Run(limit, cli, nil, "tunnel", "endpoint", "--help"); he == nil {
			info.Endpoint = strings.Contains(help, "set") && strings.Contains(help, "reset")
		}
		b.mu.Lock()
		owned := b.warpOwned
		b.mu.Unlock()
		if !owned {
			if status, se := Run(limit, cli, nil, "status"); se == nil && connected(status) {
				info.ForeignVPN = true
			}
		}
	}
	if _, err = SystemPath("nft"); err != nil {
		info.Warnings = append(info.Warnings, "nftables_missing")
	}
	b.mu.Lock()
	b.caps = info
	b.mu.Unlock()
	return info, nil
}

func physical(name string) bool {
	lower := strings.ToLower(name)
	if lower == "lo" || lower == "" {
		return false
	}
	for _, prefix := range []string{"tun", "tap", "wg", "ppp", "ipsec", "warp", "cloudflare", "zarp", "docker", "veth", "br-"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}

func (b *Backend) Supports(s core.Strategy) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if core.ValidateStrategy(s) != nil {
		return false
	}
	if b.serverMode {
		return s.Transport == core.TLS || s.Transport == core.QUIC || s.Transport == core.UDP
	}
	if b.caps.WarpVersion == "" {
		return s.Transport == core.TLS || s.Transport == core.QUIC
	}
	switch s.Transport {
	case core.TLS:
		return b.caps.H2
	case core.QUIC:
		return b.caps.H3
	case core.WG:
		return false
	}
	return false
}

func (b *Backend) Prepare(ctx context.Context, cfg core.Config, emit func(string)) error {
	if os.Geteuid() != 0 {
		return errors.New("system_service_requires_root")
	}
	if cfg.Settings.Source == "warp" {
		if !cfg.Settings.AcceptedTerms {
			return errors.New("warp_terms_required")
		}
		if err := checkWarpScope(ctx); err != nil {
			return err
		}
	}
	if cfg.Settings.AutoUpdateZapret {
		limit, cancel := context.WithTimeout(ctx, 8*time.Second)
		if _, err := b.CheckUpdates(limit, cfg, emit); err != nil {
			emit("update_failed_using_current_runtime")
		}
		cancel()
		if err := b.activatePending(); err != nil {
			emit("update_failed_using_current_runtime")
		}
	}
	b.mu.Lock()
	b.serverMode = cfg.Settings.Source != "warp"
	b.mu.Unlock()
	if cfg.Settings.Source != "warp" {
		return nil
	}
	if !cfg.Settings.AcceptedTerms {
		return errors.New("warp_terms_required")
	}
	if err := checkWarpScope(ctx); err != nil {
		return err
	}
	if _, err := SystemPath("warp-cli"); err != nil {
		if err = b.installWarp(ctx, cfg, emit); err != nil {
			return err
		}
	}
	systemctl, err := SystemPath("systemctl")
	if err != nil {
		return err
	}
	if _, err = Run(ctx, systemctl, nil, "start", "warp-svc.service"); err != nil {
		return errors.New("warp_service_start_failed")
	}
	if _, err = b.Inspect(ctx); err != nil {
		return err
	}
	return b.ensureRegistration(ctx, cfg, emit, nil)
}

func (b *Backend) filterPlan(ctx context.Context, targets []Target, cgroup string) (FilterPlan, error) {
	info, err := b.Inspect(ctx)
	if err != nil {
		return FilterPlan{}, err
	}
	if info.ForeignVPN {
		return FilterPlan{}, errors.New("foreign_vpn_detected")
	}
	q, err := FreeQueue()
	if err != nil {
		return FilterPlan{}, err
	}
	plan := FilterPlan{Table: "zarp_" + randomToken(8), Queue: q, Interface: info.Interface, WarpCgroup: cgroup, Targets: targets}
	if cgroup != "" {
		plan.TunnelMSS, err = warpMSS(info.Interface)
		if err != nil {
			return FilterPlan{}, err
		}
	}
	return plan, nil
}

func (b *Backend) startFilter(ctx context.Context, targets []Target, cgroup string, s core.Strategy, strict ...bool) (*Filter, error) {
	if _, err := os.Stat(filepath.Join(b.State, "filter.json")); err == nil {
		return nil, errors.New("previous_filter_requires_cleanup")
	}
	plan, err := b.filterPlan(ctx, targets, cgroup)
	if err != nil {
		return nil, err
	}
	plan.StrictTargets = len(strict) > 0 && strict[0]
	plan.ProtectAPI = cgroup != "" && !plan.StrictTargets && s.Transport == core.TLS
	return StartFilter(ctx, b.Runtime, b.State, plan, s)
}

func (b *Backend) Open(ctx context.Context, c core.Candidate, cfg core.Config, persistent bool, except string) (core.Tunnel, error) {
	if !core.Compatible(c.Strategy, c.Profile) || !b.Supports(c.Strategy) {
		return nil, errors.New("unsupported_strategy")
	}
	if c.Profile != nil {
		if persistent {
			probe, err := b.openProxy(ctx, c, cfg, false)
			if err != nil {
				return nil, err
			}
			measurement, probeErr := probe.Measure(ctx)
			cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			closeErr := probe.Close(cleanup)
			cancel()
			if closeErr != nil {
				b.rememberFailure(probe)
				return nil, errors.New("cleanup_failed")
			}
			if probeErr != nil {
				return nil, probeErr
			}
			if !measurement.Applied {
				return nil, errors.New("strategy_not_applied")
			}
		}
		return b.openProxy(ctx, c, cfg, persistent)
	}
	return b.openWarp(ctx, c, cfg, except)
}

func (b *Backend) warpCgroup(ctx context.Context) (string, error) {
	systemctl, err := SystemPath("systemctl")
	if err != nil {
		return "", err
	}
	out, err := Run(ctx, systemctl, nil, "show", "warp-svc.service", "--property=ControlGroup", "--value")
	if err != nil {
		return "", errors.New("warp_service_cgroup_unavailable")
	}
	group := strings.TrimPrefix(strings.TrimSpace(out), "/")
	if !validCgroup(group) {
		return "", errors.New("warp_service_cgroup_invalid")
	}
	return group, nil
}

func resolvePublic(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if !core.PublicIP(a) {
			return nil, errors.New("private_destination_refused")
		}
		return []netip.Addr{a}, nil
	}
	if !core.ValidHost(host) {
		return nil, errors.New("invalid_destination")
	}
	addresses, err := defaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, errors.New("dns_resolution_failed")
	}
	var result []netip.Addr
	for _, a := range addresses {
		a = a.Unmap()
		if core.PublicIP(a) {
			result = append(result, a)
		}
	}
	if len(result) == 0 || len(result) > 32 {
		return nil, errors.New("no_public_destination_addresses")
	}
	return result, nil
}
