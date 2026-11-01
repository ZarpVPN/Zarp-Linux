package linux

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"github.com/ZarpVPN/Zarp-Linux/internal/storage"
)

var missingRegistration = regexp.MustCompile(`(?i)\b(?:MissingRegistration|Registration(?:Missing|NotFound)|NotRegistered|registration (?:is )?(?:missing|not found)|not registered|no (?:device )?registration(?: found| exists)?|warp-cli registration new)\b`)
var daemonFailure = regexp.MustCompile(`(?i)(\bIPC\b|communicat.*daemon|(?:cannot|unable|failed).*?(?:connect|contact).*?daemon|daemon.*(?:unavailable|not running|not responding|not ready))`)
var endpointPattern = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}|\[[0-9a-fA-F:]+\]:[0-9]{2,5}`)
var disconnectedPattern = regexp.MustCompile(`(?im)^\s*(?:Status update:\s*)?Disconnected\b`)
var accountPattern = regexp.MustCompile(`(?im)^\s*Account type:\s*(Unlimited|Limited|Free)\s*$`)

func connected(text string) bool {
	return regexp.MustCompile(`(?im)^\s*(?:Status update:\s*)?Connected\b`).MatchString(text)
}

func warpCommand(ctx context.Context, args ...string) (string, error) {
	cli, err := SystemPath("warp-cli")
	if err != nil {
		return "", err
	}
	return Run(ctx, cli, nil, append([]string{"--accept-tos"}, args...)...)
}

func (b *Backend) warpCommand(ctx context.Context, args ...string) (string, error) {
	if b.warpRun != nil {
		return b.warpRun(ctx, args...)
	}
	return warpCommand(ctx, args...)
}

func (b *Backend) waitDisconnected(ctx context.Context) error {
	limit, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		out, err := b.warpCommand(limit, "status")
		if err == nil && disconnectedPattern.MatchString(out) || err != nil && confirmedMissing(out) {
			return nil
		}
		select {
		case <-limit.Done():
			return errors.New("warp_disconnect_not_confirmed")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func tlsStrategies(cfg core.Config) []core.Strategy {
	strategies := append(core.Catalog(), cfg.Custom...)
	strategies = slices.DeleteFunc(strategies, func(s core.Strategy) bool {
		if s.Transport != core.TLS || core.ValidateStrategy(s) != nil {
			return true
		}
		return len(cfg.Settings.Countries) > 0 && !slices.ContainsFunc(s.Countries, func(c string) bool { return slices.Contains(cfg.Settings.Countries, c) })
	})
	return strategies
}

// Type=simple systemd startup does not imply that the local WARP IPC socket is
// ready. Retry only read-only IPC failures; never turn them into MissingRegistration.
func (b *Backend) readRegistration(ctx context.Context) (string, error) {
	timeout := b.warpReadyTimeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	pause := b.warpReadyPause
	if pause <= 0 {
		pause = 100 * time.Millisecond
	}
	ready, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var out string
	for {
		if ready.Err() != nil {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			return out, errors.New("warp_service_not_ready")
		}
		attempt, stop := context.WithTimeout(ready, 2*time.Second)
		text, err := b.warpCommand(attempt, "registration", "show")
		stop()
		out = text
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if err == nil || confirmedMissing(out) || (!daemonFailure.MatchString(out) && !errors.Is(err, context.DeadlineExceeded)) {
			return out, err
		}
		select {
		case <-ready.Done():
		case <-time.After(pause):
		}
	}
}

func (b *Backend) ensureRegistration(ctx context.Context, cfg core.Config, emit func(string), after func(context.Context) error) error {
	warpCommand := b.warpCommand
	if !cfg.Settings.AcceptedTerms {
		return errors.New("warp_terms_required")
	}
	out, err := b.readRegistration(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		_ = os.Remove(b.State + "/registration-pending.json")
		if after != nil {
			return b.withAPIProtection(ctx, cfg, emit, after)
		}
		return nil
	}
	if !confirmedMissing(out) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil && err.Error() == "warp_service_not_ready" {
			return err
		}
		return errors.New("warp_registration_status_unavailable")
	}
	var pending struct {
		When time.Time `json:"when"`
	}
	pendingPath := b.State + "/registration-pending.json"
	if err = storage.Read(pendingPath, &pending); err == nil {
		return errors.New("warp_registration_pending_check_service")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("warp_registration_journal_invalid")
	}
	return b.withAPIProtection(ctx, cfg, emit, func(call context.Context) error {
		// Re-read before every creation. A timed-out request can have succeeded remotely.
		out, err := b.readRegistration(call)
		if call.Err() != nil {
			return call.Err()
		}
		if err == nil {
			_ = os.Remove(pendingPath)
			if after != nil {
				return after(call)
			}
			return nil
		}
		if !confirmedMissing(out) {
			return errors.New("warp_registration_status_unavailable")
		}
		if err = storage.Write(pendingPath, struct {
			When time.Time `json:"when"`
		}{When: time.Now().UTC()}); err != nil {
			return errors.New("warp_registration_journal_failed")
		}
		emit("warp_registering_protected")
		out, createdErr := warpCommand(call, "registration", "new")
		for i := 0; i < 3; i++ {
			read, readErr := b.readRegistration(call)
			if readErr == nil {
				_ = os.Remove(pendingPath)
				emit("warp_registration_ready")
				if after != nil {
					return after(call)
				}
				return nil
			}
			if !confirmedMissing(read) {
				return errors.New("warp_registration_pending_check_service")
			}
			select {
			case <-call.Done():
				return call.Err()
			case <-time.After(func() time.Duration {
				if b.registrationPause > 0 {
					return b.registrationPause
				}
				return time.Second
			}()):
			}
		}
		if strings.Contains(out, "429") {
			_ = os.Remove(pendingPath)
			return errors.New("warp_registration_rate_limited")
		}
		if createdErr == nil || call.Err() != nil || strings.Contains(strings.ToLower(out), "old registration") || strings.Contains(strings.ToLower(out), "timeout") || strings.Contains(strings.ToLower(out), "timed out") {
			return errors.New("warp_registration_pending_check_service")
		}
		_ = os.Remove(pendingPath)
		return errors.New("warp_registration_network_error")
	})
}

func confirmedMissing(out string) bool {
	return !daemonFailure.MatchString(out) && missingRegistration.MatchString(out)
}

func apiHostname(version string) string {
	match := regexp.MustCompile(`\b([0-9]{4})\.([0-9]{1,2})\.[0-9]+`).FindStringSubmatch(version)
	if len(match) == 3 {
		year, _ := strconv.Atoi(match[1])
		month, _ := strconv.Atoi(match[2])
		if year > 2026 || year == 2026 && month >= 6 {
			return "api.devices.cloudflare.com"
		}
	}
	return "api.cloudflareclient.com"
}

func (b *Backend) withAPIProtection(ctx context.Context, cfg core.Config, emit func(string), call func(context.Context) error) error {
	if b.apiProtect != nil {
		return b.apiProtect(ctx, cfg, emit, call)
	}
	cgroup, err := b.warpCgroup(ctx)
	if err != nil {
		return err
	}
	addresses := []netip.Addr{netip.MustParseAddr("162.159.137.105"), netip.MustParseAddr("162.159.138.105"), netip.MustParseAddr("2606:4700:7::a29f:8969"), netip.MustParseAddr("2606:4700:7::a29f:8a69")}
	for _, host := range []string{"api.cloudflareclient.com", "api.devices.cloudflare.com", "zero-trust-client.cloudflareclient.com", "notifications.cloudflareclient.com"} {
		limit, cancel := context.WithTimeout(ctx, 2*time.Second)
		found, _ := resolvePublic(limit, host)
		cancel()
		addresses = append(addresses, found...)
	}
	var targets []Target
	for _, a := range addresses {
		targets = append(targets, Target{Address: a, Port: 443})
	}
	strategies := tlsStrategies(cfg)
	if len(strategies) == 0 {
		return errors.New("no_registration_tls_strategies")
	}
	for _, s := range strategies {
		emit("registration_strategy:" + s.Name)
		filter, filterErr := b.startFilter(ctx, targets, cgroup, s)
		if filterErr != nil {
			return filterErr
		}
		// Find reachability with a read-only request before creating any device.
		b.mu.Lock()
		version := b.caps.WarpVersion
		b.mu.Unlock()
		host := apiHostname(version)
		probeCtx, probeCancel := context.WithTimeout(ctx, 10*time.Second)
		_, probeStatus, _ := fetchAt(probeCtx, "https://"+host+"/", addresses, 65536, true)
		probeCancel()
		if probeStatus < 200 || probeStatus > 599 || probeStatus == 429 || !filter.Applied() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			closeErr := filter.Close(cleanup)
			stop()
			if closeErr != nil {
				return errors.New("cleanup_failed")
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if probeStatus == 429 {
				return errors.New("warp_registration_rate_limited")
			}
			continue
		}
		limit, cancel := context.WithTimeout(ctx, 50*time.Second)
		err = call(limit)
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := filter.Close(cleanup)
		stop()
		if closeErr != nil {
			return errors.New("cleanup_failed")
		}
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err.Error() != "warp_registration_network_error" {
			return err
		}
	}
	return errors.New("warp_registration_strategies_exhausted")
}

func (b *Backend) ApplyLicense(ctx context.Context, key string, cfg core.Config, emit func(string)) (string, error) {
	warpCommand := b.warpCommand
	if cfg.Settings.Source != "warp" {
		return "", errors.New("select_warp_before_account_changes")
	}
	if err := b.Prepare(ctx, cfg, emit); err != nil {
		return "", err
	}
	account := "unknown"
	err := b.ensureRegistration(ctx, cfg, emit, func(call context.Context) error {
		if _, err := warpCommand(call, "registration", "license", key); err != nil {
			return errors.New("warp_license_rejected")
		}
		out, err := warpCommand(call, "registration", "show")
		if err != nil {
			return errors.New("warp_account_status_unavailable")
		}
		if match := accountPattern.FindStringSubmatch(out); len(match) == 2 {
			account = strings.ToLower(match[1])
		}
		return nil
	})
	return account, err
}

type WarpLease struct {
	Owned           bool   `json:"owned"`
	EndpointChanged bool   `json:"endpointChanged"`
	OldProtocol     string `json:"oldProtocol"`
	OldOptions      string `json:"oldOptions"`
}
type warpTunnel struct {
	cgroupPath  string
	cgroupInode uint64
	backend     *Backend
	filter      *Filter
	lease       WarpLease
	endpoint    string
	connectMS   int
	mu          sync.Mutex
	closed      bool
}

func (b *Backend) openWarp(ctx context.Context, c core.Candidate, cfg core.Config, except string) (core.Tunnel, error) {
	warpCommand := b.warpCommand
	cgroup, err := b.warpCgroup(ctx)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	caps := b.caps
	b.mu.Unlock()
	if len(cfg.Settings.Endpoints) > 0 && !caps.Endpoint {
		return nil, errors.New("warp_endpoint_control_unsupported")
	}
	endpoints := cfg.Settings.Endpoints
	if len(endpoints) == 0 && caps.Endpoint {
		if c.Strategy.Transport == core.TLS {
			// The .1 entry is H3-only and presents a different certificate.
			// H2 uses the MASQUE TCP entries, with consumer WARP first.
			// https://xtls.github.io/en/document/level-2/warp.html
			endpoints = []string{"162.159.198.2:443", "162.159.198.10:443", "162.159.197.2:443"}
		} else {
			endpoints = []string{"162.159.198.1:443", "162.159.198.2:443", "162.159.197.1:443", "162.159.198.1:8443"}
		}
	}
	endpoint := ""
	if len(endpoints) > 0 {
		endpoint = endpoints[0]
		for _, candidate := range endpoints {
			if candidate != except {
				endpoint = candidate
				break
			}
		}
		if except == "" {
			if saved, ok := cfg.Results[c.ID()]; ok && saved.OK && slices.Contains(endpoints, saved.Endpoint) {
				endpoint = saved.Endpoint
			}
		}
	}
	var targets []Target
	if endpoint != "" {
		a := netip.MustParseAddrPort(endpoint)
		targets = []Target{{Address: a.Addr(), Port: a.Port(), UDP: c.Strategy.Transport == core.QUIC}}
	} else {
		// Without endpoint control, cover published consumer ingress ranges and fallbacks.
		for _, subnet := range []string{"162.159.197.0/24", "162.159.198.0/24"} {
			prefix := netip.MustParsePrefix(subnet)
			for a := prefix.Addr(); prefix.Contains(a); a = a.Next() {
				for _, port := range []uint16{443, 500, 1701, 4500, 4443, 8443, 8095} {
					if c.Strategy.Transport == core.TLS && port != 443 {
						continue
					}
					targets = append(targets, Target{Address: a, Port: port, UDP: c.Strategy.Transport == core.QUIC})
				}
			}
		}
		return nil, errors.New("warp_endpoint_control_required_for_scoped_bypass")
	}
	filter, err := b.startFilter(ctx, targets, cgroup, c.Strategy, true)
	if err != nil {
		return nil, err
	}
	lease := WarpLease{Owned: true, EndpointChanged: endpoint != ""}
	if err = storage.Write(b.State+"/warp-lease.json", lease); err != nil {
		_ = filter.Close(context.Background())
		return nil, errors.New("warp_lease_save_failed")
	}
	b.mu.Lock()
	b.warpOwned = true
	b.mu.Unlock()
	t := &warpTunnel{backend: b, filter: filter, lease: lease, endpoint: endpoint}
	t.cgroupPath = "/sys/fs/cgroup/" + cgroup
	if stat, se := os.Stat(t.cgroupPath); se == nil {
		if raw, ok := stat.Sys().(*syscall.Stat_t); ok {
			t.cgroupInode = raw.Ino
		}
	}
	fail := func(reason string) (core.Tunnel, error) {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if ce := t.Close(cleanup); ce != nil {
			b.rememberFailure(t)
			return nil, ce
		}
		return nil, errors.New(reason)
	}
	// The packet filter is installed before any operation that can trigger a dial.
	if _, err = warpCommand(ctx, "disconnect"); err != nil {
		return fail("warp_disconnect_failed")
	}
	if err = b.waitDisconnected(ctx); err != nil {
		return fail(err.Error())
	}
	if _, err = warpCommand(ctx, "mode", "warp+doh"); err != nil {
		return fail("warp_mode_failed")
	}
	if _, err = warpCommand(ctx, "tunnel", "protocol", "set", "MASQUE"); err != nil {
		return fail("warp_protocol_failed")
	}
	option := "h3-only"
	if c.Strategy.Transport == core.TLS {
		option = "h2-only"
	}
	if _, err = warpCommand(ctx, "tunnel", "masque-options", "set", option); err != nil {
		return fail("warp_transport_failed")
	}
	if endpoint != "" {
		if _, err = warpCommand(ctx, "tunnel", "endpoint", "set", endpoint); err != nil {
			return fail("warp_endpoint_failed")
		}
	}
	started := time.Now()
	if filter.Plan.FragmentCompat {
		if err = syscall.Kill(-filter.Process.PID(), syscall.SIGSTOP); err != nil {
			return fail("warp_fragment_pause_failed")
		}
	}
	if _, err = warpCommand(ctx, "connect"); err != nil {
		return fail("warp_connect_failed")
	}
	if filter.Plan.FragmentCompat {
		if err = enableWarpFragments(ctx, filter.Plan); err != nil {
			return fail(err.Error())
		}
		if err = syscall.Kill(-filter.Process.PID(), syscall.SIGCONT); err != nil {
			return fail("warp_fragment_resume_failed")
		}
	}
	limit, cancel := context.WithTimeout(ctx, time.Duration(cfg.Settings.TimeoutSeconds)*time.Second)
	defer cancel()
	for {
		if !t.Alive() {
			return fail(t.filter.Failure())
		}
		status, statusErr := warpCommand(limit, "status")
		if statusErr == nil && connected(status) {
			t.connectMS = int(time.Since(started).Milliseconds())
			break
		}
		select {
		case <-limit.Done():
			return fail("warp_connect_timeout")
		case <-time.After(300 * time.Millisecond):
		}
	}
	go t.guard()
	return t, nil
}

func (t *warpTunnel) Alive() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !t.filter.Alive() || t.cgroupInode == 0 {
		return false
	}
	stat, err := os.Stat(t.cgroupPath)
	if err != nil {
		return false
	}
	raw, ok := stat.Sys().(*syscall.Stat_t)
	return ok && raw.Ino == t.cgroupInode
}

func (t *warpTunnel) guard() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		if !t.Alive() {
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			_ = t.Close(ctx)
			cancel()
			return
		}
	}
}
func (t *warpTunnel) Measure(ctx context.Context) (core.Measurement, error) {
	if !t.Alive() {
		return core.Measurement{}, errors.New(t.filter.Failure())
	}
	m, err := measureHTTP(ctx, nil, true)
	m.ConnectMS = t.connectMS
	m.Endpoint = t.endpoint
	m.Applied = t.filter.Applied()
	if err != nil {
		return m, err
	}
	if !m.Applied {
		return m, errors.New("strategy_not_applied")
	}
	return m, nil
}
func (t *warpTunnel) Close(ctx context.Context) error {
	warpCommand := t.backend.warpCommand
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	_ = t.filter.Block(ctx)
	if _, err := warpCommand(ctx, "disconnect"); err != nil {
		return errors.New("cleanup_failed")
	}
	if err := t.backend.waitDisconnected(ctx); err != nil {
		return errors.New("cleanup_failed")
	}
	if t.lease.EndpointChanged {
		if _, err := warpCommand(ctx, "tunnel", "endpoint", "reset"); err != nil {
			return errors.New("cleanup_failed")
		}
	}
	if _, err := warpCommand(ctx, "tunnel", "masque-options", "reset"); err != nil {
		return errors.New("cleanup_failed")
	}
	if err := t.filter.Close(ctx); err != nil {
		return errors.New("cleanup_failed")
	}
	t.closed = true
	t.backend.mu.Lock()
	t.backend.warpOwned = false
	t.backend.mu.Unlock()
	_ = os.Remove(t.backend.State + "/warp-lease.json")
	return nil
}
