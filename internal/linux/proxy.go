package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
)

func freePort() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port, nil
}

type proxyTunnel struct {
	backend   *Backend
	filter    *Filter
	session   core.ProxySession
	children  []*Child
	dir       string
	connectMS int
	mu        sync.Mutex
	closed    bool
}

func (b *Backend) openProxy(ctx context.Context, c core.Candidate, cfg core.Config, persistent bool) (core.Tunnel, error) {
	info, err := b.Inspect(ctx)
	if err != nil {
		return nil, err
	}
	addresses, err := b.resolve(ctx, c.Profile.Host, cfg, func(string) {})
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(addresses, func(a, b netip.Addr) int {
		if a.Is4() == b.Is4() {
			return 0
		}
		if a.Is4() {
			return -1
		}
		return 1
	})
	if !cfg.Settings.IPv6 {
		addresses = slices.DeleteFunc(addresses, func(a netip.Addr) bool { return a.Is6() })
	}
	if len(addresses) == 0 {
		return nil, errors.New("server_address_family_unavailable")
	}
	port, err := freePort()
	if err != nil {
		return nil, errors.New("proxy_listener_unavailable")
	}
	bridgePort := 0
	if c.Profile.Network == "xhttp" {
		bridgePort, err = freePort()
		if err != nil {
			return nil, err
		}
	}
	s := core.ProxySession{Profile: *c.Profile, Address: addresses[0], Interface: info.Interface, Port: port, User: randomToken(12), Password: randomToken(24), BridgePort: bridgePort, BridgeUser: randomToken(12), BridgePassword: randomToken(24), Tun: persistent, Settings: cfg.Settings}
	s.ProbeProcess, _ = os.Executable()
	if persistent {
		routes, routeErr := b.expandRoutes(cfg.Settings.Routes)
		if routeErr != nil {
			return nil, routeErr
		}
		s.Settings.Routes = routes
	}
	if err = os.MkdirAll(b.State+"/sessions", 0700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(b.State+"/sessions", "connection-")
	if err != nil {
		return nil, err
	}
	t := &proxyTunnel{backend: b, session: s, dir: dir}
	fail := func(reason string) (core.Tunnel, error) {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if ce := t.Close(cleanup); ce != nil {
			b.rememberFailure(t)
			return nil, ce
		}
		return nil, errors.New(reason)
	}
	if persistent {
		ip, _ := SystemPath("ip")
		if _, err = Run(ctx, ip, nil, "link", "show", "zarptun0"); err == nil {
			return fail("tun_interface_already_exists")
		}
	}
	boxConfig, err := core.CompileSingBox(s)
	if err != nil {
		return fail("server_configuration_invalid")
	}
	if err = os.WriteFile(dir+"/sing-box.json", boxConfig, 0600); err != nil {
		return fail("server_configuration_storage_failed")
	}
	if _, err = Run(ctx, b.Runtime.Path("sing-box"), nil, "check", "-c", dir+"/sing-box.json"); err != nil {
		return fail("sing_box_configuration_rejected")
	}
	if bridgePort > 0 {
		xrayConfig, ce := core.CompileXray(s)
		if ce != nil {
			return fail("xray_configuration_invalid")
		}
		if err = os.WriteFile(dir+"/xray.json", xrayConfig, 0600); err != nil {
			return fail("server_configuration_storage_failed")
		}
		if _, err = Run(ctx, b.Runtime.Path("xray"), nil, "run", "-test", "-c", dir+"/xray.json"); err != nil {
			return fail("xray_configuration_rejected")
		}
	}
	var targets []Target
	for _, a := range addresses {
		targets = append(targets, Target{Address: a, Port: c.Profile.Port, UDP: c.Profile.Outer() != core.TLS})
	}
	filter, err := b.startFilter(ctx, targets, "", c.Strategy)
	if err != nil {
		return fail(err.Error())
	}
	t.filter = filter
	started := time.Now()
	if bridgePort > 0 {
		child, ce := Start(b.Runtime.Path("xray"), "run", "-c", dir+"/xray.json")
		if ce != nil {
			return fail("xray_start_failed")
		}
		t.children = append(t.children, child)
		if err = waitPort(ctx, bridgePort, child); err != nil {
			return fail("xray_not_ready")
		}
	}
	child, err := Start(b.Runtime.Path("sing-box"), "run", "-c", dir+"/sing-box.json")
	if err != nil {
		return fail("sing_box_start_failed")
	}
	t.children = append(t.children, child)
	if err = waitPort(ctx, port, child); err != nil {
		return fail("sing_box_not_ready")
	}
	if persistent {
		b.mu.Lock()
		b.proxyOwned = true
		b.mu.Unlock()
	}
	t.connectMS = int(time.Since(started).Milliseconds())
	go t.guard()
	return t, nil
}

func waitPort(ctx context.Context, port int, child *Child) error {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if !child.Alive() {
			return errors.New("engine_stopped")
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("engine_start_timeout")
		case <-time.After(40 * time.Millisecond):
		}
	}
}
func (t *proxyTunnel) Alive() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.filter == nil || !t.filter.Alive() {
		return false
	}
	for _, c := range t.children {
		if !c.Alive() {
			return false
		}
	}
	return true
}
func (t *proxyTunnel) guard() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		if !t.Alive() {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			_ = t.Close(ctx)
			cancel()
			return
		}
	}
}
func (t *proxyTunnel) Measure(ctx context.Context) (core.Measurement, error) {
	if !t.Alive() {
		return core.Measurement{}, errors.New("proxy_engine_stopped")
	}
	m, err := measureHTTP(ctx, &t.session, false)
	m.ConnectMS = t.connectMS
	m.Endpoint = net.JoinHostPort(t.session.Address.String(), strconv.Itoa(int(t.session.Profile.Port)))
	m.Applied = t.filter.Applied()
	if err != nil {
		return m, err
	}
	if !m.Applied {
		return m, errors.New("strategy_not_applied")
	}
	if t.session.Tun {
		system, checkErr := measureHTTP(ctx, nil, false)
		if checkErr != nil {
			return m, errors.New("system_tun_https_failed")
		}
		m.LatencyMS = max(m.LatencyMS, system.LatencyMS)
	}
	m.UDP = probeUDP(ctx, t.session)
	return m, nil
}
func (t *proxyTunnel) Close(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	if t.filter != nil {
		_ = t.filter.Block(ctx)
	}
	for i := len(t.children) - 1; i >= 0; i-- {
		if err := t.children[i].Stop(ctx); err != nil {
			return errors.New("cleanup_failed")
		}
	}
	if t.filter != nil {
		if err := t.filter.Close(ctx); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(t.dir); err != nil {
		return errors.New("cleanup_failed")
	}
	t.closed = true
	if t.session.Tun {
		t.backend.mu.Lock()
		t.backend.proxyOwned = false
		t.backend.mu.Unlock()
	}
	return nil
}
