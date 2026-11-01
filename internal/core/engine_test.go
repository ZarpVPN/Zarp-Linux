package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeBackend struct {
	mu            sync.Mutex
	opens         map[string]int
	closed        atomic.Int32
	inspectCount  int
	networkChange int
	unapplied     bool
	closeFail     bool
	block         bool
	seen          chan struct{}
}

func (b *fakeBackend) Inspect(context.Context) (Inspection, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.inspectCount++
	network := "home"
	if b.networkChange > 0 && b.inspectCount >= b.networkChange {
		network = "mobile"
	}
	return Inspection{Network: network, Runtime: "test", H2: true, H3: true}, nil
}
func (b *fakeBackend) Prepare(context.Context, Config, func(string)) error { return nil }
func (b *fakeBackend) Supports(s Strategy) bool                            { return len(s.Args) > 0 }
func (b *fakeBackend) Open(ctx context.Context, c Candidate, cfg Config, persistent bool, except string) (Tunnel, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.opens == nil {
		b.opens = map[string]int{}
	}
	b.opens[c.ID()]++
	count := b.opens[c.ID()]
	if b.seen != nil {
		select {
		case b.seen <- struct{}{}:
		default:
		}
	}
	return &fakeTunnel{backend: b, fail: c.Strategy.ID == "warp-q-google6" && count == 2, endpoint: []string{"one", "two"}[count%2]}, nil
}
func (*fakeBackend) DownloadSubscription(context.Context, string, Config, func(string)) ([]byte, error) {
	return nil, errors.New("offline")
}
func (*fakeBackend) ApplyLicense(context.Context, string, Config, func(string)) (string, error) {
	return "free", nil
}

type fakeTunnel struct {
	backend  *fakeBackend
	fail     bool
	endpoint string
	closed   atomic.Bool
}

func (t *fakeTunnel) Measure(ctx context.Context) (Measurement, error) {
	if t.backend.block {
		<-ctx.Done()
		return Measurement{}, ctx.Err()
	}
	if t.fail {
		return Measurement{}, errors.New("second_attempt_failed")
	}
	return Measurement{ConnectMS: 200, LatencyMS: 20, Endpoint: t.endpoint, Applied: !t.backend.unapplied}, nil
}
func (t *fakeTunnel) Alive() bool { return !t.closed.Load() }
func (t *fakeTunnel) Close(context.Context) error {
	if t.closed.CompareAndSwap(false, true) {
		t.backend.closed.Add(1)
	}
	if t.backend.closeFail {
		return errors.New("cleanup_failed")
	}
	return nil
}

func waitEngine(t *testing.T, e *Engine, expected string) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		state, busy := e.state, e.busy
		e.mu.Unlock()
		if state == expected && !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("state=%s, expected=%s", e.Snapshot().State, expected)
}
func testEngine(b Backend, cfg Config) *Engine {
	return NewEngine(b, cfg, func(Config) error { return nil }, false)
}
func closeEngine(t *testing.T, e *Engine) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = e.Close(ctx)
}

func TestBatchChecksEverySelectedStrategyWithoutConnecting(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Settings.QuickCount = 1
	b := &fakeBackend{}
	e := testEngine(b, cfg)
	defer closeEngine(t, e)
	candidates := Candidates(cfg)
	ids := []string{candidates[0].ID(), candidates[2].ID()}
	if err := e.StartBatch(ids); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := e.Snapshot()
		if snapshot.State == "idle" && len(snapshot.Results) == 2 {
			if snapshot.Active != "" {
				t.Fatal("batch test left a tunnel connected")
			}
			for _, result := range snapshot.Results {
				if result.ID == ids[0] {
					if result.OK || result.Error != "second_attempt_failed" {
						t.Fatal(result)
					}
				} else if result.ID != ids[1] || !result.Confirmed || !result.OK {
					t.Fatal(result)
				}
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(e.Snapshot())
}

func TestEditingNextConnectionSettingsPreservesActiveTunnel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Settings.QuickCount = 1
	b := &fakeBackend{}
	e := testEngine(b, cfg)
	defer closeEngine(t, e)
	if err := e.Start("connect", "", false); err != nil {
		t.Fatal(err)
	}
	waitEngine(t, e, "connected")
	closed := b.closed.Load()
	if err := e.Update(func(c *Config) error { c.Settings.TimeoutSeconds = 24; return nil }); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().State != "connected" || b.closed.Load() != closed || e.Config().Settings.TimeoutSeconds != 24 {
		t.Fatal("saving preferences disrupted the active tunnel")
	}
}

func TestQuickScanCountsOnlyConfirmedCandidates(t *testing.T) {
	b := &fakeBackend{}
	cfg := DefaultConfig()
	cfg.Settings.QuickCount = 1
	e := testEngine(b, cfg)
	defer closeEngine(t, e)
	if err := e.Start("scan", "", false); err != nil {
		t.Fatal(err)
	}
	waitEngine(t, e, "connected")
	saved := e.Config()
	if saved.Results["warp-q-google6"].Confirmed {
		t.Fatal("failed second check must not be confirmed")
	}
	if !saved.Results["warp-q-google3"].Confirmed {
		t.Fatal("search did not continue to the next candidate")
	}
	if e.Snapshot().Done != 2 {
		t.Fatal("quick quota must count confirmations")
	}
	if saved.Selected != "warp-q-google3" {
		t.Fatal("wrong pair selected")
	}
}
func TestNoImplicitPlainConnection(t *testing.T) {
	b := &fakeBackend{unapplied: true}
	e := testEngine(b, DefaultConfig())
	defer closeEngine(t, e)
	if err := e.Start("connect", "", false); err != nil {
		t.Fatal(err)
	}
	waitEngine(t, e, "error")
	for _, r := range e.Config().Results {
		if r.OK || r.Confirmed {
			t.Fatal("unapplied strategy passed")
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.opens) != len(Candidates(DefaultConfig())) {
		t.Fatal("all real strategies should be tested, without a direct fallback")
	}
}
func TestCancellationClosesThePendingTunnel(t *testing.T) {
	b := &fakeBackend{block: true, seen: make(chan struct{}, 1)}
	e := testEngine(b, DefaultConfig())
	defer closeEngine(t, e)
	_ = e.Start("scan", "", false)
	select {
	case <-b.seen:
	case <-time.After(time.Second):
		t.Fatal("test did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := e.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if b.closed.Load() != 1 {
		t.Fatal("cancel leaked a tunnel")
	}
	if len(e.Config().Results) != 0 {
		t.Fatal("cancellation overwrote saved results")
	}
}
func TestNetworkChangeDoesNotOverwriteResults(t *testing.T) {
	b := &fakeBackend{networkChange: 4}
	cfg := DefaultConfig()
	cfg.Results["previous"] = Result{ID: "previous", OK: true, Confirmed: true}
	e := testEngine(b, cfg)
	defer closeEngine(t, e)
	_ = e.Start("scan", "", false)
	waitEngine(t, e, "error")
	if len(e.Config().Results) != 1 || !e.Config().Results["previous"].OK {
		t.Fatal("network change overwrote previous results")
	}
}
func TestCleanupFailureStopsDiscovery(t *testing.T) {
	b := &fakeBackend{closeFail: true}
	e := testEngine(b, DefaultConfig())
	defer closeEngine(t, e)
	_ = e.Start("scan", "", false)
	waitEngine(t, e, "cleanup_failed")
	b.mu.Lock()
	count := len(b.opens)
	b.mu.Unlock()
	if count != 1 {
		t.Fatal("discovery continued after cleanup failed")
	}
	if err := e.Start("connect", "", false); err == nil {
		t.Fatal("cleanup failure must block new connections")
	}
	b.closeFail = false
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := e.Disconnect(ctx); err != nil {
		t.Fatal("failed resource was not retained for another cleanup attempt", err)
	}
	if e.Snapshot().State != "idle" {
		t.Fatal("cleanup did not return to idle")
	}
}
func TestExplicitSelectionCannotConnectADifferentCachedPair(t *testing.T) {
	b := &fakeBackend{}
	cfg := DefaultConfig()
	cfg.Settings.QuickCount = 1
	cached := Catalog()[0]
	cfg.Results[cached.ID] = Result{ID: cached.ID, OK: true, Confirmed: true, Fingerprint: Fingerprint("home", "test", cfg.Settings, cfg.Sources, cfg.Custom)}
	cfg.Selected = cached.ID
	e := testEngine(b, cfg)
	defer closeEngine(t, e)
	selected := Catalog()[1].ID
	_ = e.Start("connect", selected, false)
	waitEngine(t, e, "connected")
	if e.Config().Selected != selected {
		t.Fatal("explicit selection was ignored")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.opens[cached.ID] != 0 {
		t.Fatal("opened an unselected cached strategy")
	}
}
