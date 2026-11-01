package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

type Inspection struct {
	Network       string   `json:"network"`
	Runtime       string   `json:"runtime"`
	Interface     string   `json:"interface"`
	WarpInstalled bool     `json:"warpInstalled"`
	WarpVersion   string   `json:"warpVersion,omitempty"`
	H2            bool     `json:"h2"`
	H3            bool     `json:"h3"`
	Endpoint      bool     `json:"endpoint"`
	ForeignVPN    bool     `json:"foreignVPN"`
	Warnings      []string `json:"warnings,omitempty"`
}

type Measurement struct {
	ConnectMS int    `json:"connectMS"`
	LatencyMS int    `json:"latencyMS"`
	Endpoint  string `json:"endpoint"`
	Applied   bool   `json:"applied"`
	UDP       bool   `json:"udp"`
}

type Tunnel interface {
	Measure(context.Context) (Measurement, error)
	Close(context.Context) error
	Alive() bool
}

type Backend interface {
	Inspect(context.Context) (Inspection, error)
	Prepare(context.Context, Config, func(string)) error
	Supports(Strategy) bool
	Open(context.Context, Candidate, Config, bool, string) (Tunnel, error)
	DownloadSubscription(context.Context, string, Config, func(string)) ([]byte, error)
	ApplyLicense(context.Context, string, Config, func(string)) (string, error)
}

type Event struct {
	When    time.Time `json:"when"`
	Message string    `json:"message"`
}
type Snapshot struct {
	Version     string       `json:"version"`
	State       string       `json:"state"`
	Detail      string       `json:"detail"`
	Done        int          `json:"done"`
	Total       int          `json:"total"`
	Active      string       `json:"active,omitempty"`
	Measurement *Measurement `json:"measurement,omitempty"`
	Results     []Result     `json:"results"`
	Candidates  []Object     `json:"candidates"`
	Events      []Event      `json:"events"`
	Demo        bool         `json:"demo"`
}

type Engine struct {
	mu                      sync.Mutex
	backend                 Backend
	config                  Config
	save                    func(Config) error
	state, detail, activeID string
	done, total             int
	measurement             *Measurement
	events                  []Event
	active                  Tunnel
	busy                    bool
	disconnecting           bool
	disconnectDone          chan struct{}
	cancel                  context.CancelFunc
	finished                chan struct{}
	root                    context.Context
	shutdown                context.CancelFunc
	demo                    bool
	generation              uint64
	losses                  []time.Time
}

func NewEngine(b Backend, cfg Config, save func(Config) error, demo bool) *Engine {
	if selector, ok := b.(interface{ SelectSource(string) }); ok {
		selector.SelectSource(cfg.Settings.Source)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{backend: b, config: cfg, save: save, state: "idle", detail: "ready", root: ctx, shutdown: cancel, demo: demo}
}

func cloneConfig(cfg Config) Config { // JSON round trip keeps snapshots independent of writers.
	b, _ := json.Marshal(cfg)
	var result Config
	_ = json.Unmarshal(b, &result)
	return result
}

func (e *Engine) Config() Config { e.mu.Lock(); defer e.mu.Unlock(); return cloneConfig(e.config) }
func (e *Engine) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Snapshot{Version: Version, State: e.state, Detail: e.detail, Done: e.done, Total: e.total, Active: e.activeID, Events: append([]Event{}, e.events...), Demo: e.demo, Results: []Result{}, Candidates: []Object{}}
	if e.measurement != nil {
		m := *e.measurement
		s.Measurement = &m
	}
	for _, r := range e.config.Results {
		s.Results = append(s.Results, r)
	}
	slices.SortFunc(s.Results, func(a, b Result) int { return strings.Compare(a.ID, b.ID) })
	for _, c := range Candidates(e.config) {
		s.Candidates = append(s.Candidates, Object{"id": c.ID(), "name": c.Name(), "strategy": c.Strategy.ID, "transport": c.Strategy.Transport, "supported": e.backend.Supports(c.Strategy)})
	}
	return s
}

func (e *Engine) Inspect(ctx context.Context) (Inspection, error) { return e.backend.Inspect(ctx) }
func (e *Engine) emit(detail string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.detail = detail
	e.events = append(e.events, Event{When: time.Now().UTC(), Message: detail})
	if len(e.events) > 200 {
		e.events = append([]Event{}, e.events[len(e.events)-200:]...)
	}
}
func (e *Engine) setState(state, detail string) {
	e.mu.Lock()
	e.state = state
	e.mu.Unlock()
	e.emit(detail)
}

func (e *Engine) Update(fn func(*Config) error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.busy || e.disconnecting {
		return errors.New("disconnect before editing connection settings")
	}
	cfg := cloneConfig(e.config)
	if err := fn(&cfg); err != nil {
		return err
	}
	if err := ValidateSettings(cfg.Settings, cfg.Sources); err != nil {
		return err
	}
	if err := e.save(cfg); err != nil {
		return errors.New("settings could not be saved")
	}
	e.config = cfg
	if selector, ok := e.backend.(interface{ SelectSource(string) }); ok {
		selector.SelectSource(cfg.Settings.Source)
	}
	e.generation++
	return nil
}

func (e *Engine) Start(kind, id string, full bool) error {
	return e.start(kind, id, full, nil)
}

func (e *Engine) StartBatch(ids []string) error {
	if len(ids) == 0 || len(ids) > 128 {
		return errors.New("select up to 128 strategies")
	}
	return e.start("test", "", true, nil, ids...)
}

func (e *Engine) start(kind, id string, full bool, expected *uint64, selection ...string) error {
	e.mu.Lock()
	if expected != nil && e.generation != *expected {
		e.mu.Unlock()
		return errors.New("recovery_cancelled")
	}
	if e.busy || e.active != nil || e.disconnecting || e.state == "cleanup_failed" {
		e.mu.Unlock()
		return errors.New("another operation or connection is active")
	}
	ctx, cancel := context.WithCancel(e.root)
	e.busy = true
	e.generation++
	e.cancel = cancel
	e.finished = make(chan struct{})
	finished := e.finished
	cfg := cloneConfig(e.config)
	e.done = 0
	e.total = 0
	e.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			e.mu.Lock()
			e.busy = false
			e.cancel = nil
			close(finished)
			e.mu.Unlock()
		}()
		if err := e.run(ctx, cfg, kind, id, full, selection...); err != nil {
			if errors.Is(err, context.Canceled) {
				e.setState("idle", "cancelled")
			} else if err.Error() == "cleanup_failed" {
				e.setState("cleanup_failed", "cleanup_failed")
			} else {
				e.setState("error", err.Error())
			}
		}
	}()
	return nil
}

func (e *Engine) run(ctx context.Context, cfg Config, kind, id string, full bool, selection ...string) error {
	e.setState("preparing", "checking_system")
	inspection, err := e.backend.Inspect(ctx)
	if err != nil {
		return err
	}
	if inspection.ForeignVPN {
		return errors.New("foreign_vpn_detected")
	}
	for i, source := range cfg.Sources {
		if source.ID != cfg.Settings.Source || source.URL == "" || time.Since(source.Updated) < 12*time.Hour {
			continue
		}
		e.emit("subscription_refreshing")
		data, downloadErr := e.backend.DownloadSubscription(ctx, source.URL, cfg, e.emit)
		if downloadErr != nil {
			if len(source.Servers) == 0 {
				return downloadErr
			}
			e.emit("subscription_failed_using_cache")
			break
		}
		servers, _, parseErr := ParseSubscription(data)
		if parseErr != nil {
			if len(source.Servers) == 0 {
				return parseErr
			}
			e.emit("subscription_failed_using_cache")
			break
		}
		cfg.Sources[i].Servers = servers
		cfg.Sources[i].Updated = time.Now().UTC()
		e.mu.Lock()
		e.config.Sources = cfg.Sources
		saveErr := e.save(e.config)
		e.mu.Unlock()
		if saveErr != nil {
			return errors.New("subscription_save_failed")
		}
		break
	}
	if err = e.backend.Prepare(ctx, cfg, e.emit); err != nil {
		return err
	}
	inspection, err = e.backend.Inspect(ctx)
	if err != nil {
		return err
	}
	fingerprint := Fingerprint(inspection.Network, inspection.Runtime, cfg.Settings, cfg.Sources, cfg.Custom)
	candidates := Candidates(cfg)
	candidates = slices.DeleteFunc(candidates, func(c Candidate) bool { return !e.backend.Supports(c.Strategy) })
	if len(selection) > 0 {
		candidates = slices.DeleteFunc(candidates, func(c Candidate) bool { return !slices.Contains(selection, c.ID()) })
	}
	if id != "" {
		candidates = slices.DeleteFunc(candidates, func(c Candidate) bool { return c.ID() != id })
		cfg.Selected = id
	}
	if len(candidates) == 0 {
		return errors.New("no_compatible_strategies")
	}
	if kind == "connect" {
		ordered := append([]Candidate{}, candidates...)
		slices.SortStableFunc(ordered, func(a, b Candidate) int {
			if a.ID() == b.ID() {
				return 0
			}
			if a.ID() == cfg.Selected {
				return -1
			}
			if b.ID() == cfg.Selected {
				return 1
			}
			return cfg.Results[a.ID()].Score() - cfg.Results[b.ID()].Score()
		})
		for _, c := range ordered {
			r, ok := cfg.Results[c.ID()]
			if !ok || !r.Confirmed || !r.OK || r.Fingerprint != fingerprint {
				continue
			}
			if err = e.apply(ctx, c, cfg); err == nil {
				return nil
			}
			if err.Error() == "cleanup_failed" {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			e.emit("saved_pair_failed")
		}
	}
	if id != "" {
		candidates = slices.DeleteFunc(candidates, func(c Candidate) bool { return c.ID() != id })
		if len(candidates) == 0 {
			return errors.New("unknown_or_incompatible_candidate")
		}
	}
	e.setState("searching", "searching")
	e.mu.Lock()
	e.total = len(candidates)
	e.mu.Unlock()
	confirmed := 0
	for i, c := range candidates {
		if err = ctx.Err(); err != nil {
			return err
		}
		current, checkErr := e.backend.Inspect(ctx)
		if checkErr != nil || current.Network != inspection.Network || current.ForeignVPN {
			return errors.New("network_changed_recheck_required")
		}
		e.emit(fmt.Sprintf("testing:%d:%d:%s", i+1, len(candidates), c.Name()))
		r := Result{ID: c.ID(), Fingerprint: fingerprint, Strategy: c.Strategy.ID, When: time.Now().UTC()}
		if c.Profile != nil {
			r.Server = c.Profile.ID
		}
		first, testErr := e.test(ctx, c, cfg, "")
		if testErr == nil {
			e.emit("confirming:" + c.Name())
			except := first.Endpoint
			if !cfg.Settings.IsolateTests {
				except = ""
			}
			second, secondErr := e.test(ctx, c, cfg, except)
			if secondErr == nil {
				r.OK = true
				r.Confirmed = true
				r.ConnectMS = max(first.ConnectMS, second.ConnectMS)
				r.LatencyMS = (first.LatencyMS + second.LatencyMS) / 2
				r.Endpoint = second.Endpoint
				r.Independent = c.Profile == nil && first.Endpoint != "" && second.Endpoint != "" && first.Endpoint != second.Endpoint
				confirmed++
			} else {
				testErr = secondErr
			}
		}
		if ctx.Err() != nil {
			if testErr != nil && testErr.Error() == "cleanup_failed" {
				return testErr
			}
			return ctx.Err()
		}
		if testErr != nil {
			r.Error = testErr.Error()
		}
		if testErr != nil && testErr.Error() == "cleanup_failed" {
			return testErr
		}
		current, checkErr = e.backend.Inspect(ctx)
		if checkErr != nil || current.Network != inspection.Network || current.ForeignVPN {
			return errors.New("network_changed_recheck_required")
		}
		e.mu.Lock()
		e.config.Results[r.ID] = r
		e.done = i + 1
		cfg.Results[r.ID] = r
		saveErr := e.save(e.config)
		e.mu.Unlock()
		if saveErr != nil {
			return errors.New("results_save_failed")
		}
		if !full && confirmed >= cfg.Settings.QuickCount {
			break
		}
	}
	if kind == "test" {
		e.setState("idle", "tests_finished")
		return nil
	}
	slices.SortStableFunc(candidates, func(a, b Candidate) int { return cfg.Results[a.ID()].Score() - cfg.Results[b.ID()].Score() })
	for _, c := range candidates {
		r := cfg.Results[c.ID()]
		if !r.OK || !r.Confirmed || r.Fingerprint != fingerprint {
			continue
		}
		if err = e.apply(ctx, c, cfg); err == nil {
			return nil
		}
		if err.Error() == "cleanup_failed" {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return errors.New("no_confirmed_connection")
}

func (e *Engine) test(ctx context.Context, c Candidate, cfg Config, except string) (Measurement, error) {
	ctx, cancelTest := context.WithTimeout(ctx, time.Duration(cfg.Settings.TimeoutSeconds)*time.Second)
	defer cancelTest()
	var zero Measurement
	t, err := e.backend.Open(ctx, c, cfg, false, except)
	if err != nil {
		return zero, err
	}
	m, measureErr := t.Measure(ctx)
	cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	closeErr := t.Close(cleanup)
	cancel()
	if closeErr != nil {
		e.rememberCleanup(t, c.ID())
		return zero, errors.New("cleanup_failed")
	}
	if measureErr != nil {
		return zero, measureErr
	}
	if !m.Applied {
		return zero, errors.New("strategy_not_applied")
	}
	return m, nil
}

func (e *Engine) apply(ctx context.Context, c Candidate, cfg Config) error {
	ctx, cancelAttempt := context.WithTimeout(ctx, time.Duration(2*cfg.Settings.TimeoutSeconds+10)*time.Second)
	defer cancelAttempt()
	e.setState("connecting", "connecting:"+c.Name())
	t, err := e.backend.Open(ctx, c, cfg, true, "")
	if err != nil {
		return err
	}
	m, err := t.Measure(ctx)
	if err != nil || !m.Applied {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		ce := t.Close(cleanup)
		cancel()
		if ce != nil {
			e.rememberCleanup(t, c.ID())
			return errors.New("cleanup_failed")
		}
		if err != nil {
			return err
		}
		return errors.New("strategy_not_applied")
	}
	if ctx.Err() != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		closeErr := t.Close(cleanup)
		cancel()
		if closeErr != nil {
			e.rememberCleanup(t, c.ID())
			return errors.New("cleanup_failed")
		}
		return ctx.Err()
	}
	e.mu.Lock()
	e.config.Selected = c.ID()
	saveErr := e.save(e.config)
	if saveErr == nil {
		e.active = t
		e.activeID = c.ID()
		e.measurement = &m
	}
	e.mu.Unlock()
	if saveErr != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		ce := t.Close(cleanup)
		cancel()
		if ce != nil {
			e.rememberCleanup(t, c.ID())
			return errors.New("cleanup_failed")
		}
		return errors.New("selection_save_failed")
	}
	e.setState("connected", "connected:"+c.Name())
	go e.monitor(t, cfg)
	return nil
}

func (e *Engine) monitor(t Tunnel, cfg Config) {
	initial, _ := e.backend.Inspect(e.root)
	ticker := time.NewTicker(7 * time.Second)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-e.root.Done():
			return
		case <-ticker.C:
			e.mu.Lock()
			current := e.active == t
			generation := e.generation
			e.mu.Unlock()
			if !current {
				return
			}
			ctx, cancel := context.WithTimeout(e.root, 8*time.Second)
			info, err := e.backend.Inspect(ctx)
			if err == nil && (info.ForeignVPN || info.Network != initial.Network) {
				err = errors.New("network_changed_recheck_required")
			}
			if err == nil {
				_, err = t.Measure(ctx)
			}
			cancel()
			if t.Alive() && err == nil {
				failures = 0
				continue
			}
			failures++
			if t.Alive() && failures < 2 {
				continue
			}
			e.emit("connection_lost")
			cleanup, stop := context.WithTimeout(context.Background(), 12*time.Second)
			err = e.disconnect(cleanup, false)
			stop()
			if err != nil {
				return
			}
			if cfg.Settings.AutoReconnect {
				e.mu.Lock()
				now := time.Now()
				e.losses = slices.DeleteFunc(e.losses, func(when time.Time) bool { return now.Sub(when) > 2*time.Minute })
				e.losses = append(e.losses, now)
				losses := len(e.losses)
				e.mu.Unlock()
				if losses > 3 {
					e.setState("error", "connection_unstable_retry_manually")
					return
				}
				e.emit("reconnecting")
				select {
				case <-e.root.Done():
					return
				case <-time.After(time.Duration(losses*2) * time.Second):
				}
				_ = e.start("connect", "", false, &generation)
			}
			return
		}
	}
}

func (e *Engine) Disconnect(ctx context.Context) error {
	return e.disconnect(ctx, true)
}

func (e *Engine) disconnect(ctx context.Context, user bool) error {
	e.mu.Lock()
	if user {
		e.generation++
	}
	if e.disconnecting {
		done := e.disconnectDone
		e.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
		e.mu.Lock()
		failed := e.state == "cleanup_failed"
		e.mu.Unlock()
		if failed {
			return errors.New("cleanup_failed")
		}
		return nil
	}
	e.disconnecting = true
	e.disconnectDone = make(chan struct{})
	done := e.disconnectDone
	defer func() { e.mu.Lock(); e.disconnecting = false; close(done); e.mu.Unlock() }()
	cancel, finished, busy := e.cancel, e.finished, e.busy
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if busy {
		select {
		case <-finished:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	e.mu.Lock()
	t := e.active
	failed := e.state == "cleanup_failed"
	e.mu.Unlock()
	if t != nil {
		if err := t.Close(ctx); err != nil {
			e.setState("cleanup_failed", "cleanup_failed")
			return err
		}
	}
	if failed {
		if retry, ok := e.backend.(interface{ RetryCleanup(context.Context) error }); ok {
			if err := retry.RetryCleanup(ctx); err != nil {
				e.setState("cleanup_failed", "cleanup_failed")
				return err
			}
		} else if t == nil {
			return errors.New("cleanup_failed")
		}
	}
	e.mu.Lock()
	if e.active == t {
		e.active = nil
		e.activeID = ""
		e.measurement = nil
	}
	e.mu.Unlock()
	e.setState("idle", "disconnected")
	return nil
}

func (e *Engine) Close(ctx context.Context) error { e.shutdown(); return e.Disconnect(ctx) }

func (e *Engine) Refresh(ctx context.Context, id string) error {
	work, finish, err := e.externalWork(ctx)
	if err != nil {
		return err
	}
	defer finish()
	ctx = work
	cfg := e.Config()
	var source *Source
	for i := range cfg.Sources {
		if cfg.Sources[i].ID == id {
			source = &cfg.Sources[i]
			break
		}
	}
	if source == nil || source.URL == "" {
		return errors.New("unknown subscription")
	}
	data, err := e.backend.DownloadSubscription(ctx, source.URL, cfg, e.emit)
	if err != nil {
		e.emit("subscription_failed_using_cache")
		return err
	}
	servers, skipped, err := ParseSubscription(data)
	if err != nil {
		return err
	}
	source.Servers = servers
	source.Updated = time.Now().UTC()
	e.emit(fmt.Sprintf("subscription_updated:%d:%d", len(servers), skipped))
	e.mu.Lock()
	defer e.mu.Unlock()
	if err = e.save(cfg); err != nil {
		return errors.New("subscription_save_failed")
	}
	e.config = cfg
	return nil
}

func (e *Engine) License(ctx context.Context, key string) (string, error) {
	if !regexpLicense.MatchString(key) {
		return "", errors.New("invalid_warp_license")
	}
	work, finish, err := e.externalWork(ctx)
	if err != nil {
		return "", err
	}
	defer finish()
	ctx = work
	cfg := e.Config()
	return e.backend.ApplyLicense(ctx, key, cfg, e.emit)
}

var regexpLicense = regexp.MustCompile(`^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$`)

func (e *Engine) externalWork(parent context.Context) (context.Context, func(), error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.busy || e.active != nil || e.disconnecting || e.state == "cleanup_failed" {
		return nil, nil, errors.New("another operation or connection is active")
	}
	ctx, cancel := context.WithCancel(parent)
	e.busy = true
	e.cancel = cancel
	e.finished = make(chan struct{})
	finished := e.finished
	return ctx, func() {
		cancel()
		e.mu.Lock()
		e.busy = false
		e.cancel = nil
		close(finished)
		e.mu.Unlock()
	}, nil
}

func (e *Engine) rememberCleanup(t Tunnel, id string) {
	e.mu.Lock()
	e.active = t
	e.activeID = id
	e.measurement = nil
	e.mu.Unlock()
}
