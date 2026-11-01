package core

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// DemoBackend has no system adapter and never opens a network connection.
type DemoBackend struct{ counter atomic.Uint64 }

func (*DemoBackend) ReadAccount(context.Context) (string, error) { return "demo", nil }

func (*DemoBackend) Inspect(context.Context) (Inspection, error) {
	return Inspection{Network: "demo-network", Runtime: "demo-only", Interface: "demo", WarpInstalled: true, H2: true, H3: true, Endpoint: true}, nil
}
func (*DemoBackend) Prepare(ctx context.Context, cfg Config, emit func(string)) error {
	emit("demo_no_network_changes")
	return ctx.Err()
}
func (*DemoBackend) Supports(s Strategy) bool { return ValidateStrategy(s) == nil }
func (b *DemoBackend) Open(ctx context.Context, c Candidate, cfg Config, persistent bool, except string) (Tunnel, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}
	n := b.counter.Add(1)
	return &demoTunnel{endpoint: []string{"162.159.198.1:443", "162.159.198.2:443"}[n%2]}, nil
}
func (*DemoBackend) DownloadSubscription(context.Context, string, Config, func(string)) ([]byte, error) {
	return nil, errors.New("demo_does_not_download")
}
func (*DemoBackend) ApplyLicense(context.Context, string, Config, func(string)) (string, error) {
	return "", errors.New("demo_does_not_register_accounts")
}

type demoTunnel struct {
	closed   atomic.Bool
	endpoint string
}

func (t *demoTunnel) Alive() bool                 { return !t.closed.Load() }
func (t *demoTunnel) Close(context.Context) error { t.closed.Store(true); return nil }
func (t *demoTunnel) Measure(ctx context.Context) (Measurement, error) {
	if ctx.Err() != nil {
		return Measurement{}, ctx.Err()
	}
	if t.closed.Load() {
		return Measurement{}, errors.New("demo_closed")
	}
	return Measurement{ConnectMS: 180, LatencyMS: 42, Endpoint: t.endpoint, Applied: true, UDP: true}, nil
}
