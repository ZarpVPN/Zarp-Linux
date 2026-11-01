package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type delayedPreparationBackend struct {
	*fakeBackend
	entered   chan struct{}
	release   chan struct{}
	ready     atomic.Bool
	premature atomic.Bool
}

func (b *delayedPreparationBackend) Prepare(ctx context.Context, _ Config, _ func(string)) error {
	close(b.entered)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.release:
		b.ready.Store(true)
		return nil
	}
}

func (b *delayedPreparationBackend) Open(ctx context.Context, c Candidate, cfg Config, persistent bool, except string) (Tunnel, error) {
	if !b.ready.Load() {
		b.premature.Store(true)
	}
	return b.fakeBackend.Open(ctx, c, cfg, persistent, except)
}

func TestFirstSearchAndConnectWaitForPreparationAndCanCancel(t *testing.T) {
	for _, entry := range []struct {
		name, kind string
		full       bool
		id         string
	}{{"quick", "scan", false, ""}, {"full", "scan", true, ""}, {"connect", "connect", false, ""}, {"selected", "test", false, "warp-q-google3"}} {
		for _, cancelDuringPreparation := range []bool{false, true} {
			name := entry.name + "/ready"
			if cancelDuringPreparation {
				name = entry.name + "/cancel"
			}
			t.Run(name, func(t *testing.T) {
				b := &delayedPreparationBackend{fakeBackend: &fakeBackend{}, entered: make(chan struct{}), release: make(chan struct{})}
				cfg := DefaultConfig()
				cfg.Settings.QuickCount = 1
				e := testEngine(b, cfg)
				defer closeEngine(t, e)
				if err := e.Start(entry.kind, entry.id, entry.full); err != nil {
					t.Fatal(err)
				}
				select {
				case <-b.entered:
				case <-time.After(time.Second):
					t.Fatal("preparation not entered")
				}
				b.mu.Lock()
				opened := len(b.opens)
				b.mu.Unlock()
				if opened != 0 || b.premature.Load() {
					t.Fatal("tunnel opened before preparation")
				}
				if cancelDuringPreparation {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					if err := e.Disconnect(ctx); err != nil {
						t.Fatal(err)
					}
					waitEngine(t, e, "idle")
					b.mu.Lock()
					opened = len(b.opens)
					b.mu.Unlock()
					if opened != 0 || b.ready.Load() {
						t.Fatal("cancellation continued opening tunnels")
					}
				} else {
					close(b.release)
					expected := "connected"
					if entry.kind == "test" {
						expected = "idle"
					}
					waitEngine(t, e, expected)
					if b.premature.Load() || !b.ready.Load() {
						t.Fatal("preparation ordering violated")
					}
				}
			})
		}
	}
}
