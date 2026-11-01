package linux

import (
	"context"
	"errors"
	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"os"

	"github.com/ZarpVPN/Zarp-Linux/internal/storage"
)

func (b *Backend) rememberFailure(t core.Tunnel) {
	b.mu.Lock()
	b.pendingCleanup = append(b.pendingCleanup, t)
	b.mu.Unlock()
}
func (b *Backend) RetryCleanup(ctx context.Context) error {
	b.mu.Lock()
	pending := append([]core.Tunnel{}, b.pendingCleanup...)
	b.mu.Unlock()
	for _, t := range pending {
		if err := t.Close(ctx); err != nil {
			return errors.New("cleanup_failed")
		}
	}
	b.mu.Lock()
	b.pendingCleanup = nil
	b.mu.Unlock()
	return b.Recover(ctx)
}

// Recovery only acts on resources recorded in the root-owned private journal.
func (b *Backend) Recover(ctx context.Context) error {
	var lease WarpLease
	if err := storage.Read(b.State+"/warp-lease.json", &lease); err == nil {
		if !lease.Owned {
			return errors.New("warp_lease_invalid")
		}
		var plan FilterPlan
		if err = storage.Read(b.State+"/filter.json", &plan); err == nil && tableID.MatchString(plan.Table) {
			filter := &Filter{Plan: plan}
			_ = filter.Block(ctx)
		}
		if _, err = warpCommand(ctx, "disconnect"); err != nil {
			return errors.New("owned_warp_recovery_failed")
		}
		if err = b.waitDisconnected(ctx); err != nil {
			return errors.New("owned_warp_recovery_failed")
		}
		if lease.EndpointChanged {
			if _, err = warpCommand(ctx, "tunnel", "endpoint", "reset"); err != nil {
				return errors.New("owned_warp_recovery_failed")
			}
		}
		if _, err = warpCommand(ctx, "tunnel", "masque-options", "reset"); err != nil {
			return errors.New("owned_warp_recovery_failed")
		}
		if err = os.Remove(b.State + "/warp-lease.json"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("warp_lease_invalid")
	}
	if err := RecoverFilter(ctx, b.State); err != nil {
		return err
	}
	return nil
}
