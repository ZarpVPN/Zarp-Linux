package linux

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
)

func registrationBackend(t *testing.T) (*Backend, *bool) {
	t.Helper()
	protected := false
	b := &Backend{State: t.TempDir(), registrationPause: time.Millisecond, warpReadyTimeout: 40 * time.Millisecond, warpReadyPause: time.Millisecond}
	b.apiProtect = func(ctx context.Context, cfg core.Config, emit func(string), call func(context.Context) error) error {
		protected = true
		defer func() { protected = false }()
		return call(ctx)
	}
	return b, &protected
}
func TestRegistrationCreatesOnlyUnderProtection(t *testing.T) {
	b, protected := registrationBackend(t)
	registered := false
	created := 0
	b.warpRun = func(ctx context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "registration show":
			if registered {
				return "Account type: Free", nil
			}
			return "MissingRegistration", errors.New("missing")
		case "registration new":
			if !*protected {
				t.Fatal("registration attempted before zapret protection")
			}
			created++
			registered = true
			return "", nil
		}
		return "", errors.New("unexpected")
	}
	cfg := core.DefaultConfig()
	cfg.Settings.AcceptedTerms = true
	if err := b.ensureRegistration(context.Background(), cfg, func(string) {}, nil); err != nil {
		t.Fatal(err)
	}
	if created != 1 {
		t.Fatal("registration should be created once")
	}
	if err := b.ensureRegistration(context.Background(), cfg, func(string) {}, nil); err != nil {
		t.Fatal(err)
	}
	if created != 1 {
		t.Fatal("existing account must be preserved")
	}
}
func TestRegistrationReadTimeoutNeverCreatesAnAccount(t *testing.T) {
	b, _ := registrationBackend(t)
	created := false
	b.warpRun = func(ctx context.Context, args ...string) (string, error) {
		if strings.Join(args, " ") == "registration new" {
			created = true
		}
		return "IPC timeout communicating with daemon", context.DeadlineExceeded
	}
	cfg := core.DefaultConfig()
	cfg.Settings.AcceptedTerms = true
	if err := b.ensureRegistration(context.Background(), cfg, func(string) {}, nil); err == nil {
		t.Fatal("unknown registration state accepted")
	}
	if created {
		t.Fatal("an IPC timeout must not create another account")
	}
}

func TestCannotReadRegistrationIsNotMissingRegistration(t *testing.T) {
	for _, out := range []string{"Cannot contact daemon while reading registration", "IPC timeout: missing registration status", "Old registration is still around"} {
		if confirmedMissing(out) {
			t.Fatalf("ambiguous status treated as missing: %s", out)
		}
	}
	if !confirmedMissing("Error: MissingRegistration") {
		t.Fatal("explicit missing status not recognised")
	}
}
func TestUncertainCreationSurvivesRestart(t *testing.T) {
	b, _ := registrationBackend(t)
	created := 0
	b.warpRun = func(ctx context.Context, args ...string) (string, error) {
		if strings.Join(args, " ") == "registration new" {
			created++
			return "IPC timeout", context.DeadlineExceeded
		}
		return "MissingRegistration", errors.New("missing")
	}
	cfg := core.DefaultConfig()
	cfg.Settings.AcceptedTerms = true
	if err := b.ensureRegistration(context.Background(), cfg, func(string) {}, nil); err == nil {
		t.Fatal("lost registration response accepted")
	}
	if _, err := os.Stat(b.State + "/registration-pending.json"); err != nil {
		t.Fatal("uncertain operation was not persisted")
	}
	if err := b.ensureRegistration(context.Background(), cfg, func(string) {}, nil); err == nil {
		t.Fatal("uncertain creation retried")
	}
	if created != 1 {
		t.Fatal("duplicate account creation")
	}
}
func TestAccountContinuationKeepsTheAPIProtection(t *testing.T) {
	b, protected := registrationBackend(t)
	b.warpRun = func(context.Context, ...string) (string, error) { return "Account type: Unlimited", nil }
	cfg := core.DefaultConfig()
	cfg.Settings.AcceptedTerms = true
	called := false
	if err := b.ensureRegistration(context.Background(), cfg, func(string) {}, func(context.Context) error {
		called = true
		if !*protected {
			t.Fatal("account continuation lost protection")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("account continuation not executed")
	}
}

func TestColdRegistrationWaitsForIPCBeforeCreatingUnderProtection(t *testing.T) {
	for _, entry := range []struct {
		name       string
		registered bool
	}{{"missing_registration", false}, {"existing_registration", true}} {
		t.Run(entry.name, func(t *testing.T) {
			b, protected := registrationBackend(t)
			reads, created := 0, 0
			registered := entry.registered
			b.warpRun = func(ctx context.Context, args ...string) (string, error) {
				if strings.Join(args, " ") == "registration show" {
					reads++
					if reads <= 2 {
						return "Unable to connect to the CloudflareWARP daemon: No such file or directory", errors.New("IPC not ready")
					}
					if registered {
						return "Account type: Free", nil
					}
					return "MissingRegistration", errors.New("missing")
				}
				if strings.Join(args, " ") == "registration new" {
					if !*protected {
						t.Fatal("unprotected creation")
					}
					created++
					registered = true
					return "Success", nil
				}
				return "", errors.New("unexpected command")
			}
			cfg := core.DefaultConfig()
			cfg.Settings.AcceptedTerms = true
			if err := b.ensureRegistration(context.Background(), cfg, func(string) {}, nil); err != nil {
				t.Fatal(err)
			}
			expected := 1
			if entry.registered {
				expected = 0
			}
			if created != expected || reads < 3 {
				t.Fatal("startup or duplicate registration", reads, created)
			}
			if err := b.ensureRegistration(context.Background(), cfg, func(string) {}, nil); err != nil || created != expected {
				t.Fatal("retry changed existing device", err, created)
			}
		})
	}
}

func TestIPCReadinessCancellationDoesNotCreateOrJournalRegistration(t *testing.T) {
	b, _ := registrationBackend(t)
	created := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.warpRun = func(ctx context.Context, args ...string) (string, error) {
		if strings.Join(args, " ") == "registration new" {
			created++
		}
		cancel()
		return "IPC timeout communicating with daemon", errors.New("unavailable")
	}
	cfg := core.DefaultConfig()
	cfg.Settings.AcceptedTerms = true
	if err := b.ensureRegistration(ctx, cfg, func(string) {}, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if created != 0 {
		t.Fatal("creation after cancellation")
	}
	if _, err := os.Stat(b.State + "/registration-pending.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("readiness wait created a registration journal", err)
	}
}
