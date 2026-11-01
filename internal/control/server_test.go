package control

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
)

func TestUnixControlLifecycleAndRequestValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := core.NewEngine(&core.DemoBackend{}, core.DefaultConfig(), func(core.Config) error { return nil }, true)
	defer engine.Close(context.Background())
	server := &Server{Engine: engine, Authorize: Policy("", true)}
	socket := filepath.Join(t.TempDir(), "control.sock")
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(ctx, socket) }()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	response, err := CallMode(ctx, socket, "status", nil, true)
	if err != nil || !response.OK {
		t.Fatal("control status failed", err)
	}
	if _, err = CallMode(ctx, socket, "connect", nil, false); err == nil {
		t.Fatal("system and demo commands must not be interchangeable")
	}
	for _, request := range []string{`{"version":1,"command":"status","command":"disconnect"}`, `{"version":99,"command":"status"}`, `{"version":1,"command":"configure","params":{"source":"warp","unsafe":true}}`, `{"version":1,"command":"execute","params":{"shell":"id"}}`} {
		conn, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte(request + "\n"))
		var result Response
		if err = json.NewDecoder(conn).Decode(&result); err != nil {
			t.Fatal(err)
		}
		conn.Close()
		if result.OK {
			t.Fatal("unsafe request accepted")
		}
	}
	// A connected client that never sends a frame must not prevent shutdown.
	stalled, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	cancel()
	select {
	case err = <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled client prevented service shutdown")
	}
}
func TestImportDoesNotReturnCredentialOrSubscriptionURL(t *testing.T) {
	e := core.NewEngine(&core.DemoBackend{}, core.DefaultConfig(), func(core.Config) error { return nil }, true)
	defer e.Close(context.Background())
	s := &Server{Engine: e}
	result, err := s.importSource("Example", "trojan://private-password@example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(result)
	if strings.Contains(string(data), "private-password") {
		t.Fatal("credential leaked in import result")
	}
	result, err = s.importSource("Subscription", "https://example.com/list?token=secret-token")
	if err != nil {
		t.Fatal(err)
	}
	data, _ = json.Marshal(result)
	if strings.Contains(string(data), "secret-token") {
		t.Fatal("subscription token leaked")
	}
}
