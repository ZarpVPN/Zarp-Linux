package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"github.com/ZarpVPN/Zarp-Linux/internal/storage"
)

const ProtocolVersion = 1
const MaxRequest = 1024 * 1024

type Request struct {
	Demo    bool            `json:"demo"`
	Version int             `json:"version"`
	Command string          `json:"command"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type Response struct {
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	Result  any    `json:"result,omitempty"`
	Error   string `json:"error,omitempty"`
}
type Authorize func(context.Context, *syscall.Ucred) error
type Server struct {
	Engine    *core.Engine
	Authorize Authorize
	mu        sync.Mutex
	listener  *net.UnixListener
	wg        sync.WaitGroup
	path      string
}

func (s *Server) Serve(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("control path is not a socket")
		}
		if conn, err := net.DialTimeout("unix", path, 200*time.Millisecond); err == nil {
			conn.Close()
			return errors.New("another daemon is running")
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) {
			return errors.New("socket belongs to another user")
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	if err = os.Chmod(path, 0666); err != nil {
		listener.Close()
		return err
	}
	s.mu.Lock()
	s.listener = listener
	s.path = path
	s.mu.Unlock()
	go func() { <-ctx.Done(); listener.Close() }()
	slots := make(chan struct{}, 8)
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			s.wg.Add(1)
			go func() { defer s.wg.Done(); defer func() { <-slots }(); defer conn.Close(); s.handle(ctx, conn) }()
		default:
			conn.Close()
		}
	}
	s.wg.Wait()
	return nil
}

func (s *Server) handle(parent context.Context, conn *net.UnixConn) {
	stopClose := context.AfterFunc(parent, func() { conn.Close() })
	defer stopClose()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Minute))
	credential, err := peerCredential(conn)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
	defer cancel()
	if err = s.Authorize(ctx, credential); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{Version: 1, Error: "control_access_denied"})
		return
	}
	reader := bufio.NewReader(io.LimitReader(conn, MaxRequest+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > MaxRequest {
		_ = json.NewEncoder(conn).Encode(Response{Version: 1, Error: "request_too_large_or_incomplete"})
		return
	}
	var request Request
	if err = storage.Decode(line, &request); err != nil || request.Version != ProtocolVersion {
		_ = json.NewEncoder(conn).Encode(Response{Version: 1, Error: "invalid_request_version_or_document"})
		return
	}
	if request.Demo != s.Engine.Snapshot().Demo {
		_ = json.NewEncoder(conn).Encode(Response{Version: 1, Error: "control_mode_mismatch"})
		return
	}
	result, err := s.Dispatch(ctx, request)
	response := Response{Version: 1, OK: err == nil, Result: result}
	if err != nil {
		response.Error = err.Error()
		response.Result = nil
	}
	_ = json.NewEncoder(conn).Encode(response)
}

func peerCredential(conn *net.UnixConn) (*syscall.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var credential *syscall.Ucred
	var sockErr error
	if err = raw.Control(func(fd uintptr) {
		credential, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return credential, sockErr
}

func parameters(raw json.RawMessage, value any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	return storage.Decode(raw, value)
}

func (s *Server) Dispatch(ctx context.Context, r Request) (any, error) {
	switch r.Command {
	case "status":
		return s.Engine.Snapshot(), nil
	case "inspect":
		return s.Engine.Inspect(ctx)
	case "account":
		return s.Engine.Account(ctx)
	case "geodata":
		return s.Engine.GeoStatus(), nil
	case "download_geo":
		var p struct {
			Kind string `json:"kind"`
			URL  string `json:"url"`
		}
		if err := parameters(r.Params, &p); err != nil {
			return nil, err
		}
		return nil, s.Engine.DownloadGeo(ctx, p.Kind, p.URL)
	case "check_updates":
		return s.Engine.CheckUpdates(ctx)
	case "get_config":
		return s.Engine.Config(), nil
	case "configure":
		var p core.Settings
		if err := parameters(r.Params, &p); err != nil {
			return nil, err
		}
		return nil, s.Engine.Update(func(c *core.Config) error { c.Settings = p; return nil })
	case "connect", "scan", "test":
		var p struct {
			ID   string   `json:"id"`
			Full bool     `json:"full"`
			IDs  []string `json:"ids,omitempty"`
		}
		if err := parameters(r.Params, &p); err != nil {
			return nil, err
		}
		if r.Command == "test" && len(p.IDs) > 0 {
			return nil, s.Engine.StartBatch(p.IDs)
		}
		if r.Command == "test" && p.ID == "" {
			return nil, errors.New("select a strategy to test")
		}
		return nil, s.Engine.Start(r.Command, p.ID, p.Full)
	case "disconnect":
		return nil, s.Engine.Disconnect(ctx)
	case "import":
		var p struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if err := parameters(r.Params, &p); err != nil {
			return nil, err
		}
		return s.importSource(p.Name, p.Value)
	case "remove_source":
		var p struct {
			ID string `json:"id"`
		}
		if err := parameters(r.Params, &p); err != nil {
			return nil, err
		}
		return nil, s.Engine.Update(func(c *core.Config) error {
			for i, v := range c.Sources {
				if v.ID == p.ID {
					c.Sources = append(c.Sources[:i], c.Sources[i+1:]...)
					if c.Settings.Source == p.ID {
						c.Settings.Source = "warp"
						c.Settings.Server = ""
						c.Settings.PerApp = false
						c.Settings.Routes = nil
					}
					return nil
				}
			}
			return errors.New("unknown source")
		})
	case "refresh":
		var p struct {
			ID string `json:"id"`
		}
		if err := parameters(r.Params, &p); err != nil {
			return nil, err
		}
		return nil, s.Engine.Refresh(ctx, p.ID)
	case "strategies":
		var p struct {
			Text string `json:"text"`
		}
		if err := parameters(r.Params, &p); err != nil {
			return nil, err
		}
		strategies, err := core.ParseStrategies(p.Text)
		if err != nil {
			return nil, err
		}
		return nil, s.Engine.Update(func(c *core.Config) error { c.Custom = strategies; return nil })
	case "license":
		var p struct {
			Key string `json:"key"`
		}
		if err := parameters(r.Params, &p); err != nil {
			return nil, err
		}
		return s.Engine.License(ctx, p.Key)
	default:
		return nil, errors.New("unknown_control_command")
	}
}

func (s *Server) importSource(name, value string) (any, error) {
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") || len(value) > 2*1024*1024 {
		return nil, errors.New("source exceeds limits")
	}
	if name == "" {
		name = "Servers"
	}
	source := core.Source{Name: name, Servers: []core.Profile{}}
	if strings.HasPrefix(value, "https://") {
		u, err := url.Parse(value)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Port() != "" && u.Port() != "443" {
			return nil, errors.New("subscription requires a public HTTPS URL")
		}
		source.URL = value
		source.ID = "source-" + core.Fingerprint(value)[:24]
	} else {
		profiles, _, err := core.ParseSubscription([]byte(value))
		if err != nil {
			return nil, err
		}
		source.Servers = profiles
		source.ID = "source-" + core.Fingerprint(profiles)[:24]
	}
	err := s.Engine.Update(func(c *core.Config) error {
		if len(c.Sources) >= 32 {
			return errors.New("too many sources")
		}
		for _, v := range c.Sources {
			if v.ID == source.ID {
				return errors.New("source already exists")
			}
		}
		c.Sources = append(c.Sources, source)
		return nil
	})
	return core.Object{"id": source.ID, "servers": len(source.Servers), "subscription": source.URL != ""}, err
}

func Call(ctx context.Context, path, command string, params any) (Response, error) {
	return CallMode(ctx, path, command, params, false)
}

func CallMode(ctx context.Context, path, command string, params any, demo bool) (Response, error) {
	var response Response
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return response, errors.New("zarp_service_unavailable")
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return response, err
	}
	if string(raw) == "null" {
		raw = nil
	}
	if err = json.NewEncoder(conn).Encode(Request{Version: 1, Command: command, Params: raw, Demo: demo}); err != nil {
		return response, err
	}
	decoder := json.NewDecoder(io.LimitReader(conn, 8*1024*1024))
	if err = decoder.Decode(&response); err != nil {
		return response, errors.New("invalid_service_response")
	}
	if !response.OK {
		return response, errors.New(response.Error)
	}
	return response, nil
}

func Policy(ownerPath string, demo bool) Authorize {
	var mu sync.Mutex
	return func(ctx context.Context, peer *syscall.Ucred) error {
		if demo {
			if peer.Uid != uint32(os.Getuid()) {
				return errors.New("different user")
			}
			return nil
		}
		if peer.Uid == 0 {
			return nil
		}
		// Bind authorization to the kernel peer PID, start time and UID, not JSON claims.
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", peer.Pid))
		if err != nil {
			return err
		}
		end := strings.LastIndex(string(stat), ")")
		if end < 0 {
			return errors.New("peer exited")
		}
		fields := strings.Fields(string(stat)[end+1:])
		if len(fields) < 20 {
			return errors.New("peer stat invalid")
		}
		start := fields[19]
		pkcheck := "/usr/bin/pkcheck"
		process := fmt.Sprintf("%d,%s,%d", peer.Pid, start, peer.Uid)
		command := exec.CommandContext(ctx, pkcheck, "--action-id", "dev.zarp.control", "--process", process)
		if err = command.Run(); err != nil {
			return errors.New("inactive or unauthorized desktop session")
		}
		mu.Lock()
		defer mu.Unlock()
		var owner struct {
			UID uint32 `json:"uid"`
		}
		if err = storage.Read(ownerPath, &owner); errors.Is(err, os.ErrNotExist) {
			owner.UID = peer.Uid
			return storage.Write(ownerPath, owner)
		} else if err != nil {
			return err
		}
		if owner.UID != peer.Uid {
			return errors.New("this installation belongs to another desktop user")
		}
		return nil
	}
}

func DefaultDemoSocket() string {
	if run := os.Getenv("XDG_RUNTIME_DIR"); run != "" {
		return filepath.Join(run, "zarp-demo.sock")
	}
	return filepath.Join(os.TempDir(), "zarp-demo-"+strconv.Itoa(os.Getuid())+".sock")
}
