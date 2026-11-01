package linux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type boundedOutput struct {
	mu    sync.Mutex
	data  []byte
	tail  string
	Sent  atomic.Uint64
	Fault atomic.Bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if len(b.data) < 262144 {
		take := min(len(p), 262144-len(b.data))
		b.data = append(b.data, p[:take]...)
	}
	b.tail += string(p)
	for {
		line, rest, found := strings.Cut(b.tail, "\n")
		if !found {
			break
		}
		b.tail = rest
		if strings.TrimSpace(line) == "ZARP_SENT" {
			b.Sent.Add(1)
		}
		if strings.Contains(line, "ZARP_ERROR") {
			b.Fault.Store(true)
		}
	}
	if len(b.tail) > 8192 {
		b.tail = b.tail[len(b.tail)-8192:]
	}
	return n, nil
}
func (b *boundedOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(append([]byte{}, b.data...))
}

func command(ctx context.Context, path string, input []byte, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/root", "DEBIAN_FRONTEND=noninteractive"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	return cmd
}

func Run(ctx context.Context, path string, input []byte, args ...string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cmd := command(ctx, path, input, args...)
	out := new(boundedOutput)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return out.String(), ctx.Err()
		}
		return out.String(), errors.New("command_failed:" + filepath.Base(path))
	}
	return out.String(), nil
}

type Child struct {
	cmd    *exec.Cmd
	Output *boundedOutput
	Done   chan struct{}
	once   sync.Once
	err    error
}

func Start(path string, args ...string) (*Child, error) {
	type started struct {
		child *Child
		err   error
	}
	ready := make(chan started, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		cmd := command(context.Background(), path, nil, args...)
		out := new(boundedOutput)
		cmd.Stdout = out
		cmd.Stderr = out
		if err := cmd.Start(); err != nil {
			ready <- started{err: errors.New("engine_start_failed:" + filepath.Base(path))}
			return
		}
		child := &Child{cmd: cmd, Output: out, Done: make(chan struct{})}
		ready <- started{child: child}
		child.err = cmd.Wait()
		close(child.Done)
	}()
	result := <-ready
	return result.child, result.err
}
func (c *Child) Alive() bool {
	select {
	case <-c.Done:
		return false
	default:
		return !c.Output.Fault.Load()
	}
}
func (c *Child) PID() int { return c.cmd.Process.Pid }
func (c *Child) Stop(ctx context.Context) error {
	select {
	case <-c.Done:
		return nil
	default:
	}
	c.once.Do(func() { _ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGTERM) })
	timer := time.NewTimer(800 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-c.Done:
		return nil
	case <-timer.C:
	case <-ctx.Done():
	}
	select {
	case <-c.Done:
		return nil
	default:
	}
	_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
	select {
	case <-c.Done:
		return nil
	case <-ctx.Done():
		return errors.New("engine_cleanup_timeout")
	}
}

func SystemPath(name string) (string, error) {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/opt/cloudflare-warp", "/opt/zarp-warp"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			resolved, resolveErr := filepath.EvalSymlinks(path)
			if resolveErr != nil {
				continue
			}
			if os.Geteuid() == 0 && trustedPath(resolved, false) != nil {
				continue
			}
			return path, nil
		}
	}
	return "", errors.New("missing_tool:" + name)
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(cryptoReader, b); err != nil {
		panic("system random source unavailable")
	}
	return hexString(b)
}
