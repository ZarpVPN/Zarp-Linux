package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/control"
	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"github.com/ZarpVPN/Zarp-Linux/internal/linux"
	"github.com/ZarpVPN/Zarp-Linux/internal/storage"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
func run() error {
	demo := flag.Bool("demo", false, "Run without system tools, network access or real results")
	socket := flag.String("socket", "/run/zarp/control.sock", "Unix control socket")
	state := flag.String("state", "/var/lib/zarp", "Private state directory")
	runtimePath := flag.String("runtime", "/usr/lib/zarp/runtime", "Root-owned runtime directory")
	doctor := flag.Bool("doctor", false, "Print read-only system inspection and exit")
	version := flag.Bool("version", false, "Print version")
	flag.Parse()
	if *version {
		fmt.Println(core.Version)
		return nil
	}
	if *demo {
		if *socket == "/run/zarp/control.sock" {
			*socket = control.DefaultDemoSocket()
		}
		if *state == "/var/lib/zarp" {
			cache, err := os.UserCacheDir()
			if err != nil {
				return err
			}
			*state = filepath.Join(cache, "zarp-demo")
		}
	} else if os.Geteuid() != 0 {
		return errors.New("run the installed system service; the desktop must not run as root")
	}
	if err := os.MkdirAll(*state, 0700); err != nil {
		return err
	}
	cfg := core.DefaultConfig()
	configPath := filepath.Join(*state, "config.json")
	if err := storage.Read(configPath, &cfg); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("stored_configuration_invalid")
	}
	if cfg.Schema != 1 {
		return errors.New("unsupported_configuration_schema")
	}
	if err := core.ValidateSettings(cfg.Settings, cfg.Sources); err != nil {
		return errors.New("stored_configuration_invalid")
	}
	if cfg.Results == nil {
		cfg.Results = map[string]core.Result{}
	}
	if cfg.Bootstrap == nil {
		cfg.Bootstrap = map[string]string{}
	}
	var backend core.Backend
	if *demo {
		backend = &core.DemoBackend{}
	} else {
		runtime, err := linux.LoadRuntime(*runtimePath)
		if err != nil {
			return err
		}
		real := linux.NewBackend(runtime, *state)
		if !*doctor {
			cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			err = real.Recover(cleanup)
			cancel()
			if err != nil {
				return err
			}
		}
		backend = real
	}
	if *doctor {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		info, err := backend.Inspect(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(info)
	}
	engine := core.NewEngine(backend, cfg, func(c core.Config) error { return storage.Write(configPath, c) }, *demo)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &control.Server{Engine: engine, Authorize: control.Policy(filepath.Join(*state, "owner.json"), *demo)}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = engine.Close(ctx)
	}()
	fmt.Printf("Zarp %s ready on %s (demo=%t)\n", core.Version, *socket, *demo)
	return server.Serve(ctx, *socket)
}
