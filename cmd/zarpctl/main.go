package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/control"
)

func main() {
	socket := flag.String("socket", "/run/zarp/control.sock", "Control socket")
	demo := flag.Bool("demo", false, "Use demo socket")
	flag.Parse()
	if *demo {
		*socket = control.DefaultDemoSocket()
	}
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: zarpctl [--demo|--socket PATH] COMMAND < parameters.json\nCommands: status inspect get_config configure connect scan test disconnect import refresh remove_source strategies license")
		os.Exit(2)
	}
	var params any
	if info, _ := os.Stdin.Stat(); info != nil && info.Mode()&os.ModeCharDevice == 0 {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, control.MaxRequest+1))
		if err != nil || len(data) > control.MaxRequest {
			fmt.Fprintln(os.Stderr, "request too large")
			os.Exit(2)
		}
		if len(data) > 0 {
			if err = json.Unmarshal(data, &params); err != nil {
				fmt.Fprintln(os.Stderr, "invalid JSON parameters")
				os.Exit(2)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	response, err := control.CallMode(ctx, *socket, flag.Arg(0), params, *demo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(response.Result)
}
