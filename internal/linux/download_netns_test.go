package linux

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
)

func TestNetnsDownloadServerHelper(t *testing.T) {
	if os.Getenv("ZARP_DOWNLOAD_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	current, _ := os.Readlink("/proc/self/ns/net")
	initial, _ := os.Readlink("/proc/1/ns/net")
	if current == initial {
		t.Fatal("refusing the initial namespace")
	}
	ip, _ := SystemPath("ip")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for {
		if _, err := net.InterfaceByName("zdpeer0"); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("test veth not received")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"addr", "add", "10.231.19.2/30", "dev", "zdpeer0"}, {"link", "set", "zdpeer0", "up"}, {"addr", "add", "1.1.1.1/32", "dev", "lo"}} {
		if out, err := Run(ctx, ip, nil, args...); err != nil {
			t.Fatal(err, out)
		}
	}
	listener, err := net.Listen("tcp", "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = fmt.Fprint(w, "verified download fixture")
	})}
	fmt.Println("READY")
	if err = server.ServeTLS(listener, os.Getenv("ZARP_DOWNLOAD_CERT"), os.Getenv("ZARP_DOWNLOAD_KEY")); err != nil {
		t.Fatal(err)
	}
}

func TestNetnsDownloadRetriesThenUsesZapret(t *testing.T) {
	runtime := requireNetns(t)
	dir := t.TempDir()
	template := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	pair := template.TLS.Certificates[0]
	template.Close()
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := dir+"/cert.pem", dir+"/key.pem"
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600)
	t.Setenv("SSL_CERT_FILE", certFile)
	exe, _ := os.Executable()
	helper := exec.Command(exe, "-test.run=^TestNetnsDownloadServerHelper$")
	helper.Env = append(os.Environ(), "ZARP_DOWNLOAD_HELPER=1", "ZARP_DOWNLOAD_CERT="+certFile, "ZARP_DOWNLOAD_KEY="+keyFile)
	helper.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	output, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	helper.Stderr = os.Stderr
	if err = helper.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = helper.Process.Kill(); _ = helper.Wait() }()
	ip, _ := SystemPath("ip")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, args := range [][]string{{"link", "add", "zdownload0", "type", "veth", "peer", "name", "zdpeer0"}, {"link", "set", "zdpeer0", "netns", fmt.Sprint(helper.Process.Pid)}, {"addr", "add", "10.231.19.1/30", "dev", "zdownload0"}, {"link", "set", "zdownload0", "up"}, {"route", "add", "default", "via", "10.231.19.2", "dev", "zdownload0"}} {
		if out, err := Run(ctx, ip, nil, args...); err != nil {
			t.Fatal(err, out)
		}
	}
	defer Run(context.Background(), ip, nil, "link", "delete", "zdownload0")
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			if scanner.Text() == "READY" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("download helper exited")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	dns, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	go func() {
		buffer := make([]byte, 512)
		for {
			n, peer, err := dns.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n < 17 {
				continue
			}
			end := 12
			for end < n && buffer[end] != 0 {
				end += int(buffer[end]) + 1
			}
			end++
			if end+4 > n {
				continue
			}
			kind := binary.BigEndian.Uint16(buffer[end : end+2])
			answer := append([]byte{}, buffer[:end+4]...)
			answer[2] = 0x81
			answer[3] = 0x80
			for i := 6; i < 12; i++ {
				answer[i] = 0
			}
			if kind == 1 {
				answer[7] = 1
				answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 1, 1, 1)
			}
			_, _ = dns.WriteTo(answer, peer)
		}
	}()
	previous := defaultResolver
	defaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dns.LocalAddr().String())
	}}
	defer func() { defaultResolver = previous }()
	backend := NewBackend(runtime, dir)
	events := []string{}
	data, err := backend.Download(ctx, "https://example.com/package.deb", 1024, core.DefaultConfig(), func(message string) { events = append(events, message) })
	if err != nil {
		t.Fatalf("download failed: %v; events=%v", err, events)
	}
	if string(data) != "verified download fixture" {
		t.Fatal("download data changed")
	}
	retries, protected := 0, false
	for _, event := range events {
		if event == "download_retry" {
			retries++
		}
		if strings.HasPrefix(event, "download_strategy:") {
			protected = true
		}
	}
	if retries != 2 || !protected {
		t.Fatal("failed downloads did not transition to zapret2", events)
	}
}
