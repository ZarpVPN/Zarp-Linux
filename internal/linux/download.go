package linux

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"github.com/ZarpVPN/Zarp-Linux/internal/storage"
)

type redirectError struct{ Location string }

func (e redirectError) Error() string { return "download_redirect" }

func markedDialer() *net.Dialer {
	return &net.Dialer{Timeout: 8 * time.Second, Control: func(network, address string, raw syscall.RawConn) error {
		var result error
		if err := raw.Control(func(fd uintptr) {
			result = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, core.SocketMark)
		}); err != nil {
			return err
		}
		return result
	}}
}

func fetchAt(ctx context.Context, rawURL string, addresses []netip.Addr, maxSize int64, marked bool) ([]byte, int, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Port() != "" && u.Port() != "443" {
		return nil, 0, errors.New("download_requires_https")
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	if marked {
		dialer = markedDialer()
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		for _, a := range addresses {
			conn, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), "443"))
			if e == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, errors.New("download_connection_failed")
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, 0, errors.New("download_request_invalid")
	}
	request.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Zarp/"+core.Version+")")
	if u.Hostname() == "cloudflare-dns.com" {
		request.Header.Set("Accept", "application/dns-json")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, errors.New("download_network_error")
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		location, e := response.Location()
		if e != nil {
			return nil, response.StatusCode, errors.New("download_redirect_invalid")
		}
		return nil, response.StatusCode, redirectError{Location: location.String()}
	}
	if response.StatusCode != 200 {
		return nil, response.StatusCode, errors.New("download_http_" + strconv.Itoa(response.StatusCode))
	}
	if response.ContentLength > maxSize {
		return nil, 200, errors.New("download_size_exceeded")
	}
	// An inactivity deadline protects stalled bodies without penalising a slow transfer.
	timer := time.AfterFunc(15*time.Second, func() { response.Body.Close() })
	defer timer.Stop()
	var data []byte
	buffer := make([]byte, 64*1024)
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			timer.Reset(15 * time.Second)
			if int64(len(data)+n) > maxSize {
				return nil, 200, errors.New("download_size_exceeded")
			}
			data = append(data, buffer[:n]...)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, 200, errors.New("download_interrupted")
		}
		if ctx.Err() != nil {
			return nil, 200, ctx.Err()
		}
	}
	if response.ContentLength >= 0 && int64(len(data)) != response.ContentLength {
		return nil, 200, errors.New("download_incomplete")
	}
	return data, 200, nil
}

func (b *Backend) resolve(ctx context.Context, host string, cfg core.Config, emit func(string)) ([]netip.Addr, error) {
	limit, cancel := context.WithTimeout(ctx, 3*time.Second)
	addresses, err := resolvePublic(limit, host)
	cancel()
	if err == nil {
		return addresses, nil
	}
	if !core.ValidHost(host) {
		return nil, err
	}
	emit("dns_bootstrap_protected")
	bootstrap := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}
	targets := []Target{{Address: bootstrap[0], Port: 443}, {Address: bootstrap[1], Port: 443}}
	for _, strategy := range tlsStrategies(cfg) {
		filter, filterErr := b.startFilter(ctx, targets, "", strategy)
		if filterErr != nil {
			return nil, filterErr
		}
		data, _, requestErr := fetchAt(ctx, "https://cloudflare-dns.com/dns-query?name="+url.QueryEscape(host)+"&type=A", bootstrap, 65536, true)
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := filter.Close(cleanup)
		stop()
		if closeErr != nil {
			return nil, errors.New("cleanup_failed")
		}
		if requestErr != nil {
			continue
		}
		var answer struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if json.Unmarshal(data, &answer) != nil {
			continue
		}
		var result []netip.Addr
		for _, record := range answer.Answer {
			if record.Type == 1 || record.Type == 28 {
				if a, e := netip.ParseAddr(record.Data); e == nil && core.PublicIP(a) {
					result = append(result, a)
				}
			}
		}
		if len(result) > 0 && len(result) <= 32 {
			return result, nil
		}
	}
	return nil, errors.New("dns_resolution_failed")
}

func (b *Backend) Download(ctx context.Context, rawURL string, maxSize int64, cfg core.Config, emit func(string)) ([]byte, error) {
	var cached map[string]string
	if storage.Read(b.State+"/download-strategies.json", &cached) == nil && cached != nil {
		cfg.Bootstrap = cached
	}
	if cfg.Bootstrap == nil {
		cfg.Bootstrap = map[string]string{}
	}
	for redirects := 0; redirects <= 5; redirects++ {
		data, err := b.downloadOne(ctx, rawURL, maxSize, cfg, emit)
		var redirect redirectError
		if !errors.As(err, &redirect) {
			return data, err
		}
		next, e := url.Parse(redirect.Location)
		if e != nil || next.Scheme != "https" || next.User != nil || next.Fragment != "" {
			return nil, errors.New("download_redirect_refused")
		}
		rawURL = next.String()
	}
	return nil, errors.New("download_redirect_limit")
}

func (b *Backend) downloadOne(ctx context.Context, rawURL string, maxSize int64, cfg core.Config, emit func(string)) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("download_requires_https")
	}
	addresses, err := b.resolve(ctx, u.Hostname(), cfg, emit)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		data, status, downloadErr := fetchAt(ctx, rawURL, addresses, maxSize, false)
		if downloadErr == nil {
			return data, nil
		}
		if status >= 300 && status < 400 || status == 404 || status == 401 || status == 429 {
			return nil, downloadErr
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		emit("download_retry")
	}
	var targets []Target
	for _, a := range addresses {
		targets = append(targets, Target{Address: a, Port: 443})
	}
	strategies := tlsStrategies(cfg)
	if preferred := cfg.Bootstrap[u.Hostname()]; preferred != "" {
		slices.SortStableFunc(strategies, func(a, b core.Strategy) int {
			if a.ID == b.ID {
				return 0
			}
			if a.ID == preferred {
				return -1
			}
			if b.ID == preferred {
				return 1
			}
			return 0
		})
	}
	for _, strategy := range strategies {
		emit("download_strategy:" + strategy.Name)
		filter, filterErr := b.startFilter(ctx, targets, "", strategy)
		if filterErr != nil {
			return nil, filterErr
		}
		data, status, downloadErr := fetchAt(ctx, rawURL, addresses, maxSize, true)
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := filter.Close(cleanup)
		stop()
		if closeErr != nil {
			return nil, errors.New("cleanup_failed")
		}
		if downloadErr == nil {
			cfg.Bootstrap[u.Hostname()] = strategy.ID
			_ = storage.Write(b.State+"/download-strategies.json", cfg.Bootstrap)
			return data, nil
		}
		if status >= 300 && status < 400 || status == 404 || status == 401 || status == 429 {
			return nil, downloadErr
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("download_strategies_exhausted")
}

func (b *Backend) DownloadSubscription(ctx context.Context, rawURL string, cfg core.Config, emit func(string)) ([]byte, error) {
	return b.Download(ctx, rawURL, 2*1024*1024, cfg, emit)
}
func verifyDigest(data []byte, want string) bool {
	h := sha256.Sum256(data)
	return strings.EqualFold(hex.EncodeToString(h[:]), want)
}
