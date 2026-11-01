package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
)

var defaultResolver = net.DefaultResolver

func socksDial(ctx context.Context, address, user, password string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, errors.New("proxy_probe_unavailable")
	}
	deadline, _ := ctx.Deadline()
	if deadline.IsZero() {
		deadline = time.Now().Add(10 * time.Second)
	}
	_ = conn.SetDeadline(deadline)
	fail := func() (net.Conn, error) { conn.Close(); return nil, errors.New("proxy_authentication_failed") }
	if len(user) > 255 || len(password) > 255 {
		return fail()
	}
	if _, err = conn.Write([]byte{5, 1, 2}); err != nil {
		return fail()
	}
	response := make([]byte, 2)
	if _, err = io.ReadFull(conn, response); err != nil || response[0] != 5 || response[1] != 2 {
		return fail()
	}
	auth := append([]byte{1, byte(len(user))}, []byte(user)...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, []byte(password)...)
	if _, err = conn.Write(auth); err != nil {
		return fail()
	}
	if _, err = io.ReadFull(conn, response); err != nil || response[1] != 0 {
		return fail()
	}
	return conn, nil
}

func socksConnect(ctx context.Context, proxy, user, password, target string) (net.Conn, error) {
	conn, err := socksDial(ctx, proxy, user, password)
	if err != nil {
		return nil, err
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, errors.New("invalid_probe_target")
	}
	port, _ := strconv.Atoi(portText)
	if len(host) > 255 {
		conn.Close()
		return nil, errors.New("invalid_probe_target")
	}
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err = conn.Write(request); err != nil {
		conn.Close()
		return nil, errors.New("proxy_connect_failed")
	}
	if _, err = readSocksAddress(conn); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func readSocksAddress(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 5 || header[1] != 0 {
		return "", errors.New("proxy_destination_failed")
	}
	length := 0
	switch header[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		b := []byte{0}
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		length = int(b[0])
	default:
		return "", errors.New("proxy_reply_invalid")
	}
	body := make([]byte, length+2)
	if _, err := io.ReadFull(conn, body); err != nil {
		return "", errors.New("proxy_reply_invalid")
	}
	host := string(body[:length])
	if header[3] != 3 {
		host = net.IP(body[:length]).String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(body[length:])))), nil
}

func measureHTTP(ctx context.Context, s *core.ProxySession, warp bool) (core.Measurement, error) {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	if s != nil {
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return socksConnect(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port)), s.User, s.Password, address)
		}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var elapsed int
	for i := 0; i < 3; i++ {
		started := time.Now()
		request, err := http.NewRequestWithContext(ctx, "GET", "https://www.cloudflare.com/cdn-cgi/trace", nil)
		if err != nil {
			return core.Measurement{}, err
		}
		response, err := client.Do(request)
		if err != nil {
			return core.Measurement{}, errors.New("tunnel_https_failed")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 8193))
		response.Body.Close()
		if readErr != nil || len(body) > 8192 || response.StatusCode != 200 {
			return core.Measurement{}, errors.New("tunnel_probe_invalid")
		}
		if warp && !strings.Contains(string(body), "warp=on") && !strings.Contains(string(body), "warp=plus") {
			return core.Measurement{}, errors.New("traffic_is_not_warp")
		}
		if !strings.Contains(string(body), "ip=") {
			return core.Measurement{}, errors.New("tunnel_probe_invalid")
		}
		elapsed += int(time.Since(started).Milliseconds())
	}
	return core.Measurement{LatencyMS: elapsed / 3}, nil
}

func probeUDP(ctx context.Context, s core.ProxySession) bool {
	control, err := socksDial(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port)), s.User, s.Password)
	if err != nil {
		return false
	}
	defer control.Close()
	if _, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return false
	}
	address, err := readSocksAddress(control)
	if err != nil {
		return false
	}
	host, port, _ := net.SplitHostPort(address)
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	udp, err := net.DialTimeout("udp", net.JoinHostPort(host, port), 3*time.Second)
	if err != nil {
		return false
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
	id := []byte{0, 0}
	_, _ = cryptoReader.Read(id)
	query := append([]byte{}, id...)
	query = append(query, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7)
	query = append(query, []byte("example")...)
	query = append(query, 3)
	query = append(query, []byte("com")...)
	query = append(query, 0, 0, 1, 0, 1)
	packet := append([]byte{0, 0, 0, 1, 1, 1, 1, 1, 0, 53}, query...)
	if _, err = udp.Write(packet); err != nil {
		return false
	}
	response := make([]byte, 2048)
	n, err := udp.Read(response)
	if err != nil || n < 22 {
		return false
	}
	offset := 10
	switch response[3] {
	case 4:
		offset = 22
	case 3:
		offset = 7 + int(response[4])
	}
	return n >= offset+12 && response[offset] == id[0] && response[offset+1] == id[1] && response[offset+2]&0x80 != 0
}
