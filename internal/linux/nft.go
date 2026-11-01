package linux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"github.com/ZarpVPN/Zarp-Linux/internal/storage"
)

type Target struct {
	Address netip.Addr `json:"address"`
	Port    uint16     `json:"port"`
	UDP     bool       `json:"udp"`
}
type FilterPlan struct {
	ProtectAPI        bool           `json:"protectAPI,omitempty"`
	StrictTargets     bool           `json:"strictTargets,omitempty"`
	Payload           core.Transport `json:"payload"`
	AccountingChanged bool           `json:"accountingChanged,omitempty"`
	Table             string         `json:"table"`
	Queue             int            `json:"queue"`
	Interface         string         `json:"interface"`
	WarpCgroup        string         `json:"warpCgroup,omitempty"`
	CgroupCompat      bool           `json:"cgroupCompat,omitempty"`
	FragmentCompat    bool           `json:"fragmentCompat,omitempty"`
	TunnelMSS         uint16         `json:"tunnelMSS,omitempty"`
	Targets           []Target       `json:"targets"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
var tableID = regexp.MustCompile(`^zarp_[a-f0-9]{16}$`)
var cgroupID = regexp.MustCompile(`^(?:[A-Za-z0-9_.@:-]+/)*[A-Za-z0-9_.@:-]+$`)

func checkWarpScope(ctx context.Context) error {
	_, err := warpScope(ctx)
	return err
}

func warpScope(ctx context.Context) (bool, error) {
	nft, err := SystemPath("nft")
	if err != nil {
		return false, err
	}
	table := "zarp_" + randomToken(8)
	rules := fmt.Sprintf("add table inet %s\nadd chain inet %s check { type filter hook output priority mangle; policy accept; }\nadd rule inet %s check socket transparent 1 counter\n", table, table, table)
	if _, err = Run(ctx, nft, []byte(rules), "--check", "--file", "-"); err != nil {
		if compatErr := checkCompatScope(ctx); compatErr != nil {
			return false, errors.New("kernel_warp_cgroup_filter_unavailable")
		}
		return true, nil
	}
	return false, nil
}

func NftRules(p FilterPlan) (string, error) {
	if !tableID.MatchString(p.Table) || !identifier.MatchString(p.Interface) || p.Queue < 20000 || p.Queue > 29999 || len(p.Targets) == 0 || len(p.Targets) > 512 {
		return "", errors.New("invalid_filter_plan")
	}
	sets := map[string][]string{"tcp4": {}, "tcp6": {}, "udp4": {}, "udp6": {}}
	for _, t := range p.Targets {
		if !t.Address.IsValid() || t.Address.Zone() != "" || t.Port == 0 {
			return "", errors.New("invalid_filter_target")
		}
		key := "tcp"
		if t.UDP {
			key = "udp"
		}
		if t.Address.Is4() {
			key += "4"
		} else {
			key += "6"
		}
		sets[key] = append(sets[key], fmt.Sprintf("%s . %d", t.Address, t.Port))
	}
	origin := fmt.Sprintf("meta mark & 0x%x != 0", core.SocketMark)
	if p.WarpCgroup != "" {
		if !validCgroup(p.WarpCgroup) {
			return "", errors.New("invalid_warp_cgroup")
		}
		if !p.CgroupCompat {
			origin = fmt.Sprintf("socket cgroupv2 level %d \"%s\"", strings.Count(p.WarpCgroup, "/")+1, p.WarpCgroup)
		} else {
			origin = fmt.Sprintf("ct mark & 0x%x != 0", core.SocketMark)
		}
	}
	if p.CgroupCompat && p.WarpCgroup == "" {
		return "", errors.New("invalid_warp_cgroup")
	}
	if p.FragmentCompat && (p.WarpCgroup == "" || p.Payload != core.QUIC) {
		return "", errors.New("invalid_fragment_scope")
	}
	if p.ProtectAPI && (p.WarpCgroup == "" || p.Payload != core.TLS) {
		return "", errors.New("invalid_api_filter")
	}
	if p.TunnelMSS != 0 && (p.WarpCgroup == "" || p.TunnelMSS < 512 || p.TunnelMSS > 1220) {
		return "", errors.New("invalid_tunnel_mss")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s { comment \"Zarp managed %s\"; }\n", p.Table, p.Table)
	for _, key := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		values := sets[key]
		if len(values) == 0 {
			continue
		}
		slices.Sort(values)
		values = slices.Compact(values)
		family := "ipv4_addr"
		if strings.HasSuffix(key, "6") {
			family = "ipv6_addr"
		}
		fmt.Fprintf(&b, "add set inet %s %s { type %s . inet_service; elements = { %s }; }\n", p.Table, key, family, strings.Join(values, ", "))
	}
	fmt.Fprintf(&b, "add chain inet %s rawout { type filter hook output priority -401; policy accept; }\n", p.Table)
	fmt.Fprintf(&b, "add rule inet %s rawout meta mark & 0x%x != 0 notrack\n", p.Table, core.DesyncMark)
	priority := "mangle"
	if p.CgroupCompat {
		priority = "mangle + 1" // xt_cgroup has tagged conntrack without altering routing marks.
	}
	fmt.Fprintf(&b, "add chain inet %s classify { type filter hook output priority %s; policy accept; }\n", p.Table, priority)
	fmt.Fprintf(&b, "add chain inet %s post { type filter hook postrouting priority srcnat + 1; policy accept; }\n", p.Table)
	fmt.Fprintf(&b, "add chain inet %s pre { type filter hook prerouting priority filter; policy accept; }\n", p.Table)
	fmt.Fprintf(&b, "add chain inet %s gate\n", p.Table)
	if p.TunnelMSS != 0 {
		// Clamp both advertised directions, only on our official WARP TUN.
		// The physical interface and the host's network settings stay untouched.
		fmt.Fprintf(&b, "add rule inet %s classify oifname \"CloudflareWARP\" tcp flags & syn == syn tcp option maxseg size > %d tcp option maxseg size set %d\n", p.Table, p.TunnelMSS, p.TunnelMSS)
		fmt.Fprintf(&b, "add rule inet %s pre iifname \"CloudflareWARP\" tcp flags & syn == syn tcp option maxseg size > %d tcp option maxseg size set %d\n", p.Table, p.TunnelMSS, p.TunnelMSS)
	}
	if p.ProtectAPI {
		// Service-scoped HTTPS also covers registration endpoints not in DNS snapshots.
		fmt.Fprintf(&b, "add rule inet %s classify meta mark & 0x%x == 0 %s tcp dport 443 ct mark set ct mark | 0x%x\n", p.Table, core.DesyncMark, origin, core.SocketMark)
		fmt.Fprintf(&b, "add rule inet %s post oifname \"%s\" meta mark & 0x%x == 0 ct mark & 0x%x != 0 tcp dport 443 jump gate\n", p.Table, p.Interface, core.DesyncMark, core.SocketMark)
		fmt.Fprintf(&b, "add rule inet %s pre iifname \"%s\" ct mark & 0x%x != 0 tcp sport 443 ct reply packets 1-24 counter queue num %d\n", p.Table, p.Interface, core.SocketMark, p.Queue)
	}
	for _, key := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		if len(sets[key]) == 0 {
			continue
		}
		family := "ip"
		if strings.HasSuffix(key, "6") {
			family = "ip6"
		}
		proto := key[:3]
		fmt.Fprintf(&b, "add rule inet %s classify meta mark & 0x%x == 0 %s %s daddr . %s dport @%s ct mark set ct mark | 0x%x\n", p.Table, core.DesyncMark, origin, family, proto, key, core.SocketMark)
		if p.WarpCgroup != "" {
			fmt.Fprintf(&b, "add rule inet %s classify meta mark & 0x%x == 0 meta mark & 0x%x != 0 %s daddr . %s dport @%s ct mark set ct mark | 0x%x\n", p.Table, core.DesyncMark, core.SocketMark, family, proto, key, core.SocketMark)
		}
		if p.ProtectAPI && proto == "tcp" {
			continue
		}
		fmt.Fprintf(&b, "add rule inet %s post oifname \"%s\" meta mark & 0x%x == 0 ct mark & 0x%x != 0 %s daddr . %s dport @%s jump gate\n", p.Table, p.Interface, core.DesyncMark, core.SocketMark, family, proto, key)
		if p.StrictTargets {
			fmt.Fprintf(&b, "add rule inet %s post oifname \"%s\" meta mark & 0x%x == 0 ct mark & 0x%x == 0 %s daddr . %s dport @%s counter drop\n", p.Table, p.Interface, core.DesyncMark, core.SocketMark, family, proto, key)
		}
		fmt.Fprintf(&b, "add rule inet %s pre iifname \"%s\" ct mark & 0x%x != 0 %s saddr . %s sport @%s ct reply packets 1-24 counter queue num %d\n", p.Table, p.Interface, core.SocketMark, family, proto, key, p.Queue)
	}
	fmt.Fprintf(&b, "add rule inet %s gate meta l4proto tcp ct original packets 1-24 counter queue num %d\n", p.Table, p.Queue)
	if p.Payload == core.QUIC {
		fmt.Fprintf(&b, "add rule inet %s gate meta l4proto udp @th,64,8 & 0xc0 == 0xc0 counter queue num %d\n", p.Table, p.Queue)
	} else {
		fmt.Fprintf(&b, "add rule inet %s gate meta l4proto udp counter queue num %d\n", p.Table, p.Queue)
	}
	fmt.Fprintf(&b, "add rule inet %s gate meta l4proto tcp tcp flags & (fin | rst) != 0 counter queue num %d\n", p.Table, p.Queue)
	return b.String(), nil
}

type Filter struct {
	Plan    FilterPlan
	Process *Child
	path    string
	mu      sync.Mutex
	closed  bool
	removed bool
}

func StartFilter(ctx context.Context, r *Runtime, state string, plan FilterPlan, strategy core.Strategy) (*Filter, error) {
	plan.Payload = strategy.Transport
	if plan.WarpCgroup != "" && strategy.Transport == core.QUIC {
		for _, arg := range strategy.Args {
			for _, part := range strings.Split(arg, ":") {
				if part == "ipfrag" {
					plan.FragmentCompat = true
				}
			}
		}
	}
	if plan.WarpCgroup != "" && !plan.CgroupCompat {
		compat, scopeErr := warpScope(ctx)
		if scopeErr != nil {
			return nil, scopeErr
		}
		plan.CgroupCompat = compat
	}
	if err := core.ValidateStrategy(strategy); err != nil {
		return nil, err
	}
	blobPaths, err := strategyBlobPaths(r, plan, strategy)
	if err != nil {
		return nil, err
	}
	rules, err := NftRules(plan)
	if err != nil {
		return nil, err
	}
	nft, err := SystemPath("nft")
	if err != nil {
		return nil, err
	}
	if _, err = Run(ctx, nft, []byte(rules), "--check", "--file", "-"); err != nil {
		return nil, errors.New("nft_filter_check_failed")
	}
	accounting, accountErr := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_acct")
	if accountErr != nil {
		return nil, errors.New("conntrack_accounting_unavailable")
	}
	plan.AccountingChanged = strings.TrimSpace(string(accounting)) == "0"
	args := []string{fmt.Sprintf("--qnum=%d", plan.Queue), fmt.Sprintf("--fwmark=0x%x", core.DesyncMark), "--debug=0", "--lua-init=@" + r.Path("lua/zapret-lib.lua"), "--lua-init=@" + r.Path("lua/zapret-antidpi.lua"), "--lua-init=@" + r.Path("lua/zarp-observe.lua")}
	for _, blob := range []string{"quic_google", "quic_vk", "tls_google", "tls_vk", "tls_gosuslugi", "stun"} {
		args = append(args, "--blob="+blob+":@"+blobPaths[blob])
	}
	if strategy.Transport == core.UDP {
		args = append(args, "--out-range=-n1")
	}
	args = append(args, strategy.Args...)
	args = append(args, "--bind-fix4", "--bind-fix6")
	if _, err = Run(ctx, r.Path("nfqws2"), nil, append([]string{"--dry-run"}, args...)...); err != nil {
		return nil, errors.New("nfqws_strategy_invalid")
	}
	if _, err = Run(ctx, r.Path("nfqws2"), nil, append([]string{"--intercept=0"}, args...)...); err != nil {
		return nil, errors.New("nfqws_lua_init_failed")
	}
	child, err := Start(r.Path("nfqws2"), args...)
	if err != nil {
		return nil, err
	}
	f := &Filter{Plan: plan, Process: child, path: state + "/filter.json"}
	ready := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if !child.Alive() {
			break
		}
		if queuePresent(plan.Queue) {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Millisecond):
		}
		if ctx.Err() != nil {
			break
		}
	}
	if !ready {
		_ = child.Stop(context.Background())
		return nil, errors.New("nfqueue_not_ready")
	}
	if err = storage.Write(f.path, plan); err != nil {
		_ = child.Stop(context.Background())
		return nil, errors.New("filter_journal_failed")
	}
	f.Plan = plan
	if plan.AccountingChanged {
		if err = os.WriteFile("/proc/sys/net/netfilter/nf_conntrack_acct", []byte("1"), 0600); err != nil {
			_ = child.Stop(context.Background())
			_ = os.Remove(f.path)
			return nil, errors.New("conntrack_accounting_enable_failed")
		}
	}
	if _, err = Run(ctx, nft, []byte(rules), "--file", "-"); err != nil {
		_ = child.Stop(context.Background())
		_ = restoreAccounting(plan)
		_ = os.Remove(f.path)
		return nil, errors.New("filter_install_failed")
	}
	if plan.CgroupCompat {
		if err = installCompatScope(ctx, plan); err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if closeErr := f.Close(cleanup); closeErr != nil {
				return nil, errors.New("cleanup_failed")
			}
			return nil, err
		}
	}
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-child.Done:
			case <-ticker.C:
				if child.Alive() {
					continue
				}
			}
			limit, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = f.Block(limit)
			cancel()
			return
		}
	}()
	return f, nil
}

func queuePresent(number int) bool {
	b, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == strconv.Itoa(number) {
			return true
		}
	}
	return false
}
func FreeQueue() (int, error) {
	for q := 22700; q < 22800; q++ {
		if !queuePresent(q) {
			return q, nil
		}
	}
	return 0, errors.New("nfqueue_range_busy")
}
func (f *Filter) Alive() bool   { return f.Process.Alive() }
func (f *Filter) Applied() bool { return f.Alive() && f.Process.Output.Sent.Load() > 0 }
func (f *Filter) Failure() string {
	code := "nfqws_stopped"
	output := f.Process.Output.String()
	if f.Process.Output.Fault.Load() {
		code = "nfqws_send_failed"
		if strings.Contains(output, "Operation not permitted") {
			code = "nfqws_send_blocked"
		}
		if strings.Contains(output, "Message too long") {
			code = "nfqws_packet_exceeds_mtu"
		}
		if strings.Contains(output, "ZARP_ERROR:lua:") {
			code = "nfqws_lua_error"
		}
		var details []string
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "ZARP_ERROR:") || strings.HasPrefix(line, "rawsend:") {
				details = append(details, line)
			}
		}
		_ = storage.Write(filepath.Join(filepath.Dir(f.path), "nfqws-error.json"), struct {
			Code      string   `json:"code"`
			Interface string   `json:"interface"`
			Details   []string `json:"details"`
		}{code, f.Plan.Interface, details})
	}
	return code
}
func (f *Filter) Block(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.removed {
		return nil
	}
	nft, err := SystemPath("nft")
	if err != nil {
		return err
	}
	_, err = Run(ctx, nft, []byte("flush chain inet "+f.Plan.Table+" gate\nadd rule inet "+f.Plan.Table+" gate counter drop\n"), "-f", "-")
	return err
}
func (f *Filter) Close(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	_ = f.Process.Stop(ctx)
	if err := removeWarpFragments(ctx, f.Plan); err != nil {
		return err
	}
	nft, err := SystemPath("nft")
	if err != nil {
		return err
	}
	if !f.removed {
		if _, err = Run(ctx, nft, nil, "delete", "table", "inet", f.Plan.Table); err != nil {
			return errors.New("cleanup_failed")
		}
		f.removed = true
	}
	if f.Plan.CgroupCompat {
		if err = removeCompatScope(ctx, f.Plan); err != nil {
			return err
		}
	}
	if err = restoreAccounting(f.Plan); err != nil {
		return errors.New("cleanup_failed")
	}
	f.closed = true
	_ = os.Remove(f.path)
	return nil
}

func RecoverFilter(ctx context.Context, state string) error {
	var p FilterPlan
	if err := storage.Read(state+"/filter.json", &p); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("filter_journal_invalid")
	}
	if !tableID.MatchString(p.Table) {
		return errors.New("filter_journal_invalid")
	}
	if err := removeWarpFragments(ctx, p); err != nil {
		return err
	}
	nft, err := SystemPath("nft")
	if err != nil {
		return err
	}
	out, listErr := Run(ctx, nft, nil, "-j", "list", "tables")
	if listErr != nil {
		return errors.New("filter_recovery_failed")
	}
	var tables map[string]json.RawMessage
	if json.Unmarshal([]byte(out), &tables) != nil {
		return errors.New("filter_recovery_failed")
	}
	if strings.Contains(out, `"`+p.Table+`"`) {
		if _, err = Run(ctx, nft, nil, "delete", "table", "inet", p.Table); err != nil {
			return errors.New("filter_recovery_failed")
		}
	}
	if p.CgroupCompat {
		if err = removeCompatScope(ctx, p); err != nil {
			return err
		}
	}
	if err = restoreAccounting(p); err != nil {
		return errors.New("filter_recovery_failed")
	}
	return os.Remove(state + "/filter.json")
}

func restoreAccounting(p FilterPlan) error {
	if !p.AccountingChanged {
		return nil
	}
	current, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_acct")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(current)) == "1" {
		return os.WriteFile("/proc/sys/net/netfilter/nf_conntrack_acct", []byte("0"), 0600)
	}
	return nil
}
