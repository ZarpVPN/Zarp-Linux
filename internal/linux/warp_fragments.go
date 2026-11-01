package linux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ZarpVPN/Zarp-Linux/internal/core"
	"strings"
	"time"
)

// WARP permits its UDP endpoint by port. Non-initial IP fragments have no UDP
// header and hit that chain's default drop. Permit only packets already emitted
// by our trusted nfqws2, to the exact selected endpoint and physical interface.
// Ordinary WARP traffic has no DesyncMark and cannot use this exception.
func fragmentComment(p FilterPlan) string { return "Zarp fragments " + p.Table }

type warpFirewall struct {
	NFTables []struct {
		Rule *struct {
			Handle  uint64 `json:"handle"`
			Comment string `json:"comment"`
			Expr    []struct {
				Match *struct {
					Op   string `json:"op"`
					Left struct {
						Payload *struct {
							Protocol string `json:"protocol"`
							Field    string `json:"field"`
						} `json:"payload"`
					} `json:"left"`
					Right any `json:"right"`
				} `json:"match"`
				Accept json.RawMessage `json:"accept"`
			} `json:"expr"`
		} `json:"rule"`
	} `json:"nftables"`
}

func readWarpFirewall(ctx context.Context) (warpFirewall, bool, error) {
	var result warpFirewall
	nft, err := SystemPath("nft")
	if err != nil {
		return result, false, err
	}
	out, err := Run(ctx, nft, nil, "-a", "-j", "list", "chain", "inet", "cloudflare-warp", "output")
	if err != nil {
		if strings.Contains(out, "No such file") || strings.Contains(out, "does not exist") {
			return result, false, nil
		}
		return result, false, errors.New("warp_fragment_firewall_unavailable")
	}
	if json.Unmarshal([]byte(out), &result) != nil {
		return result, false, errors.New("warp_fragment_firewall_invalid")
	}
	return result, true, nil
}

func (fw warpFirewall) endpointReady(target Target) bool {
	for _, entry := range fw.NFTables {
		if entry.Rule == nil {
			continue
		}
		address, port, accept := false, false, false
		for _, expr := range entry.Rule.Expr {
			if len(expr.Accept) > 0 {
				accept = true
			}
			match := expr.Match
			if match == nil || match.Op != "==" || match.Left.Payload == nil {
				continue
			}
			payload := match.Left.Payload
			if (payload.Protocol == "ip" || payload.Protocol == "ip6") && payload.Field == "daddr" && match.Right == target.Address.String() {
				address = true
			}
			if payload.Protocol == "udp" && payload.Field == "dport" && match.Right == float64(target.Port) {
				port = true
			}
		}
		if address && port && accept {
			return true
		}
	}
	return false
}

func enableWarpFragments(ctx context.Context, p FilterPlan) error {
	if !p.FragmentCompat {
		return nil
	}
	if _, err := NftRules(p); err != nil || p.WarpCgroup == "" || p.Payload != core.QUIC {
		return errors.New("invalid_fragment_scope")
	}
	for _, target := range p.Targets {
		if !target.UDP {
			return errors.New("invalid_fragment_scope")
		}
	}
	limit, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for {
		fw, exists, err := readWarpFirewall(limit)
		if err != nil {
			return err
		}
		ready := exists
		for _, target := range p.Targets {
			ready = ready && fw.endpointReady(target)
		}
		if ready {
			break
		}
		select {
		case <-limit.Done():
			return errors.New("warp_fragment_firewall_not_ready")
		case <-time.After(30 * time.Millisecond):
		}
	}
	nft, _ := SystemPath("nft")
	var rules strings.Builder
	seen := map[string]bool{}
	for _, target := range p.Targets {
		address := target.Address.String()
		if seen[address] {
			continue
		}
		seen[address] = true
		family := "ip"
		if target.Address.Is6() {
			family = "ip6"
		}
		fmt.Fprintf(&rules, "insert rule inet cloudflare-warp output oifname \"%s\" meta mark & 0x%x != 0 meta l4proto udp %s daddr %s counter accept comment \"%s\"\n", p.Interface, core.DesyncMark, family, address, fragmentComment(p))
	}
	if _, err := Run(limit, nft, []byte(rules.String()), "-f", "-"); err != nil {
		return errors.New("warp_fragment_firewall_install_failed")
	}
	fw, exists, err := readWarpFirewall(limit)
	if err != nil || !exists {
		return errors.New("warp_fragment_firewall_install_failed")
	}
	count := 0
	for _, entry := range fw.NFTables {
		if entry.Rule != nil && entry.Rule.Comment == fragmentComment(p) {
			count++
		}
	}
	if count != len(seen) {
		return errors.New("warp_fragment_firewall_install_failed")
	}
	return nil
}

func removeWarpFragments(ctx context.Context, p FilterPlan) error {
	if !p.FragmentCompat {
		return nil
	}
	if !tableID.MatchString(p.Table) {
		return errors.New("invalid_fragment_scope")
	}
	fw, exists, err := readWarpFirewall(ctx)
	if err != nil || !exists {
		return err
	}
	nft, _ := SystemPath("nft")
	for _, entry := range fw.NFTables {
		if entry.Rule == nil || entry.Rule.Comment != fragmentComment(p) {
			continue
		}
		if entry.Rule.Handle == 0 {
			return errors.New("warp_fragment_firewall_invalid")
		}
		out, err := Run(ctx, nft, nil, "delete", "rule", "inet", "cloudflare-warp", "output", "handle", fmt.Sprint(entry.Rule.Handle))
		if err != nil && !strings.Contains(out, "No such file") {
			return errors.New("warp_fragment_firewall_cleanup_failed")
		}
	}
	return nil
}
