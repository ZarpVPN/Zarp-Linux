package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
)

// xt_cgroup uses the socket's cgroup v2 identity, including sockets that already
// exist. Unlike nft's socket expression, it is enabled in the stock WSL kernel.
// Only an owned chain and its exact OUTPUT jump are added to each IP family.
func compatChain(p FilterPlan) string { return "ZARP_" + strings.TrimPrefix(p.Table, "zarp_") }

func validCgroup(group string) bool {
	if !cgroupID.MatchString(group) {
		return false
	}
	for _, component := range strings.Split(group, "/") {
		if component == "." || component == ".." {
			return false
		}
	}
	return true
}

func currentCgroup() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if group, ok := strings.CutPrefix(line, "0::/"); ok && validCgroup(group) {
				return group, nil
			}
		}
	}
	return "", errors.New("cgroup_v2_scope_unavailable")
}

func compatRules(p FilterPlan, remove bool) (string, error) {
	if !tableID.MatchString(p.Table) || !validCgroup(p.WarpCgroup) {
		return "", errors.New("invalid_warp_cgroup")
	}
	chain := compatChain(p)
	if remove {
		return fmt.Sprintf("*mangle\n-D OUTPUT -m cgroup --path %s -j %s\n-F %s\n-X %s\nCOMMIT\n", p.WarpCgroup, chain, chain, chain), nil
	}
	// WARP exempts its outer sockets from tunnel routing with its own SO_MARK.
	// Changing the packet mark in OUTPUT reroutes those packets into the tunnel.
	// Keep that mark intact and tag conntrack state for our nftables classifier.
	return fmt.Sprintf("*mangle\n:%s - [0:0]\n-A %s -j CONNMARK --or-mark 0x%x\n-I OUTPUT 1 -m cgroup --path %s -j %s\nCOMMIT\n", chain, chain, core.SocketMark, p.WarpCgroup, chain), nil
}

func runCompat(ctx context.Context, family string, data string, test bool) error {
	tool, err := SystemPath(family + "tables-nft-restore")
	if err != nil {
		return errors.New("warp_cgroup_compat_tools_missing")
	}
	args := []string{"--wait", "2", "--noflush"}
	if test {
		args = append(args, "--test")
	}
	if _, err = Run(ctx, tool, []byte(data), args...); err != nil {
		return errors.New("warp_cgroup_compat_failed")
	}
	return nil
}

func checkCompatScope(ctx context.Context) error {
	group, err := currentCgroup()
	if err != nil {
		return err
	}
	plan := FilterPlan{Table: "zarp_" + randomToken(8), WarpCgroup: group}
	rules, _ := compatRules(plan, false)
	for _, family := range []string{"ip", "ip6"} {
		if _, err = SystemPath(family + "tables-nft"); err != nil {
			return errors.New("warp_cgroup_compat_tools_missing")
		}
		if err = runCompat(ctx, family, rules, true); err != nil {
			return err
		}
	}
	return nil
}

func installCompatScope(ctx context.Context, p FilterPlan) error {
	rules, err := compatRules(p, false)
	if err != nil {
		return err
	}
	for _, family := range []string{"ip", "ip6"} {
		if err = runCompat(ctx, family, rules, false); err != nil {
			return err
		}
	}
	return nil
}

func removeCompatScope(ctx context.Context, p FilterPlan) error {
	rules, err := compatRules(p, true)
	if err != nil {
		return err
	}
	for _, family := range []string{"ip", "ip6"} {
		tool, err := SystemPath(family + "tables-nft")
		if err != nil {
			return err
		}
		out, listErr := Run(ctx, tool, nil, "--wait", "2", "-t", "mangle", "-S", compatChain(p))
		if listErr != nil {
			if strings.Contains(out, "No chain/target/match by that name") || strings.Contains(out, "does not exist") {
				continue
			}
			return errors.New("warp_cgroup_cleanup_failed")
		}
		if err = runCompat(ctx, family, rules, false); err != nil {
			return errors.New("warp_cgroup_cleanup_failed")
		}
	}
	return nil
}
