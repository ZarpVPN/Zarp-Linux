package linux

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/ZarpVPN/Zarp-Linux/internal/core"
)

func warpMSS(iface string) (uint16, error) {
	mtu, err := linkMTU(iface)
	if err != nil {
		return 0, err
	}
	return warpMSSForMTU(mtu)
}

func linkMTU(iface string) (int, error) {
	if !identifier.MatchString(iface) {
		return 0, errors.New("network_mtu_unavailable")
	}
	// A sysfs mount can refer to a different netns after unshare/setns.
	link, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, errors.New("network_mtu_unavailable")
	}
	mtu := link.MTU
	if mtu < 1 || mtu > 65536 {
		return 0, errors.New("network_mtu_unavailable")
	}
	return mtu, nil
}

func strategyBlobPaths(runtime *Runtime, plan FilterPlan, strategy core.Strategy) (map[string]string, error) {
	paths := map[string]string{}
	for _, name := range []string{"quic_google", "quic_vk", "tls_google", "tls_vk", "tls_gosuslugi", "stun"} {
		paths[name] = runtime.Path("blobs/" + name + ".bin")
	}
	if strategy.Transport == core.TLS {
		return paths, nil
	}
	mtu, err := linkMTU(plan.Interface)
	if err != nil {
		return nil, err
	}
	header := 28 // IPv4 + UDP; use IPv6 headers when any target needs them.
	for _, target := range plan.Targets {
		if target.Address.Is6() {
			header = 48
		}
	}
	for _, arg := range strategy.Args {
		params, ok := strings.CutPrefix(arg, "--lua-desync=fake:")
		if !ok {
			continue
		}
		fragmented := false
		blob := ""
		for _, param := range strings.Split(params, ":") {
			if param == "ipfrag" || strings.HasPrefix(param, "ipfrag=") {
				fragmented = true
			}
			if value, ok := strings.CutPrefix(param, "blob="); ok {
				blob = value
			}
		}
		if blob == "" || fragmented {
			continue
		}
		// ValidateStrategy restricts blob identifiers to the bundled allowlist.
		data, err := os.Stat(paths[blob])
		if err != nil {
			return nil, errors.New("runtime_file_missing")
		}
		minimum := data.Size() + int64(header)
		if minimum > int64(mtu) && blob == "quic_vk" {
			const compact = "blobs/quic_vk_1200.bin"
			if _, ok := runtime.Manifest.Files[compact]; ok {
				data, err = os.Stat(runtime.Path(compact))
				if err != nil || data.Size() != 1200 {
					return nil, errors.New("runtime_compact_quic_invalid")
				}
				paths[blob] = runtime.Path(compact)
				minimum = data.Size() + int64(header)
			}
		}
		if minimum > int64(mtu) {
			return nil, fmt.Errorf("strategy_mtu_incompatible:%d:%d", mtu, minimum)
		}
	}
	return paths, nil
}

func warpMSSForMTU(mtu int) (uint16, error) {
	if mtu < 1280 || mtu > 65535 {
		return 0, errors.New("warp_link_mtu_too_small")
	}
	// Reserve a conservative MASQUE/QUIC envelope and IPv6 + TCP headers.
	// The official client currently exposes a 1280-byte inner TUN.
	mss := mtu - 128 - 60
	if mss >= 1220 {
		return 0, nil
	}
	return uint16(mss), nil
}
