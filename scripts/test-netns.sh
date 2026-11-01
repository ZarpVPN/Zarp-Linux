#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${ZARP_NETNS_TEST:-}" != 1 ]; then
    test "$(id -u)" = 0 || { echo 'Run with sudo; the test creates a separate network namespace.' >&2; exit 1; }
    for tool in nft iptables-nft ip6tables-nft ip unshare go; do
        command -v "$tool" >/dev/null || { echo "Missing packet-test dependency: $tool" >&2; exit 1; }
    done
    mkdir -p build
    CGO_ENABLED=0 go test -buildvcs=false -c -o build/linux-netns.test ./internal/linux
    exec unshare --net env ZARP_NETNS_TEST=1 bash "$0"
fi
test "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" || { echo 'Refusing to change the initial network namespace.' >&2; exit 1; }
work=$(mktemp -d /tmp/zarp-netns.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
cp -a "${ZARP_TEST_RUNTIME:-$PWD/vendor/runtime}" "$work/runtime"
chown -R root:root "$work"
find "$work" -type d -exec chmod 755 {} +
find "$work" -type f -exec chmod 644 {} +
chmod 755 "$work/runtime/nfqws2" "$work/runtime/sing-box" "$work/runtime/xray"
ip link set lo up
export ZARP_TEST_RUNTIME="$work/runtime"
export ZARP_PROJECT_ROOT="$PWD"
build/linux-netns.test -test.run '^TestNetns' -test.v -test.timeout 90s
