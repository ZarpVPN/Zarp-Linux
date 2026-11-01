#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd "$(dirname "$0")/.." && pwd)
build_dir=${1:?Specify a native build directory}
mkdir -p "$build_dir"
mkdir -p "$build_dir/source"
cp -a "$project_dir/vendor/zapret2-src/nfq2" "$build_dir/source/"
bash "$project_dir/tools/build-nfqws.sh" "$build_dir/source/nfq2"
mkdir -p "$build_dir/runtime"
cp -a "$project_dir/vendor/runtime/." "$build_dir/runtime/"
cp "$build_dir/source/nfq2/nfqws2" "$build_dir/runtime/nfqws2"
find "$build_dir/runtime" -type d -exec chmod 755 {} +
find "$build_dir/runtime" -type f -exec chmod 644 {} +
chmod 755 "$build_dir/runtime/nfqws2" "$build_dir/runtime/sing-box" "$build_dir/runtime/xray"
python3 "$project_dir/tools/refresh-runtime.py" "$build_dir/runtime"
ldd "$build_dir/runtime/nfqws2"
