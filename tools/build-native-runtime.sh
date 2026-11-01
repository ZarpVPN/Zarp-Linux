#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd "$(dirname "$0")/.." && pwd)
build_dir=${1:?Specify a native build directory}
mkdir -p "$build_dir"
mkdir -p "$build_dir/source"
cp -a "$project_dir/vendor/zapret2-src/nfq2" "$build_dir/source/"
lua_pkg=''
for candidate in lua54 lua5.4 lua-5.4 lua; do
    if pkg-config --exists "$candidate"; then lua_pkg=$candidate; break; fi
done
test -n "$lua_pkg"
make -C "$build_dir/source/nfq2" LUA_JIT=0 LUA_VER=5.4 "LUA_CFLAGS=$(pkg-config --cflags "$lua_pkg")" "LUA_LIB=$(pkg-config --libs "$lua_pkg")" clean
make -C "$build_dir/source/nfq2" LUA_JIT=0 "LUA_CFLAGS=$(pkg-config --cflags "$lua_pkg")" "LUA_LIB=$(pkg-config --libs "$lua_pkg")" -j2
mkdir -p "$build_dir/runtime"
cp -a "$project_dir/vendor/runtime/." "$build_dir/runtime/"
cp "$build_dir/source/nfq2/nfqws2" "$build_dir/runtime/nfqws2"
find "$build_dir/runtime" -type d -exec chmod 755 {} +
find "$build_dir/runtime" -type f -exec chmod 644 {} +
chmod 755 "$build_dir/runtime/nfqws2" "$build_dir/runtime/sing-box" "$build_dir/runtime/xray"
python3 "$project_dir/tools/refresh-runtime.py" "$build_dir/runtime"
ldd "$build_dir/runtime/nfqws2"
