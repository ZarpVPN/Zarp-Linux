#!/usr/bin/env bash
set -euo pipefail
source_dir=${1:?Specify the nfq2 source directory}
lua_pkg=''
for candidate in lua54 lua5.4 lua-5.4 lua; do
    if pkg-config --exists "$candidate"; then
        version=$(pkg-config --modversion "$candidate")
        case "$version" in
            5.4|5.4.*) lua_pkg=$candidate; break ;;
        esac
    fi
done
if [ -z "$lua_pkg" ]; then
    echo 'Lua 5.4 development files not found through pkg-config.' >&2
    exit 1
fi
echo "Building nfqws2 with Lua $version ($lua_pkg)"
make_args=(LUA_JIT=0 LUA_VER=5.4 "LUA_CFLAGS=$(pkg-config --cflags "$lua_pkg")" "LUA_LIB=$(pkg-config --libs "$lua_pkg")")
make -C "$source_dir" "${make_args[@]}" clean
make -C "$source_dir" "${make_args[@]}" -j2
