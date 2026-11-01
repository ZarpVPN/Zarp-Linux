#!/usr/bin/env python3
"""Prepare pinned Linux engines. Downloads never execute installation scripts."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "resources/engines.json").read_text())
OUT = ROOT / "vendor/runtime"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Zarp-Linux-build"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(100 * 1024 * 1024 + 1)
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("runtime download exceeds limit")
    return data


def main():
    if os.uname().machine != "x86_64":
        raise SystemExit("The runtime lock supports Linux x86_64")
    OUT.mkdir(parents=True, exist_ok=True)
    binary_pins = {}
    for engine in LOCK["engines"]:
        archive_path = ROOT / "vendor" / (engine["name"] + ".archive")
        data = archive_path.read_bytes() if archive_path.exists() else fetch(engine["url"])
        if hashlib.sha256(data).hexdigest() != engine["sha256"]:
            raise ValueError("archive integrity check failed: " + engine["name"])
        archive_path.write_bytes(data)
        if engine["url"].endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                binary = archive.read("xray")
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                member = next(m for m in archive.getmembers() if m.isfile() and Path(m.name).name == engine["name"])
                binary = archive.extractfile(member).read()
        target = OUT / engine["name"]
        target.write_bytes(binary)
        target.chmod(0o755)
        binary_pins[engine["name"]] = hashlib.sha256(binary).hexdigest()
        print(engine["name"] + " " + engine["version"] + " verified", flush=True)

    source = ROOT / "vendor/zapret2-src"
    if not source.exists():
        subprocess.run(["git", "clone", "https://github.com/bol-van/zapret2.git", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "checkout", "--detach", LOCK["zapretCommit"]], check=True)
    subprocess.run(["bash", str(ROOT / "tools/build-nfqws.sh"), str(source / "nfq2")], check=True)
    shutil.copyfile(source / "nfq2/nfqws2", OUT / "nfqws2")
    (OUT / "nfqws2").chmod(0o755)
    for name in ("zapret-lib.lua", "zapret-antidpi.lua"):
        (OUT / "lua").mkdir(exist_ok=True)
        shutil.copyfile(source / "lua" / name, OUT / "lua" / name)
    shutil.copyfile(ROOT / "resources/zarp-observe.lua", OUT / "lua/zarp-observe.lua")
    compact = ROOT / "resources/quic_vk_1200.bin"
    if hashlib.sha256(compact.read_bytes()).hexdigest() != "ea1675a7209961b6ed75c0f736bce6f5b4f0b4744bf27f79bb017e6bcd13d06f":
        raise ValueError("Compact VK resource changed; verify with compact-quic-fake.py")
    (OUT / "blobs").mkdir(exist_ok=True)
    shutil.copyfile(compact, OUT / "blobs/quic_vk_1200.bin")
    key = (ROOT / "resources/cloudflare-warp-keyring.gpg").read_bytes()
    if hashlib.sha256(key).hexdigest() != "5697798dcaa90492b359d9057f1a0bad7ed7dfc3b9fcd9363bf4e9f42f0f245b":
        raise ValueError("Cloudflare signing key changed; review the key rotation")
    (OUT / "cloudflare-warp-keyring.gpg").write_bytes(key)
    blobs = {"quic_google": "quic_initial_www_google_com.bin", "quic_vk": "quic_initial_vk_com.bin", "tls_google": "tls_clienthello_www_google_com.bin", "tls_vk": "tls_clienthello_vk_com.bin", "tls_gosuslugi": "tls_clienthello_gosuslugi_ru.bin", "stun": "stun.bin"}
    (OUT / "blobs").mkdir(exist_ok=True)
    for name, original in blobs.items():
        shutil.copyfile(source / "files/fake" / original, OUT / "blobs" / (name + ".bin"))
    (OUT / "licenses").mkdir(exist_ok=True)
    shutil.copyfile(source / "docs/LICENSE.txt", OUT / "licenses/zapret2.txt")
    for name in ("sing-box", "xray", "GPL-3.0"):
        shutil.copyfile(ROOT / "resources/licenses" / (name + ".txt"), OUT / "licenses" / (name + ".txt"))
    pins = {str(path.relative_to(OUT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in OUT.rglob("*") if path.is_file() and path.name != "integrity.json"}
    (OUT / "integrity.json").write_text(json.dumps({"schema": 1, "versions": {"zapret2": LOCK["zapretCommit"], **{e["name"]: e["version"] for e in LOCK["engines"]}}, "files": pins}, indent=2) + "\n")
    print("runtime prepared: " + str(OUT), flush=True)


if __name__ == "__main__":
    main()
