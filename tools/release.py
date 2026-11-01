#!/usr/bin/env python3
"""Validate release versions and assemble a complete four-platform release."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from string import Template

ROOT = Path(__file__).resolve().parents[1]
ASSETS = {
    'ubuntu': 'zarp-ubuntu-amd64.deb',
    'debian': 'zarp-debian-amd64.deb',
    'fedora': 'zarp-fedora-x86_64.rpm',
    'arch': 'zarp-arch-x86_64.pkg.tar.zst',
}
SUFFIXES = {'ubuntu': '.deb', 'debian': '.deb', 'fedora': '.rpm', 'arch': '.pkg.tar.zst'}
PLATFORMS = {'ubuntu': 'Ubuntu 26.04', 'debian': 'Debian 13', 'fedora': 'Fedora 44', 'arch': 'Arch Linux'}

def release_notes(source_version, packages):
    entries = {info['platform']: info for info in packages}
    base = 'https://github.com/ZarpVPN/Zarp-Linux/releases/download/v' + source_version + '/'
    downloads = '| System | Package |\n| --- | --- |\n'
    downloads += '\n'.join(f'| {label} | [{ASSETS[platform]}]({base}{ASSETS[platform]}) |' for platform, label in PLATFORMS.items())
    checksums = '\n'.join(entries[platform]['sha256'] + '  ' + ASSETS[platform] for platform in ASSETS)
    versions = packages[0]['runtime']
    runtimes = '| Engine | Version |\n| --- | --- |\n'
    runtimes += '\n'.join(f'| {name} | `{value}` |' for name, value in versions.items())
    template = Template((ROOT / 'resources/release-notes.md').read_text(encoding='utf-8'))
    return template.substitute(version=source_version, downloads=downloads, checksums=checksums, runtimes=runtimes)

def version():
    match = re.search(r'^const Version = "([^"]+)"$', (ROOT / 'internal/core/types.go').read_text(), re.M)
    if not match or not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', match[1]):
        raise ValueError('Source version must be a stable MAJOR.MINOR.PATCH value')
    return match[1]

def validate_tag(source_version, tag):
    if tag != 'v' + source_version:
        raise ValueError(f'Release tag {tag!r} does not match source version v{source_version}')

def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()

def regular_file(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected a regular file: ' + str(path))

def stage(platform, directory, runtime, output):
    source_version = version()
    packages = sorted(p for p in directory.glob('zarp*') if p.name.endswith(SUFFIXES[platform]))
    if len(packages) != 1:
        raise ValueError('Expected exactly one freshly built package')
    package = packages[0]
    regular_file(package)
    if not package.name.startswith(('zarp-' + source_version + '-', 'zarp_' + source_version + '-')):
        raise ValueError('Package filename does not match source version')
    expected = package.with_name(package.name + '.sha256')
    regular_file(expected)
    checksum = sha256(package)
    if expected.read_text().split()[0] != checksum:
        raise ValueError('Package SHA-256 does not match its build output')
    manifest = json.loads((runtime / 'integrity.json').read_text())
    if manifest.get('schema') != 1 or not manifest.get('files'):
        raise ValueError('Invalid runtime manifest')
    for name, digest in manifest['files'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or '\\' in name:
            raise ValueError('Unsafe runtime member')
        member = runtime / relative
        regular_file(member)
        if sha256(member) != digest:
            raise ValueError('Runtime integrity failure: ' + name)
    commit = os.environ.get('GITHUB_SHA', '')
    if commit and not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', commit):
        raise ValueError('Invalid source commit')
    output.mkdir(parents=True, exist_ok=True)
    asset = output / ASSETS[platform]
    if asset.exists():
        raise ValueError('Release output must be fresh')
    shutil.copyfile(package, asset)
    info = {
        'schema': 1, 'platform': platform, 'version': source_version, 'commit': commit or None,
        'file': asset.name, 'size': asset.stat().st_size, 'sha256': checksum,
        'package': package.name, 'runtime': manifest['versions'],
    }
    (output / (platform + '.json')).write_text(json.dumps(info, indent=2) + '\n')
    return info

def collect(source, output):
    source_version = version()
    entries = {}
    for path in sorted(source.rglob('*.json')):
        regular_file(path)
        info = json.loads(path.read_text())
        platform = info.get('platform')
        if platform not in ASSETS or platform in entries or info.get('schema') != 1:
            raise ValueError('Unexpected or duplicate release metadata')
        if info.get('version') != source_version or info.get('file') != ASSETS[platform]:
            raise ValueError('Release metadata does not match this version/platform')
        asset = path.parent / ASSETS[platform]
        regular_file(asset)
        if asset.stat().st_size != info.get('size') or sha256(asset) != info.get('sha256'):
            raise ValueError('Downloaded artifact failed integrity verification')
        entries[platform] = (info, asset)
    if set(entries) != set(ASSETS):
        raise ValueError('Release requires Ubuntu, Debian, Fedora and Arch packages')
    if len({entry[0].get('commit') for entry in entries.values()}) != 1:
        raise ValueError('Packages were built from different source commits')
    output.mkdir(parents=True, exist_ok=True)
    checksums = []
    packages = []
    for platform in ASSETS:
        info, asset = entries[platform]
        target = output / asset.name
        if target.exists():
            raise ValueError('Release output must be fresh')
        shutil.copyfile(asset, target)
        checksums.append(info['sha256'] + '  ' + asset.name)
        packages.append(info)
    (output / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n')
    (output / 'release-manifest.json').write_text(json.dumps({'schema': 1, 'version': source_version, 'packages': packages}, indent=2) + '\n')
    (output / 'notes.md').write_text(release_notes(source_version, packages), encoding='utf-8')
    return packages

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    check = commands.add_parser('version')
    check.add_argument('--github-output', type=Path)
    package = commands.add_parser('stage')
    package.add_argument('--platform', choices=ASSETS, required=True)
    package.add_argument('--directory', type=Path, required=True)
    package.add_argument('--runtime', type=Path, required=True)
    package.add_argument('--output', type=Path, required=True)
    release = commands.add_parser('collect')
    release.add_argument('--input', type=Path, required=True)
    release.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'version':
        current = version()
        if os.environ.get('GITHUB_REF_TYPE') == 'tag':
            validate_tag(current, os.environ.get('GITHUB_REF_NAME', ''))
        if args.github_output:
            with args.github_output.open('a') as target:
                target.write('version=' + current + '\n')
        print(current)
    elif args.command == 'stage':
        print(json.dumps(stage(args.platform, args.directory, args.runtime, args.output)))
    else:
        print('Verified complete release:', len(collect(args.input, args.output)), 'packages')

if __name__ == '__main__':
    main()
