#!/usr/bin/env python3
"""Install a locally built native package. Never start WARP or change routes."""
import argparse
from pathlib import Path
import subprocess

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=('ubuntu', 'debian', 'fedora', 'arch'), required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    suffix = {'ubuntu': '.deb', 'debian': '.deb', 'fedora': '.rpm', 'arch': '.pkg.tar.zst'}[args.platform]
    packages = sorted(path for path in args.directory.glob('zarp*') if path.name.endswith(suffix))
    if len(packages) != 1:
        parser.error('Expected exactly one freshly built package')
    package = str(packages[0].resolve())
    if args.platform in ('ubuntu', 'debian'):
        command = ['dpkg', '-i', package]
    elif args.platform == 'fedora':
        command = ['rpm', '-Uvh', '--replacepkgs', package]
    else:
        command = ['pacman', '-U', '--noconfirm', package]
    subprocess.run(command, check=True)

if __name__ == '__main__':
    main()
