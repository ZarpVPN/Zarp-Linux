#!/usr/bin/env bash
set -euo pipefail
case "${1:?Specify ubuntu, debian, fedora or arch}" in
  ubuntu|debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
      build-essential pkg-config liblua5.4-dev libnetfilter-queue-dev libmnl-dev zlib1g-dev \
      python3 python3-yaml python3-cryptography python3-pyside6.qtwidgets python3-pyside6.qttest \
      qt6-qpa-plugins qt6-wayland fonts-dejavu-core fonts-noto-core \
      nftables iptables iproute2 gnupg gpgv polkitd pkexec dbus util-linux passwd tar gzip findutils xz-utils
    ;;
  fedora)
    dnf install -y \
      gcc gcc-c++ make pkgconf-pkg-config lua-devel libnetfilter_queue-devel libmnl-devel zlib-devel \
      python3 python3-pyyaml python3-cryptography python3-pyside6 qt6-qtbase qt6-qtwayland \
      dejavu-sans-fonts google-noto-sans-fonts \
      nftables iptables-nft iproute gnupg2 polkit dbus util-linux shadow-utils rpm-build tar gzip findutils xz
    ;;
  arch)
    pacman -Syu --noconfirm --needed \
      base-devel lua54 libnetfilter_queue libmnl zlib python python-yaml python-cryptography pyside6 \
      qt6-base qt6-wayland ttf-dejavu noto-fonts \
      nftables iptables iproute2 gnupg polkit dbus util-linux shadow tar gzip findutils xz
    ;;
  *) echo 'Unsupported distribution' >&2; exit 1 ;;
esac
if ! id zarpbuild >/dev/null 2>&1; then
  useradd --create-home zarpbuild
fi
