#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Verify shared Debian sid CLI packages and three unchanged isolation profiles.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

toolchain=scripts/install-cli-toolchain.sh
bash -n "$toolchain"

for profile in strict usb nested; do
  file="Containerfile.$profile"
  [[ -f "$file" ]]
  grep -Fqx 'FROM docker.io/library/debian:sid' "$file"
  grep -Fq 'COPY scripts/install-cli-toolchain.sh /tmp/install-cli-toolchain.sh' "$file"
  grep -Fq 'RUN bash /tmp/install-cli-toolchain.sh' "$file"
  grep -Fq 'SHELL=/usr/bin/fish' "$file"
  grep -Fq 'NPM_CONFIG_PREFIX=/work/.npm-global' "$file"
  grep -Fq 'CARGO_HOME=/work/.cargo' "$file"
  grep -Fq 'GOPATH=/work/go' "$file"
  grep -Fq 'GOBIN=/work/go/bin' "$file"
  grep -Fq '/work/.npm-global/bin:/work/.local/bin:/work/.cargo/bin:/work/go/bin' "$file"
  grep -Fqx 'CMD ["/usr/bin/fish"]' "$file"
  if grep -Eq 'dnf|fedora:|libusb1-devel|rpmkeys' "$file"; then
    echo "Unexpected Fedora-specific instructions in $file" >&2
    exit 1
  fi
done

for deb in \
  fish nano nodejs npm libnode-dev node-corepack python3 python-is-python3 python3-pip \
  python3-dev python3-venv python3-virtualenv pipx rustc cargo golang curl wget unzip \
  gcc g++ make pkg-config libssl-dev libffi-dev zlib1g-dev; do
  grep -Fqx "  $deb" "$toolchain"
done

for excluded in gh ruby ruby-dev rubygems bundler php-cli lua default-jre clang git-lfs \
                pnpm yarn zypper; do
  if grep -Fqx "  $excluded" "$toolchain"; then
    echo "Nonessential DEB unexpectedly included: $excluded" >&2
    exit 1
  fi
done

grep -Fqx '!scripts/install-cli-toolchain.sh' .dockerignore
grep -Fq 'usbutils' Containerfile.usb
grep -Fq 'libusb-1.0-0' Containerfile.usb
grep -Fq 'libusb-1.0-0-dev' Containerfile.usb
grep -Fq 'bubblewrap' Containerfile.nested
grep -Fqx '  util-linux' "$toolchain"
grep -Fq 'pipx install --global uv' "$toolchain"

echo 'Debian sid CLI toolchain and Containerfile checks passed.'
