#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Shared Debian sid CLI toolchain for strict, usb and nested images.
# Additional arguments are profile-specific DEB packages.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

packages=(
  # Essential shells, downloads and Git transport.
  bash
  fish
  nano
  ca-certificates
  curl
  wget
  openssl
  git
  openssh-client

  # Standard UNIX tools, archives and text processing.
  coreutils
  findutils
  diffutils
  grep
  sed
  gawk
  # Debian's essential debianutils package already provides 'which'.
  file
  less
  procps
  util-linux
  tar
  gzip
  bzip2
  xz-utils
  zstd
  zip
  unzip
  patch
  jq
  ripgrep

  # Debian sid packages Node, npm and Corepack separately. The distribution
  # currently packages Node 24/npm 12 rather than Fedora's Node 26/npm 11.
  nodejs
  npm
  libnode-dev
  node-corepack

  # Python 3, both interpreter names, pip, venv, virtualenv and pipx.
  python3
  python-is-python3
  python3-pip
  python3-dev
  python3-venv
  python3-virtualenv
  pipx

  # Rust and Go compilers / package managers.
  rustc
  cargo
  golang

  # Minimal native-build prerequisites for Node/Python/Rust dependencies.
  gcc
  g++
  make
  cmake
  pkg-config
  libssl-dev
  libffi-dev
  zlib1g-dev
)

# Sid has no separate security pocket/advisory class. Refresh and install all
# available upgrades; a pending upgrade after installation must fail the build.
apt-get -o APT::Update::Error-Mode=any update
apt-get -y full-upgrade
apt-get -y --no-install-recommends install "${packages[@]}" "$@"

# The Debian Corepack package ships shims under /usr/share, but unlike Fedora
# does not expose pnpm/yarn in /usr/bin. Expose exactly those existing shims.
for shim in pnpm pnpx yarn yarnpkg; do
  [[ -f "/usr/share/nodejs/corepack/shims/$shim" ]] || {
    echo "ERROR: Missing Debian Corepack shim: $shim" >&2; exit 1;
  }
  ln -s "/usr/share/nodejs/corepack/shims/$shim" "/usr/local/bin/$shim"
done

# Debian sid currently ships only the uv-build backend, not the uv CLI.
# Install the missing original-project CLI using pipx's isolated global venv;
# this adds uv (and uvx), not another language runtime or system package.
pipx install --global uv

echo 'Checking Debian package updates still pending...'
pending_updates=$(apt list --upgradable 2>/dev/null | sed '1d')
if [[ -n "$pending_updates" ]]; then
  echo 'ERROR: Debian packages still have pending upgrades:' >&2
  printf '%s\n' "$pending_updates" >&2
  exit 1
fi

apt-get clean
rm -rf /var/lib/apt/lists/*

# Fail image builds if the distribution stops exposing a required CLI.
for binary in fish nano node npm npx corepack pnpm yarn python python3 pip3 virtualenv pipx uv rustc cargo go; do
  command -v "$binary" >/dev/null || {
    echo "Missing expected executable after installation: $binary" >&2
    exit 1
  }
done
[[ $(readlink -f "$(command -v python)") == "$(readlink -f "$(command -v python3)")" ]] || {
  echo 'Expected python to resolve to the same Python 3 interpreter as python3.' >&2
  exit 1
}
[[ $(fish --version) == 'fish, version '* ]] || {
  echo 'Expected a working Debian fish shell.' >&2; exit 1;
}
