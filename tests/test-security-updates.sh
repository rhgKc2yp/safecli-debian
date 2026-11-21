#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Static regression checks for Debian updates and unchanged publication gates.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

for profile in strict usb nested; do
  grep -Fqx 'FROM docker.io/library/debian:sid' "Containerfile.$profile"
  grep -Fq 'COPY scripts/install-cli-toolchain.sh /tmp/install-cli-toolchain.sh' "Containerfile.$profile"
done

installer=scripts/install-cli-toolchain.sh
grep -Fq 'APT::Update::Error-Mode=any update' "$installer"
grep -Fq 'apt-get -y full-upgrade' "$installer"
grep -Fq 'apt-get -y --no-install-recommends install' "$installer"
grep -Fq 'apt list --upgradable' "$installer"
grep -Fq 'apt-get clean' "$installer"
grep -Fqx '  fish' "$installer"
if grep -Eq '^fish_[a-z_]+=|sources.list.d|/etc/apt/keyrings|Pin-Priority:' "$installer"; then
  echo 'ERROR: fish must use only the default Debian package source.' >&2
  exit 1
fi

wf=.github/workflows/publish-ghcr.yml
grep -Fq -- "- cron: '23 4 */3 * *'" "$wf"
grep -Fq 'pull: true' "$wf"
grep -Fq 'no-cache: true' "$wf"
for action in checkout upload-artifact download-artifact attest; do
  grep -Eq "uses: actions/${action}@[0-9a-f]{40}([[:space:]]+#.*)?$" "$wf"
done
if grep -E '^[[:space:]]*(-[[:space:]]*)?uses:' .github/workflows/*.yml | \
   grep -Ev '@[0-9a-f]{40}([[:space:]]+#.*)?$'; then
  echo 'ERROR: All GitHub Actions must use full 40-character commit SHAs.' >&2
  exit 1
fi
grep -Fq 'sbom: true' "$wf"
grep -Fq 'run: bash scripts/generate-sboms.sh' "$wf"
grep -Fq 'subject-path: |' "$wf"
grep -Fq 'predicate-path: sboms/sbom-digests.json' "$wf"
grep -Fq 'predicate-type: https://github.com/' "$wf"
if grep -Fq 'sbom-path:' "$wf"; then
  echo 'Do not pass oversized full SBOMs as predicates.' >&2; exit 1
fi
grep -Fq -- '--platform "linux/$arch"' scripts/generate-sboms.sh
grep -Fq 'sha256sum "$amd64_file"' scripts/generate-sboms.sh
grep -Fq 'sha256sum "$arm64_file"' scripts/generate-sboms.sh
grep -Fq 'cosign sign --yes' "$wf"
grep -Fq 'bash scripts/promote-image.sh' "$wf"

if grep -ERq 'FROM docker.io/library/(fedora|debian:[0-9]+)' Containerfile.*; then
  echo 'ERROR: Base must track Debian sid rather than stable Fedora or a Debian release.' >&2
  exit 1
fi

grep -Fq 'MIT License' LICENSE
grep -Fq 'Copyright (c) 2026' LICENSE
grep -Fq 'upstream' THIRD_PARTY_NOTICES.md

echo 'Debian sid update and supply-chain safeguard checks passed.'
