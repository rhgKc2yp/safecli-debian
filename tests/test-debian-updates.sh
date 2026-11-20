#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Test the Debian-only package installation and pending-update gate offline.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
installer="$PWD/scripts/install-cli-toolchain.sh"
test_dir=$(mktemp -d)
trap '/usr/bin/rm -r "$test_dir"' EXIT
mkdir -p "$test_dir/bin"

cat > "$test_dir/bin/apt-get" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_APT_CALLS"
exit "${MOCK_APT_STATUS:-0}"
MOCK
cat > "$test_dir/bin/apt" <<'MOCK'
#!/usr/bin/env bash
printf 'Listing...\n'
if [[ ${MOCK_PENDING:-0} == 1 ]]; then
  printf 'openssl/sid 9.9.9 amd64 [upgradable from: 1.0]\n'
fi
MOCK
cat > "$test_dir/bin/pipx" <<'MOCK'
#!/usr/bin/env bash
[[ $* == 'install --global uv' && ${MOCK_PIPX_FAIL:-0} == 0 ]]
MOCK
cat > "$test_dir/bin/fish" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "${MOCK_FISH_VERSION:-fish, version 99.0.0}"
MOCK
cat > "$test_dir/bin/ln" <<'MOCK'
#!/usr/bin/env bash
[[ $1 == -s && $3 == /usr/local/bin/* ]]
MOCK
# Running the installer's cleanup must not modify the host's package cache.
cat > "$test_dir/bin/rm" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
chmod +x "$test_dir/bin/"*

for binary in nano node npm npx corepack pnpm pnpx yarn yarnpkg python python3 pip3 \
              virtualenv uv rustc cargo go; do
  ln -s /usr/bin/true "$test_dir/bin/$binary"
done

# Replace just the Corepack shim read path in the test copy.
mock_installer="$test_dir/install-cli-toolchain.sh"
sed 's@/usr/share/nodejs/corepack/shims/@'"$test_dir"'/bin/@g' \
  "$installer" > "$mock_installer"

export PATH="$test_dir/bin:$PATH" MOCK_APT_CALLS="$test_dir/apt.calls"
if ! bash "$mock_installer" > "$test_dir/clean.log" 2> "$test_dir/clean.err"; then
  echo 'ERROR: Mocked Debian installer unexpectedly failed:' >&2
  sed -n '1,80p' "$test_dir/clean.err" >&2
  exit 1
fi
grep -Fq 'full-upgrade' "$MOCK_APT_CALLS"
grep -Fq -- '--no-install-recommends install bash fish nano' "$MOCK_APT_CALLS"

if MOCK_PENDING=1 bash "$mock_installer" > "$test_dir/pending.log" 2>&1; then
  echo 'ERROR: Pending Debian upgrades were accepted.' >&2; exit 1
fi
grep -Fq 'pending upgrades' "$test_dir/pending.log"

if MOCK_APT_STATUS=42 bash "$mock_installer" > "$test_dir/apt-fail.log" 2>&1; then
  echo 'ERROR: Failed apt operation was accepted.' >&2; exit 1
fi

if MOCK_PIPX_FAIL=1 bash "$mock_installer" > "$test_dir/uv-fail.log" 2>&1; then
  echo 'ERROR: Failed uv installation was accepted.' >&2; exit 1
fi

if MOCK_FISH_VERSION='invalid shell' bash "$mock_installer" > "$test_dir/fish-fail.log" 2>&1; then
  echo 'ERROR: Invalid fish version output was accepted.' >&2; exit 1
fi

echo 'Debian-only installation and update failure checks passed.'
