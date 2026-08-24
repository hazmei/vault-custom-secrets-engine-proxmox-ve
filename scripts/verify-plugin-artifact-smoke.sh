#!/usr/bin/env bash

set -eu

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
verifier="$script_dir/verify-plugin-artifact.sh"

# The verifier requires GNU coreutils/findutils (sha256sum, GNU `stat -c`, and
# `find -perm /022`) and prints a FAIL line for each that is missing. The smoke
# checks assert the verifier exits 0, so on a platform without those tools
# (notably macOS/BSD, this repo's dev platform per CLAUDE.md) every positive
# assertion fails with the opaque "direct positive: rc=1 want=0" — the exact
# message this script exists to prevent. Probe the same three tools up front and
# skip cleanly, mirroring the verifier's own probes and the "shellcheck not
# installed; skipping" branch in `make lint`.
tools_ok=1
command -v sha256sum >/dev/null 2>&1 && sha256sum /dev/null >/dev/null 2>&1 || tools_ok=0
command -v stat >/dev/null 2>&1 && stat -c '%U:%G' / >/dev/null 2>&1 || tools_ok=0
command -v find >/dev/null 2>&1 && find / -maxdepth 0 -perm /022 -print -quit >/dev/null 2>&1 || tools_ok=0
if [ "$tools_ok" -ne 1 ]; then
  echo "skipping plugin artifact smoke checks: GNU coreutils/findutils required" >&2
  echo "(brew install coreutils findutils, or run in CI on Linux)" >&2
  exit 0
fi

fixture_base=${RUNNER_TEMP:-$script_dir/../.smoke-tmp}
if ! mkdir -p "$fixture_base"; then
  echo "cannot create fixture base $fixture_base" >&2
  exit 1
fi
if ! fixture_base=$(cd -- "$fixture_base" && pwd -P); then
  echo "cannot resolve fixture base ${RUNNER_TEMP:-$script_dir/../.smoke-tmp}" >&2
  exit 1
fi

# The verifier walks every ancestor of PLUGIN_DIR up to / and fails on any
# group/other-writable directory, so the fixture's own location decides whether
# the positive assertions can pass at all. Check that ancestry up front: without
# this, a checkout under a shared path (/srv/src, a shared dev box, some
# container images) fails with "direct positive: rc=1 want=0" and nothing points
# at the fixture directory as the cause. Distinguish "not writable" from "the
# check itself failed" (unreadable dir, or find errored) so a broken probe is
# never silently read as OK — matching verify-plugin-artifact.sh.
p=$fixture_base
while :; do
  if ! writable=$(find "$p" -maxdepth 0 -perm /022 -print -quit 2>&1); then
    echo "cannot run smoke checks: cannot stat $p: $writable" >&2
    exit 1
  fi
  if [ -n "$writable" ]; then
    echo "cannot run smoke checks: $p is group/other writable" >&2
    echo "the verifier rejects group/other-writable ancestors, so every positive" >&2
    echo "assertion would fail here; set RUNNER_TEMP to a private directory" >&2
    echo "(e.g. RUNNER_TEMP=\"${HOME:-/root}/.cache/vault-proxmox-smoke\") and re-run" >&2
    exit 1
  fi
  [ "$p" = / ] && break
  p=$(dirname "$p")
done

fixture=$(mktemp -d "$fixture_base/verify-plugin.XXXXXX")
trap 'rm -rf "$fixture"' EXIT

d="$fixture/plugins"
mkdir -p "$d"
printf '#!/usr/bin/env bash\nexit 0\n' > "$d/vault-plugin-secrets-proxmox"
chmod 0755 "$d/vault-plugin-secrets-proxmox"
sha=$(sha256sum "$d/vault-plugin-secrets-proxmox" | cut -d' ' -f1)
owner=$(id -un):$(id -gn)

expect_verifier() {
  local want_rc=$1 want=$2 label=$3
  shift 3
  local output rc
  if output=$("$@" 2>&1); then
    rc=0
  else
    rc=$?
  fi
  if [ "$rc" -ne "$want_rc" ]; then
    printf '%s\n' "$output"
    echo "$label: rc=$rc want=$want_rc"
    exit 1
  fi
  case "$output" in
    *"$want"*) ;;
    *)
      printf '%s\n' "$output"
      echo "$label: missing '$want'"
      exit 1
      ;;
  esac
}

expect_verifier 0 "OK: digest matches the approved artifact" \
  "direct positive" env EXPECTED_SHA="$sha" EXPECTED_OWNER="$owner" \
  PLUGIN_DIR="$d" "$verifier"
expect_verifier 1 "FAIL: digest does not match" "direct negative" \
  env EXPECTED_SHA=deadbeef EXPECTED_OWNER="$owner" PLUGIN_DIR="$d" \
  "$verifier"

# Feed bash through a pipe, matching the stdin stream delivered by ssh.
# shellcheck disable=SC2016
expect_verifier 1 "FAIL: digest does not match" "streamed negative" \
  sh -c 'EXPECTED_SHA=deadbeef \
    EXPECTED_OWNER="$2" PLUGIN_DIR="$1" bash -s' \
  _ "$d" "$owner" < <(cat "$verifier")
# shellcheck disable=SC2016
expect_verifier 0 "OK: digest matches the approved artifact" \
  "streamed positive" sh -c 'EXPECTED_SHA="$3" \
    EXPECTED_OWNER="$2" PLUGIN_DIR="$1" bash -s' \
  _ "$d" "$owner" "$sha" < <(cat "$verifier")
expect_verifier 1 "FAIL: PLUGIN_DIR must be an absolute path" \
  "relative plugin directory" env EXPECTED_SHA="$sha" EXPECTED_OWNER="$owner" \
  PLUGIN_DIR=relative "$verifier"

chmod g+w "$d/vault-plugin-secrets-proxmox"
expect_verifier 1 "FAIL: plugin file is group/other writable" \
  "group-writable artifact" env EXPECTED_SHA="$sha" EXPECTED_OWNER="$owner" \
  PLUGIN_DIR="$d" "$verifier"
chmod g-w "$d/vault-plugin-secrets-proxmox"

mv "$d/vault-plugin-secrets-proxmox" "$d/vault-plugin-secrets-proxmox.real"
ln -s vault-plugin-secrets-proxmox.real "$d/vault-plugin-secrets-proxmox"
expect_verifier 1 "is a symlink" "symlinked artifact" \
  env EXPECTED_SHA="$sha" EXPECTED_OWNER="$owner" PLUGIN_DIR="$d" "$verifier"
rm "$d/vault-plugin-secrets-proxmox"
mv "$d/vault-plugin-secrets-proxmox.real" "$d/vault-plugin-secrets-proxmox"

ln -s "$d" "$fixture/plugin-link"
expect_verifier 1 "is a symlink" "symlinked plugin directory" \
  env EXPECTED_SHA="$sha" EXPECTED_OWNER="$owner" PLUGIN_DIR="$fixture/plugin-link" \
  "$verifier"

chmod g+w "$fixture"
expect_verifier 1 "is group/other writable" "writable ancestor" \
  env EXPECTED_SHA="$sha" EXPECTED_OWNER="$owner" PLUGIN_DIR="$d" "$verifier"
chmod g-w "$fixture"

echo "plugin artifact smoke checks passed"
