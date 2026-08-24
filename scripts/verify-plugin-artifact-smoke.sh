#!/usr/bin/env bash

set -u

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
verifier="$script_dir/verify-plugin-artifact.sh"
fixture_base=${RUNNER_TEMP:-$script_dir/../.smoke-tmp}
mkdir -p "$fixture_base" || exit 1
fixture_base=$(cd -- "$fixture_base" && pwd -P) || exit 1

# The verifier walks every ancestor of PLUGIN_DIR up to / and fails on any
# group/other-writable directory, so the fixture's own location decides whether
# the positive assertions can pass at all. Check that ancestry up front: without
# this, a checkout under a shared path (/srv/src, a shared dev box, some
# container images) fails with "direct positive: rc=1 want=0" and nothing points
# at the fixture directory as the cause.
p=$fixture_base
while :; do
  if [ -n "$(find "$p" -maxdepth 0 -perm /022 -print -quit 2>/dev/null)" ]; then
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
