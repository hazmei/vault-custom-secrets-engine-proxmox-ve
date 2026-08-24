#!/usr/bin/env bash

set -u

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
verifier="$script_dir/verify-plugin-artifact.sh"
fixture=$(mktemp -d "${TMPDIR:-/tmp}/verify-plugin.XXXXXX")
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
