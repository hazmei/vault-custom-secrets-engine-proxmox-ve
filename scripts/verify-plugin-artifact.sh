#!/usr/bin/env bash

set -u

fail=0
expected_sha=${EXPECTED_SHA:-}
expected_owner=${EXPECTED_OWNER:-}
plugin_dir=${PLUGIN_DIR:-/etc/vault/plugins}
plugin_path="$plugin_dir/vault-plugin-secrets-proxmox"

if [ -z "$expected_sha" ]; then
  echo "FAIL: EXPECTED_SHA is required"
  fail=1
fi
if [ -z "$expected_owner" ]; then
  echo "FAIL: EXPECTED_OWNER is required"
  fail=1
fi

case "$plugin_dir" in
  /*) ;;
  *)
    echo "FAIL: PLUGIN_DIR must be an absolute path"
    fail=1
    ;;
esac

service_user=${expected_owner%%:*}
if [ -z "$service_user" ]; then
  echo "FAIL: EXPECTED_OWNER must include a service user"
  fail=1
fi

tools_ok=1
if command -v sha256sum >/dev/null 2>&1 &&
  sha256sum /dev/null >/dev/null 2>&1; then
  echo "OK: sha256sum is available"
else
  echo "FAIL: sha256sum is unavailable; use shasum -a 256"
  tools_ok=0
  fail=1
fi
if command -v stat >/dev/null 2>&1 &&
  stat -c '%U:%G' / >/dev/null 2>&1; then
  echo "OK: GNU stat -c is available"
else
  echo "FAIL: GNU stat -c is unavailable; use stat -f '%Su:%Sg %Lp'"
  tools_ok=0
  fail=1
fi
if command -v find >/dev/null 2>&1 &&
  find / -maxdepth 0 -perm /022 -print -quit >/dev/null 2>&1; then
  echo "OK: find -maxdepth 0 -perm /022 is available"
else
  echo "FAIL: find -perm /022 is unavailable; use the platform equivalent"
  tools_ok=0
  fail=1
fi
if command -v sudo >/dev/null 2>&1; then
  echo "OK: sudo is available"
else
  echo "FAIL: sudo is unavailable; cannot test service-user execution"
  tools_ok=0
  fail=1
fi

if [ "$tools_ok" -eq 0 ]; then
  echo "FAIL: compatible verification tools are required; assertions skipped"
else
  actual_sha=$(sha256sum "$plugin_path" 2>/dev/null)
  sha_status=$?
  actual_sha=${actual_sha%% *}
  if [ "$sha_status" -eq 0 ] && [ "$actual_sha" = "$expected_sha" ]; then
    echo "OK: digest matches the approved artifact"
  else
    echo "FAIL: digest does not match the approved artifact"
    fail=1
  fi

  if sudo -u "$service_user" test -x "$plugin_path"; then
    echo "OK: executable by Vault service user"
  else
    echo "FAIL: not executable by Vault service user"
    fail=1
  fi

  owner=$(stat -c '%U:%G %a' "$plugin_path" 2>/dev/null)
  owner_status=$?
  echo "$owner"
  if [ "$owner_status" -eq 0 ] && [ "${owner% *}" = "$expected_owner" ]; then
    echo "OK: owner/group is $expected_owner"
  else
    echo "FAIL: unexpected owner/group"
    fail=1
  fi

  if [ -n "$(find "$plugin_path" -maxdepth 0 -perm /022 -print -quit)" ]; then
    echo "FAIL: plugin file is group/other writable"
    fail=1
  else
    echo "OK: plugin file is not group/other writable"
  fi

  p=$plugin_dir
  while :; do
    if [ -n "$(find "$p" -maxdepth 0 -perm /022 -print -quit)" ]; then
      echo "FAIL: $p is group/other writable"
      fail=1
    else
      echo "OK: $p is not group/other writable"
    fi
    [ "$p" = / ] && break
    p=$(dirname "$p")
  done
fi

if [ "$fail" -eq 0 ]; then
  echo "VERIFICATION PASSED"
else
  echo "VERIFICATION FAILED"
fi
exit "$fail"
