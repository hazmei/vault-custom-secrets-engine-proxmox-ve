# PR #25 Fix Handoff

## Severity: High

### Finding

**Locations:** `docs/PRODUCTION_VERIFICATION.md:179-181` and `docs/PRODUCTION_VERIFICATION.md:216-218`

The documented SSH wrapper is `bash -s; echo "exit=$?"`. Because `echo` is the final command, SSH exits with status 0 even when `verify-plugin-artifact.sh` fails.

### Evidence / Failure Scenario

An artifact SHA, ownership, or permissions verification failure can therefore be falsely treated as successful before plugin registration.

### Remediation

Preserve the verifier status with:

```bash
bash -s; status=$?; echo "exit=$status"; exit "$status"
```

Add a check/test, or clearly document verification, that SSH returns non-zero when the verifier fails.

### Status: Done

Updated both SSH wrapper examples in `docs/PRODUCTION_VERIFICATION.md` to
capture the verifier status, print it, and exit with it. Added guidance
explaining that a non-zero streamed verifier result is preserved through SSH.
