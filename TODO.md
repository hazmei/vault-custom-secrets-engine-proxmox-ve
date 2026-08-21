# Backlog

This backlog records work deferred from the current **token-only** implementation.
It does not change the current credential contract or claim that any item below
has been verified. Run operational checks only against an approved, disposable,
or explicitly authorized PVE target, and record results without credentials,
token secrets, Authorization headers, or sensitive command output.

## Release Blockers / Production Adoption Gates

These gates are required before production adoption. They are not optional
follow-ups. Follow the operator procedure in
[`docs/PRODUCTION_VERIFICATION.md`](docs/PRODUCTION_VERIFICATION.md).

- [ ] **Production Vault catalog and multi-node verification**
  - Build one approved plugin artifact, distribute it to every Vault node, and
    verify the executable, ownership/mode, and SHA-256 digest are identical on
    every node. Do not register a mixed artifact set.
  - Register the catalog entry with the verified digest using
    `vault plugin register -sha256=<hash> secret vault-plugin-secrets-proxmox`.
    Verify the catalog digest, mount state, and persistence across restart.
  - Verify requests through the normal cluster address are forwarded from
    standby to active before any PVE mutation. Exercise controlled failover,
    then issue, renew, and revoke credentials after failover.
  - Verify restart recovery and consistency of leases, WAL recovery, PVE user
    and token cleanup, catalog state, mount state, and audit evidence across
    nodes. Confirm the complete lifecycle and cleanup remain consistent.
  - Record pass/fail results without credentials, token secrets,
    Authorization headers, or sensitive command output.
  - A local `vault server -dev` run with `-dev-plugin-dir` auto-registers the
    plugin and is **not** production proof. It does not prove catalog
    registration, identical distribution, persistence, HA forwarding,
    failover, restart recovery, or cleanup.

## Password Credential Support — Gated Future Feature

Password credentials are deliberately **not implemented**. The engine currently
issues only PVE API tokens. This work is separate from token-only production
adoption: do not make production adoption depend on password support, and do not
add password fields or alter the token lifecycle as part of the release gates.
Complete each phase in order; later phases depend on the preceding phase's
findings, design decisions, tests, and documentation.

- [ ] **Phase 1 — PVE password behavior probe**
  - First verify PVE user creation, authentication, password rotation/update,
    expiry, disablement, and deletion semantics for passwords, including
    interaction with token credentials and the user-level `expire` backstop.
  - Record evidence in [`docs/PVE_PROBES.md`](docs/PVE_PROBES.md). The probe
    results are a dependency for the credential-mode design.
- [ ] **Phase 2 — Role-level opt-in credential mode**
  - After the probe, add an explicit role credential mode with `token` as the
    default. Preserve existing token-only behavior for all current roles and
    leases.
  - Update the schema, validation, architecture, implementation plan, and
    tests before implementing password issuance.
- [ ] **Phase 3 — Password issuance**
  - After mode design and tests are approved, implement password generation and
    issuance only for roles that explicitly opt in. Use one-time secret
    handling, safe response/storage boundaries, and collision/error
    compensation consistent with the token path.
- [ ] **Phase 4 — Password lifecycle handling**
  - After issuance exists, define and test renewal, revocation, WAL rollback,
    expiry, disablement, and out-of-band password changes. Ensure token and
    password modes cannot silently diverge in cleanup or authorization behavior.
- [ ] **Phase 5 — Documentation and security review**
  - After lifecycle behavior is tested, review the threat model, privilege
    requirements, audit expectations, secret handling, migration/
    compatibility behavior, and operator procedures.
  - Update [`README.md`](README.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
    [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md),
    [`docs/PRODUCTION_VERIFICATION.md`](docs/PRODUCTION_VERIFICATION.md), and
    [`docs/PVE_PROBES.md`](docs/PVE_PROBES.md) when the work is complete.

## Optional Security and Authorization Validation

These checks are non-blocking unless the release policy explicitly requires
them. Run them only with the documented optional canary inputs and never record
credentials.

- [ ] **Insufficient-privilege canary**
  - Configure a deliberately limited PVE identity and confirm configuration
    validation fails clearly when required privileges are absent.
  - Reference: `TestAccInsufficientPrivileges`; see the acceptance prerequisites
    and privilege-validation behavior in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
    and [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md).
- [ ] **Direct ACL anti-escalation canary**
  - With a configured unheld role, confirm a direct `PUT /access/acl` attempt by
    the provisioner identity is rejected with HTTP 403.
  - Reference: the authorization contract canary in
    [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
- [ ] **Negative-authorization canary**
  - Configure a deliberately forbidden endpoint and confirm the issued token is
    rejected with the expected authorization failure.
  - Reference: the optional negative authorization check in
    [`docs/PRODUCTION_VERIFICATION.md`](docs/PRODUCTION_VERIFICATION.md) and
    [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md).

## Optional PVE Semantics Validation

This probe is non-blocking and is not an implementation prerequisite. It must
not remove the explicit `append=1` renewal or its read-back assertion without
design review.

- [ ] **PVE `append=0` replacement-semantics probe**
  - On a throwaway user that already has the verification group, send an
    explicit replacement update with `groups=` and `append=0`; read back
    membership and document whether the group is removed.
  - A parameter-verification 400 must be recorded as a rejected request, not as
    evidence that membership was preserved.
  - Reference: the pending control in [`docs/PVE_PROBES.md`](docs/PVE_PROBES.md),
    plus the renewal contract in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Optional Failure-Injection / Operational Validation

These tests are destructive, operator-run exercises in an approved maintenance
window. They are non-blocking by default and require a tested rollback and
cleanup plan.

- [ ] **Quorum-loss, then ACL lock-contention tests**
  - First exercise a controlled PVE quorum-loss condition during a cluster write
    and verify documented error propagation and recovery behavior.
  - After quorum-loss testing is complete and the target is healthy, exercise
    controlled concurrent cluster writes to verify transient ACL lock failures,
    retry behavior, cleanup, and audit visibility.
  - References: the cluster failure-mode guidance and failure-injection
    coverage in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and the operator
    procedure in [`docs/PRODUCTION_VERIFICATION.md`](docs/PRODUCTION_VERIFICATION.md).
