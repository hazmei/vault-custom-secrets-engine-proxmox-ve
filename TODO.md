# Deferred Verification and Feature Backlog

This backlog intentionally records work deferred from the current **token-only**
implementation. It does not change the current credential contract or claim that
any item below has been verified. Run operational checks only against an approved,
disposable or explicitly authorized PVE target, and record results without
credentials or token secrets.

## Deferred production verification

These are optional follow-ups to the required positive authorization and lifecycle
checks described in [`docs/PRODUCTION_VERIFICATION.md`](docs/PRODUCTION_VERIFICATION.md).

- [ ] **Insufficient-privilege canary**
  - Configure a deliberately limited PVE identity and confirm configuration
    validation fails clearly when required privileges are absent.
  - Reference: `TestAccInsufficientPrivileges`; see the acceptance prerequisites
    and privilege-validation behavior in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
    and [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md).
- [ ] **Direct ACL anti-escalation canary**
  - With a configured unheld role, confirm a direct `PUT /access/acl` attempt by
    the provisioner identity is rejected with HTTP 403.
  - Use only the documented optional canary inputs; do not record credentials.
  - Reference: the authorization contract canary in
    [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
- [ ] **Negative-authorization canary**
  - Configure a deliberately forbidden endpoint and confirm the issued token is
    rejected with the expected authorization failure.
  - Reference: the optional negative authorization check in
    [`docs/PRODUCTION_VERIFICATION.md`](docs/PRODUCTION_VERIFICATION.md) and
    [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md).
- [ ] **PVE `append=0` replacement-semantics probe**
  - On a throwaway user that already has the verification group, send an explicit
    replacement update with `groups=` and `append=0`; read back membership and
    document whether the group is removed.
  - A parameter-verification 400 must be recorded as a rejected request, not as
    evidence that membership was preserved.
  - Reference: the pending control in [`docs/PVE_PROBES.md`](docs/PVE_PROBES.md),
    plus the renewal contract in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
- [ ] **Optional quorum-loss operational test**
  - In an approved maintenance window, exercise a controlled PVE quorum-loss
    condition during a cluster write and verify the documented error propagation
    and recovery behavior.
  - Reference: the cluster failure-mode guidance in
    [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and the operator procedure in
    [`docs/PRODUCTION_VERIFICATION.md`](docs/PRODUCTION_VERIFICATION.md).
- [ ] **Optional ACL lock-contention operational test**
  - Exercise controlled concurrent cluster writes and verify transient lock
    failures, retry behavior, cleanup, and audit visibility.
  - Reference: the cluster considerations and failure-injection coverage in
    [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Deferred password credential support

Password credentials are deliberately **not implemented**. The engine currently
issues only PVE API tokens; do not add password fields or alter the token lifecycle
as part of this backlog entry. Treat this as phased work requiring design review,
tests, and documentation updates at each stage.

- [ ] **Phase 1 — PVE password behavior probe**
  - Verify PVE user creation, authentication, password rotation/update, expiry,
    disablement, and deletion semantics for passwords, including interaction with
    token credentials and the user-level `expire` backstop.
  - Record evidence in [`docs/PVE_PROBES.md`](docs/PVE_PROBES.md).
- [ ] **Phase 2 — Role-level opt-in credential mode**
  - Add an explicit role credential mode with `token` as the default; preserve
    existing token-only behavior for all current roles and leases.
  - Update the schema, validation, architecture, implementation plan, and tests.
- [ ] **Phase 3 — Password issuance**
  - Implement password generation and issuance only for roles that explicitly opt
    in, with one-time secret handling, safe response/storage boundaries, and
    collision/error compensation consistent with the token path.
- [ ] **Phase 4 — Password lifecycle handling**
  - Define and test renewal, revocation, WAL rollback, expiry, disablement, and
    out-of-band password changes. Ensure token and password modes cannot silently
    diverge in cleanup or authorization behavior.
- [ ] **Phase 5 — Documentation and security review**
  - Review threat model, privilege requirements, audit expectations, secret
    handling, migration/compatibility behavior, and operator procedures.
  - Update [`README.md`](README.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
    [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md),
    [`docs/PRODUCTION_VERIFICATION.md`](docs/PRODUCTION_VERIFICATION.md), and
    [`docs/PVE_PROBES.md`](docs/PVE_PROBES.md) when the work is complete.
