# Backlog — deferred work and known gaps

This file tracks blockers, deliberate deferrals, and known-but-not-yet-fixed
gaps discovered while implementing the phased plan in [`SPEC.md`](SPEC.md). Each
item says which phase raised it and whether it is resolved. Clean these up in
later passes; do not let the list rot.

Status key: **open** (still needs doing) · **resolved** (done, kept for history) ·
**wontfix** (deliberately not doing, with a reason).

---

## Cross-cutting

- **resolved — no git remote.** Raised in Phase 1 (could not `git push`).
  Resolved 2026-09-06: `stremio/` was extracted from the local `computer tech`
  mono-repo into its own repository with history preserved
  (`git subtree split`), `origin` set to
  `github.com/drwbry/stremio-reviewer`, and the mono-repo stopped tracking it.

- **resolved — per-module coverage is enforced.** Resolved 2026-09-07. CI now
  enforces the SPEC §14 90% floor independently for privacy, planning,
  authenticated account access, and apply/rollback, in addition to pytest's 80%
  overall floor. The same commands are listed in `README.md`.

- **resolved — schemas work from installed wheels.** Resolved 2026-09-07.
  Hatch maps the canonical root `schemas/` tree into
  `stremioctl/schema_data/`; `schemas.py` loads it with `importlib.resources`
  and retains a source-checkout fallback. A built wheel was smoke-tested from
  outside the repository.

- **resolved — markdown table lint (MD060).** Resolved 2026-09-07. The unpadded
  cells in `docs/data-formats.md` and the compact exit-code table in `SPEC.md`
  were normalized.

- **resolved — malformed URLs cross validation boundaries cleanly.** Resolved
  2026-09-07. Profile public URLs, account base URLs, and resolved endpoint
  references now convert `urllib.parse` failures into value-free
  `ValidationError`s instead of surfacing an internal exception or secret URL.

- **resolved — malformed plan indices no longer break canonical sorting.**
  Resolved 2026-09-07. The deterministic plan sorter leaves type enforcement to
  schema/apply validation instead of raising a bare integer-conversion error.

- **resolved — existing redaction keys are revalidated.** Resolved 2026-09-07.
  Reuse now requires a regular file owned by the current user with no
  group/other permissions, matching the strict secret-file policy.

---

## Phase 2 — profiles and plans

- **open (narrowed) — `add` operations cannot be applied in v1.** `profile
  diff` can emit an `add`, but the desired profile and plan carry no manifest
  for a brand-new descriptor, so `account apply` refuses it with an actionable
  exit `2`. Resolved 2026-09-07: declared-public `replaceEndpoint` operations now
  carry `publicUrl` in the plan and work end to end; secret-reference replacement
  already worked. Do not close `add` by inventing a descriptor—design a bounded
  manifest fetch/validation step if adding becomes a Phase 6 requirement.

- **wontfix (v1) — SPEC §10 matching step 1 is not persisted.** The documented
  match order starts with "explicit local `key` mapping saved in private
  state". No private key-map store exists. `account apply` re-identifies each
  `preserve` entry against the fresh pull by `manifestId` + the keyed transport
  fingerprint carried in the plan's redacted `endpoint` label, which works
  because the drift guard has already proven the collection is byte-identical
  to the plan's base. A persisted key map would let identity survive an
  endpoint change between plan and apply. That cannot happen without tripping
  the mandatory base fingerprint drift guard, and Phase 6 promotion can use a
  unique manifest id plus a reviewed endpoint replacement. Revisit only if a
  real workflow needs identity to survive state drift; it is not a v1 blocker.

- **resolved — `backup redact --out` overwrite gap.** Resolved 2026-09-07.
  Redacted collections retain an unmarked array shape, so the command safely
  refuses every existing output target rather than guessing whether it owns the
  file. Input aliases and unrelated files are both protected.

---

## Phase 3 — probing and audit

- **open — DNS-rebinding race in the probe guard.** `probe collection` resolves
  the host and checks every address before connecting, and re-checks a redirect
  target, but it does not pin the connection to the validated IP. A resolver
  that returns a safe address to the pre-flight check and an unsafe one to
  `httpx` a moment later would not be caught. Accepted for now because probe
  targets come from the user's own collection file, not untrusted input. Close
  it with a pinned-IP transport (or `httpx` `transport=` resolver hook) if probe
  input ever becomes untrusted.

- **resolved — Phase 6 uses profile network parameters.** Resolved 2026-09-07.
  The standalone `probe collection` command intentionally keeps the SPEC §11
  defaults, while `aiostreams promote` feeds `manifestTimeoutSeconds`,
  `maxConcurrentProbes`, and `allowPrivateNetwork` from the desired profile into
  the mandatory standby probe.

- **wontfix — `healthy` / `warning` use a mocked TLS transport.**
  The loopback fake-server integration test exercises `insecure_transport`,
  `identity_mismatch`, `invalid_manifest`, `unreachable`, `blocked_destination`,
  and redirect-following over real sockets. `healthy` and `warning` need TLS,
  which the fake server does not serve, so they are covered via `respx` (an
  httpx transport-level integration test) instead. Add a self-signed TLS fake
  server if a fully real-socket pass over those two statuses is wanted — it
  would require a probe-side `verify=` toggle, which is itself a footgun. The
  production TLS behavior belongs to httpx; the current real-socket and mocked
  transport split exercises stremioctl's logic without weakening verification.

---

## Phase 4 — authenticated pull and read-only planning

- **open — any body-level API error maps to exit 4.** `fetch_addon_collection`
  treats any `{"error": {...}}` response to `addonCollectionGet` as an
  authentication failure, because on a read the auth key is the only
  client-controlled input. The server's `error.code` table is not publicly
  documented, so it is not branched on (the code is surfaced in the message).
  Build a real code → error-class mapping when the table is known, so a rate
  limit or a server fault is not reported as "bad key".

- **wontfix (v1) — `account` connection settings are not profile policy.**
  Account commands use a conservative 15 s API timeout and expose `--base-url`
  as a runtime option. The profile's network fields govern add-on manifest
  probes, not authenticated Stremio API transport, and putting the API location
  in committable desired state would conflate those concerns. Phase 6 promotion
  should expose the existing `--base-url` / `--auth-key-file` options; add a
  separate account-timeout option only if real use shows the fixed timeout is
  unsuitable.

- **resolved — strict secret-file reader.** `io.read_secret_file`
  implements the SPEC §7.2 / §8.3 permission rule (regular file, owned, no
  group/other access) and is used by `--auth-key-file`. Phase 5 reuses it for
  profile `file:` references.

- **wontfix — `login` / `loginWithToken` / `authWithApple` are not supported.**
  By SPEC §3 the user supplies an already-issued auth key. If a future version
  wants a `link`-code flow (device pairing, no password), it is a separate
  design; do not add email/password login. This is an explicit SPEC §3 non-goal,
  not unfinished v1 work.

---

## Phase 5 — apply, verification, and rollback

- **open — first live apply may reveal server-side normalization.**
  Verification uses the exact fingerprint SPEC §12 mandates: push target →
  re-pull → compare `collection_fingerprint`. The Rust upstream test shows the
  client normalizes transport URLs (`https://x` → `https://x/`), so the server
  may return descriptors that are semantically identical but not byte-identical
  to what was sent. When that happens `account apply` reports "semantically
  equivalent but not byte-identical" and still runs its single rollback, so a
  correct apply on a fresh account can read as a failed apply **and** a failed
  rollback even though the collection is fine throughout. The report already
  distinguishes this from a real mismatch (it compares the ordered
  `(manifest id, transportUrl)` structure). If a real run confirms the server
  normalizes, add a semantic-equivalence acceptance path: treat a structural
  match with a hash-only difference as success, with a loud warning, and skip
  the rollback. Needs a manually authorized run against a disposable account
  first (`STREMIOCTL_LIVE_TESTS=1` + `STREMIOCTL_DISPOSABLE_ACCOUNT=1`).

- **wontfix (v1 safety policy) — a newly written endpoint must be `https`.** `resolve_endpoint_ref`
  refuses a resolved `replaceEndpoint` target that uses plain `http`, even
  though the profile `policy.requireHttps` value is not threaded through to the
  apply path. This is deliberate for v1 (installing an insecure endpoint is an
  active choice) but it means a user who legitimately wants an `http` loopback
  endpoint via a secret reference cannot apply it. Wire `policy.requireHttps`
  (and the other `policy` network knobs, as already noted for the prober and
  `account`) into the apply path only if a real Phase 6 deployment requires an
  HTTP loopback endpoint. Secure-by-default promotion is not blocked.

- **wontfix (until sustained use) — snapshots are not automatically pruned.** Every apply
  and every rollback writes a snapshot under
  `$STREMIOCTL_DATA_DIR/snapshots/` and nothing deletes them. They are small,
  but automatic deletion would weaken rollback history. Add an explicit
  `account snapshots prune --keep N` before sustained/high-frequency use; Phase
  6's manual promotion workflow does not justify destructive retention yet.

- **resolved — empty-target applies are called out explicitly.**
  `construct_target` builds `[]` and `account apply` sends an empty `addons`
  array; nothing special-cases it. This is in-spec — it is the explicit intent
  behind an exact `--confirm` hash, and the protected-add-on guard already
  blocks it for accounts that have protected defaults. Resolved 2026-09-07: the
  apply report now warns that it will remove all N add-ons before the push.

- **resolved — same-second snapshots are unique.**
  The old snapshot filename was `<prefix>-<timestamp>-<fp12>.json` at
  one-second precision, so two applies against the same base state could name
  the same file. Resolved 2026-09-07 by appending a random suffix and adding a
  regression test.

- **resolved — `apply.py` defensive branches are covered and gated.** Line coverage
  is ~94% (above the SPEC §14 90% bar). The gaps are guardrails that a
  well-formed plan cannot reach: an out-of-range `remove` `fromIndex`, a
  non-integer `finalIndex`, a `replaceEndpoint` targeting a slot with no
  `preserve`, and the `_write_snapshot` `SecurityError` re-raise. Add direct
  unit tests now cover malformed remove indices and endpoint replacement
  without a preserved slot; CI independently enforces the module's ≥90% gate.

---

## Phase 6 — AIOStreams backup adapter and manual promotion

- **resolved — separately imported standbys have different manifest ids.**
  AIOStreams derives the configured add-on id from the configuration UUID, and
  its supported UI import discards the source UUID. Resolved 2026-09-07 by
  discovering the selected standby identity during its bounded probe, binding
  the plan to the target manifest id and SHA-256 fingerprint, and refetching it
  after the account drift guard so apply replaces the descriptor manifest and
  endpoint together without serializing the configured URL or response body.

- **resolved — native backup contract verified and implemented.** Resolved
  2026-09-07 from a private, ignored, mode-`0600` credential-excluded export
  produced by AIOStreams `2.34.0`, plus current upstream source commit
  `90eaf921c6a99a9d7ff3856112c142a54c1e408f`. The export is a direct `UserData`
  object, not a dashboard envelope. The evidence record is
  [`docs/aiostreams-backup-contract.md`](docs/aiostreams-backup-contract.md);
  only a separately authored synthetic fixture is committed.

- **resolved — offline backup validation and redaction.** The versioned,
  forward-compatible parser round-trips unknown fields losslessly.
  `aiostreams validate-backup` reports only value-free findings and
  `redact-backup` masks credentials, proxy details, every complete URL, and
  risky free text into a new mode-`0600` file without overwriting anything.

- **resolved — manual promotion planner.** Desired profiles can hold distinct
  primary/standby secret references. `aiostreams promote` validates the
  selection, pulls fresh account state, resolves HTTPS endpoints only in
  memory, probes the selected standby with profile policy, discovers its
  possibly different UUID-derived identity, and emits a secret-reference plan
  bound to the target manifest fingerprint. It never writes the account;
  `account apply` refetches that manifest after the drift guard and retains the
  existing confirmation, snapshot, verification, and rollback path.

- **resolved — real standby provisioned and exercised.** Resolved 2026-09-07.
  A credential-excluded AIOStreams 2.34.0 backup was imported through the
  supported UI, credentials were restored, distinct configured URLs were stored
  in ignored mode-`0600` files, and both manifests probed healthy. A fresh
  Stremio pull found the account already converged on the secondary after UI
  setup, so `stremioctl` correctly produced a zero-operation plan and made no
  write. Playback through the secondary's TorBox-backed AIOStreams result was
  verified. The separate first-`addonCollectionSet` normalization item above
  remains open because this exercise required no tool-driven write.
