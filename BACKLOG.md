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

- **open — per-module coverage is not enforced.** SPEC §14 requires ≥90% line
  coverage for the privacy, planning, account-apply, and rollback modules, but
  `pyproject.toml` only enforces `--cov-fail-under=80` overall. The per-module
  numbers are checked by reading the `term-missing` report each phase. Add
  explicit per-path thresholds (for example a `coverage` plugin or a CI step)
  once the account/apply modules exist.

- **open — `schemas/` resolves relative to the repo root.** `schemas.py`
  computes `_SCHEMA_DIR` from `__file__`'s grandparent, which works from a
  source checkout but not from an installed wheel. Package the schema files (or
  load them via `importlib.resources`) before shipping a wheel. Noted in code.

- **open — markdown table lint (MD060).** `docs/data-formats.md` has
  unpadded table pipes that trip the editor's markdown linter. Cosmetic; GitHub
  renders them fine. Pad them next time that file is edited substantially.

---

## Phase 2 — profiles and plans

- **open — `add` operations cannot be applied in v1.** `profile diff` can emit
  an `add` operation from a desired profile, but the plan carries no manifest
  for the new add-on, so `account apply` refuses a plan containing one (exit 2,
  actionable message). A `replaceEndpoint` whose endpoint is a declared-public
  URL is refused for the same reason — the plan stores only a redacted label.
  Closing this is a small Phase 2 change: emit the `publicUrl` verbatim on
  `add` / `replaceEndpoint` and add the schema field, so at least the
  public-endpoint path becomes end-to-end functional. Adding a new add-on still
  needs a manifest source (probe/fetch) as well.

- **open — SPEC §10 matching step 1 is still unimplemented.** The documented
  match order starts with "explicit local `key` mapping saved in private
  state". No private key-map store exists. `account apply` re-identifies each
  `preserve` entry against the fresh pull by `manifestId` + the keyed transport
  fingerprint carried in the plan's redacted `endpoint` label, which works
  because the drift guard has already proven the collection is byte-identical
  to the plan's base. A persisted key map would let identity survive an
  endpoint change between plan and apply; add it if that case comes up.

- **open — `backup redact --out` overwrite gap.** `profile init` and
  `profile diff` refuse to overwrite an input path or an unrelated existing
  file (only an existing artifact of the right kind may be replaced).
  `backup redact --out` still only refuses the exact input path; it will
  happily clobber any other existing file. Phase 1 code, left untouched in
  Phase 2. Apply the same `_guard_output_path` check there.

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

- **open — `probe collection` uses fixed network parameters.** The command
  always runs with the SPEC §11 defaults (8 s timeout, concurrency 4, 2
  attempts). `ProbeConfig` already validates the 1–30 s and 1–10 ranges, but
  nothing feeds non-default values in yet. Wire the profile `policy`
  (`manifestTimeoutSeconds`, `maxConcurrentProbes`, `allowPrivateNetwork`) into
  the prober when a later phase runs a probe as part of planning or applying.

- **open — `healthy` / `warning` are only covered over a mocked transport.**
  The loopback fake-server integration test exercises `insecure_transport`,
  `identity_mismatch`, `invalid_manifest`, `unreachable`, `blocked_destination`,
  and redirect-following over real sockets. `healthy` and `warning` need TLS,
  which the fake server does not serve, so they are covered via `respx` (an
  httpx transport-level integration test) instead. Add a self-signed TLS fake
  server if a fully real-socket pass over those two statuses is wanted — it
  would require a probe-side `verify=` toggle, which is itself a footgun.

---

## Phase 4 — authenticated pull and read-only planning

- **open — any body-level API error maps to exit 4.** `fetch_addon_collection`
  treats any `{"error": {...}}` response to `addonCollectionGet` as an
  authentication failure, because on a read the auth key is the only
  client-controlled input. The server's `error.code` table is not publicly
  documented, so it is not branched on (the code is surfaced in the message).
  Build a real code → error-class mapping when the table is known, so a rate
  limit or a server fault is not reported as "bad key".

- **open — `account` timeout / base URL not driven by profile policy.**
  `account pull` / `account plan` always use the built-in 15 s timeout. When a
  later phase runs account access as part of a workflow, feed the profile
  `policy` through, mirroring the same gap noted for the prober.

- **resolved (partial) — strict secret-file reader.** `io.read_secret_file`
  implements the SPEC §7.2 / §8.3 permission rule (regular file, owned, no
  group/other access) and is used by `--auth-key-file`. Phase 5 should reuse it
  to resolve profile `file:` references instead of reimplementing the check.

- **open — `login` / `loginWithToken` / `authWithApple` are not supported.**
  By SPEC §3 the user supplies an already-issued auth key. If a future version
  wants a `link`-code flow (device pairing, no password), it is a separate
  design; do not add email/password login.

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

- **open — a newly written endpoint must be `https`.** `resolve_endpoint_ref`
  refuses a resolved `replaceEndpoint` target that uses plain `http`, even
  though the profile `policy.requireHttps` value is not threaded through to the
  apply path. This is deliberate for v1 (installing an insecure endpoint is an
  active choice) but it means a user who legitimately wants an `http` loopback
  endpoint via a secret reference cannot apply it. Wire `policy.requireHttps`
  (and the other `policy` network knobs, as already noted for the prober and
  `account`) into the apply path if that case is real.

- **open — pre-apply / pre-rollback snapshots are never pruned.** Every apply
  and every rollback writes a snapshot under
  `$STREMIOCTL_DATA_DIR/snapshots/` and nothing deletes them. They are small,
  but add a retention policy (keep N most recent, or an explicit
  `account snapshots prune`) before this sees heavy use.

- **open — a plan that removes every descriptor pushes an empty collection.**
  `construct_target` builds `[]` and `account apply` sends an empty `addons`
  array; nothing special-cases it. This is in-spec — it is the explicit intent
  behind an exact `--confirm` hash, and the protected-add-on guard already
  blocks it for accounts that have protected defaults — but add a confirmation
  line ("this will remove all N add-ons") to the apply report if it ever feels
  too quiet.

- **open — a same-second re-apply can overwrite its own snapshot.** The
  snapshot filename is `<prefix>-<timestamp>-<fp12>.json` at one-second
  precision. Two applies in the same second against the same base state produce
  the same name; `atomic_write_text` would overwrite the first. The content is
  identical in that case, so it is harmless today, but add sub-second precision
  or a short random suffix if snapshots ever need to be individually durable.

- **open — `apply.py` has a few uncovered defensive branches.** Line coverage
  is ~94% (above the SPEC §14 90% bar). The gaps are guardrails that a
  well-formed plan cannot reach: an out-of-range `remove` `fromIndex`, a
  non-integer `finalIndex`, a `replaceEndpoint` targeting a slot with no
  `preserve`, and the `_write_snapshot` `SecurityError` re-raise. Add direct
  unit tests for these if the per-module coverage gate (also open, cross-cutting)
  is ever enforced strictly.

---

## Phase 6 — AIOStreams backup adapter and manual promotion (BLOCKED — not started)

- **blocked — Phase 6 needs a real sanitized AIOStreams config backup.**
  SPEC §13 Phase 6 opens with a hard prerequisite: *"Obtain a native AIOStreams
  JSON backup with credentials excluded. Do not infer its schema from the
  Stremio add-on collection."* and requires the parser be *"based on an actual
  sanitized sample and current upstream documentation/source."* No such sample
  is in the repo, and the SPEC §16 execution protocol says to stop with a
  documented blocker rather than guess a wire/format contract. Phase 5 finished
  and was committed; Phase 6 has not been started.

  To unblock, provide (outside of any assistant chat if it helps you feel safe
  about it, though the sample must be **credential-free**):

  1. A native AIOStreams **addon config** export — the JSON you get from the
     AIOStreams configuration UI's backup/export button (not the AIOStreams
     *server* `/dashboard/settings` export, which is a different thing). Strip
     every debrid key, password, API token, and the config UUID/hash before
     sharing. Keep the structure, key names, nesting, version marker, and any
     `exportedAt` / `version` fields intact.
  2. The AIOStreams version that produced it.
  3. Whether your AIOStreams instance exposes a **documented, stable** import
     API. Observed upstream (`Viren070/AIOStreams`, `main` @ 2026-09-06):
     `packages/frontend/.../settings/_components/import-settings-modal.tsx` +
     `settings/queries.ts` show an import flow shaped as
     `{ settings: {...}, maskedSecretKeys: [...], exportedAt, version }` posted
     to `PATCH /dashboard/settings` — but that is the **server** settings
     surface, not the per-user addon config. Per the Phase 6 restriction,
     import stays a manual UI step unless a stable addon-config import API is
     confirmed; automating browser login or reverse-engineering credential
     submission is out of scope.

  Until then: `aiostreams` remains a docstring-only stub, `stremioctl
  aiostreams *` commands are not implemented, and v1 "done" (SPEC §15) is not
  reachable.
