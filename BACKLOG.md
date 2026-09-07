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

- **open — `add` operations have no manifest source offline.** `profile diff`
  can emit an `add` operation from a desired profile, but offline planning has
  no manifest for the new add-on. A real apply needs the manifest; wiring that
  in depends on Phase 3 (probe/fetch) and Phase 5 (apply). Until then an `add`
  op only records intent (key, manifestId, position, endpoint reference).

- **open — SPEC §10 matching step 1 is unimplemented.** The documented match
  order starts with "explicit local `key` mapping saved in private state". No
  private key-map store exists yet, so matching begins at step 2 (`manifestId`
  + keyed transport fingerprint). Add the private store when a phase first
  needs to persist a resolved identity (likely Phase 4 `account pull`).

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
