# stremioctl Implementation Specification

Status: Draft ready for implementation  
Date: 2026-09-06  
Target implementer: GPT-5.6 Luna, one phase per run  
Runtime: Python 3.12+

## 1. Product summary

`stremioctl` is a local, deterministic CLI for safely inspecting, backing up,
redacting, validating, comparing, probing, and eventually applying changes to a
Stremio add-on collection. It will later support controlled AIOStreams
primary/standby promotion.

AI may build, test, and explain the tool. AI is not part of the runtime control
plane and must never receive or print live Stremio auth keys, debrid credentials,
AIOStreams passwords, configured manifest URLs, or unredacted backups.

The central operating model is:

```text
private current state + secret-free desired profile
                       |
                       v
              validate and compare
                       |
                       v
               redacted change plan
                       |
                       v
          explicit approval + drift check
                       |
                       v
              apply, verify, rollback
```

## 2. Goals

1. Make a valid, lossless local snapshot of a Stremio add-on collection.
2. Produce safe-to-share redacted reports and backups.
3. Detect malformed descriptors, duplicate identities, insecure transports,
   unreachable manifests, and manifest drift.
4. Express desired ordering, presence, and configured endpoints without storing
   secrets in the desired-state file.
5. Generate deterministic, human-reviewable plans before any account write.
6. Make writes idempotent, guarded by current-state fingerprints, and recoverable
   from a mandatory pre-apply snapshot.
7. Promote only a separately provisioned AIOStreams standby configuration; never
   simulate failover by blindly replacing a hostname.
8. Preserve unknown fields so a read/write round trip does not destroy data added
   by future Stremio versions.

## 3. Non-goals

- Discovering content sources, bypassing DRM, or selecting unauthorized media.
- Managing downloads, playback, torrents, or provider-side libraries.
- Logging into Stremio using an email and password.
- Sending secrets or raw backups to an LLM or remote analytics service.
- Editing provider API keys inside a Stremio manifest object.
- Assuming two public AIOStreams instances share users, UUIDs, passwords, or data.
- Automatic unattended account mutation or automatic failover in the initial
  release.
- Depending on undocumented API request shapes without first verifying them
  against current upstream source and a mocked contract test.

## 4. Facts and design constraints

### 4.1 Stremio collection model

The Stremio add-on client represents a saved collection as an ordered array of
add-on descriptors. Each descriptor contains a manifest, transport URL, and
flags. Current upstream reference:

- https://github.com/Stremio/stremio-addon-client/

The manifest describes capabilities. The transport URL identifies the installed
endpoint. Configured add-ons may encode user data in the URL path, so the entire
transport URL is sensitive even when it has no query string or HTTP user-info.

The Stremio API client documents authenticated collection pull/push operations
using `addonCollectionGet` and `addonCollectionSet`. The exact current wire format
must be confirmed in Phase 4 before implementing it:

- https://github.com/Stremio/stremio-api-client

### 4.2 AIOStreams model

Each public AIOStreams instance is independent and stores its own configurations,
credentials, limits, and database state. Native AIOStreams configuration export
and the Stremio add-on collection export are separate artifacts.

- https://github.com/Viren070/AIOStreams/blob/main/packages/docs/content/docs/getting-started/public-instances.mdx
- https://github.com/Viren070/AIOStreams/blob/main/packages/docs/content/docs/faq.mdx

A standby is valid only after the configuration has been created or imported on
the standby instance and its own configured manifest URL is available.

### 4.3 Observed local export shape

The local sample `stremio-addons-backup-2026-09-06.json` was inspected by shape
only. Do not print its values or copy it into tests.

Observed facts:

- Root is an array with 8 descriptors.
- Descriptor keys: `flags`, `manifest`, `transportName`, `transportUrl`.
- Manifest keys currently seen: `addonCatalogs`, `background`, `behaviorHints`,
  `catalogs`, `contactEmail`, `description`, `id`, `idPrefixes`, `logo`, `name`,
  `resources`, `types`, `version`.
- All 8 manifest IDs are currently unique. The implementation must still support
  or clearly reject future duplicates.
- Seven transport URLs use HTTPS and one does not. The audit must flag the
  non-HTTPS endpoint without revealing it in normal output.
- No current URL has query parameters or HTTP user-info. URL paths must still be
  treated as credential-bearing.

## 5. Technology choices

Use Python 3.12 and a `src/` package layout.

Production dependencies:

- `httpx` for bounded HTTP access and mockable transports.
- `jsonschema` for versioned JSON contracts.
- `platformdirs` for private application data paths.
- `typer` for the command tree.
- `rich` for readable terminal tables with centralized redaction.

Development dependencies:

- `pytest`
- `pytest-cov`
- `respx`
- `ruff`
- `mypy`

Pin compatible version ranges in `pyproject.toml`; do not pin transitive
dependencies manually. The CLI must run on Linux first. Keep OS-specific code
behind small interfaces so macOS and Windows support can be added later.

Do not introduce a database in the MVP. Use atomic JSON files and private
directories.

## 6. Repository layout

```text
.
├── SPEC.md
├── README.md
├── pyproject.toml
├── .gitignore
├── src/stremioctl/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── errors.py
│   ├── models.py
│   ├── schemas.py
│   ├── io.py
│   ├── privacy.py
│   ├── fingerprints.py
│   ├── validation.py
│   ├── profiles.py
│   ├── diff.py
│   ├── plans.py
│   ├── probing.py
│   ├── account.py
│   ├── apply.py
│   └── aiostreams.py
├── schemas/
│   ├── addon-collection-v1.schema.json
│   ├── desired-profile-v1.schema.json
│   ├── change-plan-v1.schema.json
│   └── audit-report-v1.schema.json
├── tests/
│   ├── fixtures/
│   │   ├── collection.synthetic.json
│   │   ├── collection.synthetic-invalid.json
│   │   └── desired.synthetic.json
│   ├── unit/
│   ├── integration/
│   └── live/
└── docs/
    ├── security.md
    ├── data-formats.md
    └── live-testing.md
```

Modules may be split further, but their responsibilities must not be collapsed
into one large CLI file.

## 7. Data contracts

### 7.1 Raw add-on collection

The in-memory representation must preserve:

- Array order.
- Every descriptor key, including unknown keys.
- Every manifest key, including unknown keys.
- JSON scalar types exactly.

Minimum structural validation:

```json
[
  {
    "manifest": {
      "id": "example.addon",
      "name": "Example",
      "version": "1.0.0",
      "resources": [],
      "types": []
    },
    "transportUrl": "https://example.invalid/manifest.json"
  }
]
```

`flags` and `transportName` are optional for compatibility. Validation should
produce warnings for unusual but preservable values and errors only when the
collection cannot be handled safely.

### 7.2 Desired profile v1

Desired profiles are safe to commit and contain no resolved secrets:

```json
{
  "schemaVersion": 1,
  "name": "default",
  "addons": [
    {
      "key": "metadata-primary",
      "match": {"manifestId": "example.metadata"},
      "state": "present",
      "position": 0,
      "endpoint": {
        "publicUrl": "https://example.invalid/manifest.json"
      },
      "manage": ["state", "position"]
    },
    {
      "key": "aiostreams-primary",
      "match": {"manifestId": "example.aiostreams"},
      "state": "present",
      "position": 1,
      "endpoint": {
        "secretRef": "env:STREMIOCTL_AIOSTREAMS_PRIMARY_URL"
      },
      "manage": ["state", "position", "endpoint"]
    }
  ],
  "policy": {
    "requireHttps": true,
    "manifestTimeoutSeconds": 8,
    "maxConcurrentProbes": 4,
    "allowPrivateNetwork": false,
    "preserveUnmanagedAddons": true
  }
}
```

Rules:

- `key` is a unique local stable name.
- `match.manifestId` may match more than one descriptor. If it does, planning
  fails until the profile adds a non-secret `transportFingerprint` selector.
- `endpoint.publicUrl` is allowed only when the user explicitly declares the URL
  public. Otherwise use `endpoint.secretRef`.
- Supported secret references in v1: `env:NAME` and `file:/absolute/path`.
- A secret file must be a regular file, owned by the current user, and not
  readable or writable by group/other on POSIX.
- `manage` prevents unspecified properties from becoming implicitly managed.
- `state` is `present` or `absent`. Absence is planned as removal, never as an
  invented `disabled` flag.
- Existing descriptor flags are preserved. Protected/official flags are not
  modified by v1.
- Unmanaged add-ons retain their relative order unless a managed position makes
  movement unavoidable; the planner must report any movement.

### 7.3 Change plan v1

A plan is safe to review and contains:

- `schemaVersion`
- UTC `createdAt`
- `baseCollectionFingerprint`
- desired profile fingerprint
- ordered operations
- warnings
- `planHash`

Supported v1 operations:

- `add`
- `remove`
- `move`
- `replaceEndpoint`
- `preserve`

Plans contain secret references and keyed fingerprints, never resolved secret
values. Canonicalize plan JSON before computing `planHash`. `planHash` must omit
its own field from the hash input.

### 7.4 Audit report v1

Reports contain identifiers, status, timings, warnings, and redacted endpoint
labels. They must never contain full transport URLs, response bodies, auth keys,
or HTTP headers.

## 8. Security and privacy requirements

These requirements are release blockers.

1. Treat every raw backup and every complete `transportUrl` as sensitive.
2. Never accept auth keys or configured endpoint URLs as ordinary command-line
   option values. Command-line values can leak through history and process lists.
3. Read `STREMIO_AUTH_KEY` only inside account commands, or accept an auth-key
   file meeting strict permission checks.
4. Never log environment-variable values.
5. Centralize rendering and exception sanitization in `privacy.py`.
6. Replace transport URLs in output with:

   ```text
   <scheme>://<host>/<redacted>#<keyed-fingerprint>
   ```

7. Generate a local random redaction key on first use. Store it in the private
   application directory with mode `0600`. Use HMAC-SHA-256 for stable local
   fingerprints. Do not use a plain unsalted hash of secrets.
8. Create private directories with mode `0700` and raw snapshots with mode
   `0600`. Refuse to continue if safe permissions cannot be established.
9. Write files atomically using a same-directory temporary file, `fsync`, and
   rename.
10. Default account base URL to `https://api.strem.io`. A custom base URL requires
    an explicit option and HTTPS; HTTP is accepted only for a loopback test server
    with a test-only switch.
11. Manifest probing rejects loopback, link-local, multicast, and private network
    destinations by default, including after DNS resolution and redirects.
12. Follow no cross-origin redirects by default.
13. Never place raw backups in test fixtures. Create synthetic fixtures containing
    sentinel secrets and assert those sentinels never appear in output, logs, plan
    files, reports, or exceptions.
14. Do not make network calls during `inspect`, `redact`, `validate`, `profile`,
    or offline `diff` commands.
15. Do not send telemetry.

Required `.gitignore` entries:

```gitignore
.env
.env.*
!.env.example
.stremioctl/private/
stremio-addons-backup-*.json
*.stremio-private.json
*.auth-key
*.json:Zone.Identifier
```

## 9. CLI contract

Target commands by the end of Phase 6:

```text
stremioctl --version
stremioctl backup inspect PATH [--json]
stremioctl backup validate PATH [--json]
stremioctl backup redact PATH --out PATH [--hide-hosts]
stremioctl profile init --from PATH --out PATH
stremioctl profile validate PATH
stremioctl profile diff --current PATH --desired PATH [--out-plan PATH]
stremioctl probe collection PATH [--json] [--allow-private-network]
stremioctl account pull --out PATH
stremioctl account plan --desired PATH --out PATH
stremioctl account apply PLAN_PATH --confirm PLAN_HASH
stremioctl account rollback SNAPSHOT_PATH --confirm SNAPSHOT_FINGERPRINT
stremioctl aiostreams validate-backup PATH
stremioctl aiostreams redact-backup PATH --out PATH
stremioctl aiostreams promote --profile PATH --standby KEY --out-plan PATH
```

Global behavior:

- Human-readable output goes to stdout.
- Errors go to stderr in redacted form.
- `--json` output must validate against its documented schema.
- Color is disabled automatically when stdout is not a TTY.
- No command prompts when stdin is not a TTY.
- Account mutations require the exact confirmation hash; there is no global
  `--yes` bypass in v1.

Exit codes:

| Code | Meaning |
|---:|---|
| 0 | Success; valid; no unrequested drift |
| 2 | Invalid input or configuration |
| 3 | Network or remote service failure |
| 4 | Missing, invalid, or rejected authentication |
| 5 | Current state changed since the plan was created |
| 6 | Apply or verification failed; rollback status is reported |
| 10 | `diff` completed and found planned changes |

Never use exit code `1` for an expected validation or diff condition. Reserve it
for uncaught defects until they are assigned a stable code.

## 10. Fingerprinting and identity

Use two distinct fingerprint types:

1. **Collection fingerprint:** SHA-256 of canonical raw collection JSON. It is
   stored only in private artifacts or as a one-way base-state guard. It must not
   be used as a substitute for redaction.
2. **Display fingerprint:** HMAC-SHA-256 using the local redaction key, truncated
   to 12 lowercase hexadecimal characters. It labels sensitive endpoints in
   reports and plans.

Canonical JSON means UTF-8, sorted object keys, no insignificant whitespace, and
array order preserved.

Descriptor matching order:

1. Explicit local `key` mapping saved in private state, if available.
2. `manifest.id` plus display transport fingerprint.
3. Unique `manifest.id`.
4. Otherwise fail as ambiguous. Never guess based on display name.

## 11. Network behavior

Manifest probe defaults:

- `GET` rather than `HEAD`.
- Connect timeout: 3 seconds.
- Overall timeout: 8 seconds, configurable within 1-30 seconds.
- Concurrency: 4, configurable within 1-10.
- Response limit: 2 MiB.
- Accept JSON only, but tolerate a missing/misleading content type with a warning
  if the body parses as JSON.
- At most one same-origin redirect.
- Two attempts total for transient connection errors and HTTP 429/502/503/504,
  with small jittered backoff.
- Do not retry authentication failures or other 4xx responses.
- Do not probe `catalog`, `meta`, `stream`, or `subtitles` resources by default.

Audit statuses:

- `healthy`
- `warning`
- `unreachable`
- `invalid_manifest`
- `identity_mismatch`
- `insecure_transport`
- `blocked_destination`

## 12. Account write safety

All account writes follow this state machine:

```text
pull current
    |
verify current fingerprint == plan base fingerprint
    |
resolve secret references locally
    |
construct target while preserving unknown fields
    |
write mandatory private pre-apply snapshot
    |
push complete ordered collection once
    |
pull and verify exact target fingerprint
    |                         |
 success                 mismatch/error
    |                         |
 report                  attempt rollback once
                              |
                    report rollback result clearly
```

An apply must not partially execute a list of per-addon mutations. Construct the
complete target collection locally and use one collection-set operation if the
upstream API supports it.

If the current fingerprint differs from the plan base, exit 5 without writing.
The user must create and review a new plan.

Rollback is never silently claimed. After rollback, pull again and compare the
exact fingerprint to the snapshot.

## 13. Phased implementation plan

Luna must implement exactly one phase per run and stop after its acceptance gate.
Do not begin the next phase merely because time remains.

### Phase 0 — Safe project skeleton

Deliverables:

- Create the package layout and `pyproject.toml`.
- Add `.gitignore` before reading any raw backup.
- Implement `stremioctl --version` and centralized typed errors.
- Implement private application directory creation and permission enforcement.
- Implement centralized secret-safe renderer and exception sanitizer.
- Create synthetic fixtures matching the observed shape, using obvious sentinel
  credentials such as `SENTINEL_MUST_NOT_LEAK`.
- Add Ruff, mypy, and pytest configuration.
- Write `README.md` with development commands and the warning that raw exports are
  sensitive.

Acceptance gate:

```text
python -m pytest
ruff check .
mypy src
python -m stremioctl --version
git status --short
```

All checks pass. `git status` must not list the real backup, `.env`, auth files,
or private state. No non-version command reads the real backup.

### Phase 1 — Offline inspect, validate, and redact

Deliverables:

- Lossless parser/serializer for descriptor arrays.
- Add-on collection v1 JSON Schema plus semantic checks.
- `backup inspect`, `backup validate`, and `backup redact`.
- Keyed endpoint display fingerprints.
- Atomic output and safe file modes.
- Human and JSON reports.
- Tests for malformed JSON, wrong root types, missing manifest fields, duplicate
  IDs, unknown-field preservation, HTTP warnings, URL redaction, nested secret
  names, and exception leakage.

Redacted exports retain enough metadata for debugging but replace complete
transport URLs and values under suspicious key names (`token`, `key`, `secret`,
`password`, `authorization`, and close case-insensitive variants).

Acceptance gate:

- Full test/lint/type suite passes.
- A parse/serialize round trip of every synthetic valid fixture is deeply equal.
- No sentinel value appears in captured stdout, stderr, logs, exceptions, JSON
  reports, or redacted exports.
- Running `backup inspect` on the real local export reports 8 descriptors and one
  insecure transport without printing any complete transport URL.
- No network calls occur.

### Phase 2 — Desired profiles and deterministic plans

Deliverables:

- Desired profile v1 and change plan v1 schemas.
- `profile init`, `profile validate`, and offline `profile diff`.
- Deterministic matching and ambiguity failures.
- Add/remove/move/replace-endpoint planning.
- Stable plan canonicalization and `planHash`.
- Secret-reference syntax validation without resolving secrets during ordinary
  profile validation.
- Preservation rules for unmanaged add-ons and unknown descriptor fields.

`profile init` must default all discovered configured endpoints to secret
references or unmanaged endpoints. It must never write a raw URL from the source
backup into the generated profile without an explicit `--declare-public` action
for an individual endpoint.

Acceptance gate:

- Re-running a diff with identical inputs produces byte-identical plan content
  except for `createdAt`; normalized plan hashes remain identical.
- An already-converged profile produces no operations and exit 0.
- A profile with changes produces exit 10 and a redacted plan.
- Duplicate manifest IDs cause an actionable ambiguity error unless disambiguated.
- Property-based or table-driven reorder tests cover managed and unmanaged items.
- No network calls occur and no secret references are resolved during diff.

### Phase 3 — Read-only manifest probing and audit

Deliverables:

- `probe collection` and audit report v1.
- Bounded concurrent manifest GETs.
- Destination and redirect safety checks.
- Manifest parse, structural validation, and identity comparison.
- Latency measurement and sanitized error classification.
- HTTPX/respx integration tests for timeouts, retryable errors, redirects, large
  bodies, invalid JSON, ID mismatch, and private-address blocking.

Acceptance gate:

- Full suite passes without public internet access.
- A local fake-server integration test exercises every status.
- Default probing never requests content resource routes.
- No report or error contains a complete configured URL or response body.
- A manually authorized run against the current collection can be performed only
  after tests pass; it is not required for the phase to pass.

### Phase 4 — Authenticated account pull and read-only planning

Deliverables:

- Research note recording the exact current Stremio API request and response
  shapes, linked to upstream source lines or commits.
- `account pull` using `STREMIO_AUTH_KEY` or a strict auth-key file.
- Private atomic snapshot creation.
- `account plan` combining a fresh pull with a desired profile.
- Fully mocked contract tests for success, auth rejection, malformed remote data,
  timeouts, and secret-safe errors.
- Documentation for obtaining an auth key manually without giving the CLI an
  account password.

Restrictions:

- No account write code in this phase.
- Never echo, persist, or include the auth key in a URL.
- If the current upstream wire contract cannot be verified, stop the phase with a
  documented blocker rather than guessing.

Acceptance gate:

- Full suite passes offline against mocks.
- Source inspection confirms auth is sent only in the method required upstream.
- `account pull` writes only beneath a private path with mode `0600`.
- A live read is optional, explicit, and must not be run by Luna unless the user
  separately authorizes it and supplies credentials outside chat.

### Phase 5 — Apply, verification, and rollback

Deliverables:

- Current-state drift guard.
- Local target construction with delayed secret resolution.
- Mandatory pre-apply snapshot.
- `account apply` with exact plan-hash confirmation.
- Post-write pull and exact verification.
- Single rollback attempt after a verified mismatch or ambiguous write result.
- Explicit `account rollback` with snapshot-fingerprint confirmation.
- Mocked failure-injection tests at every state transition.

Restrictions:

- No email/password login.
- No `--yes` bypass.
- No live test against the user's primary account during implementation.
- Live mutation tests require a separately designated disposable account and
  `STREMIOCTL_LIVE_TESTS=1`.

Acceptance gate:

- Reapplying a converged target makes no write.
- Stale plans exit 5 and make no write.
- Every write is preceded by a successfully persisted snapshot.
- Verification mismatch triggers exactly one rollback attempt.
- Tests distinguish successful rollback, failed rollback, and unknown remote
  state without concealing the result.
- Full test/lint/type suite passes.

### Phase 6 — AIOStreams backup adapter and manual promotion

Prerequisite:

Obtain a native AIOStreams JSON backup with credentials excluded. Do not infer its
schema from the Stremio add-on collection.

Deliverables:

- Versioned, lossless native AIOStreams backup parser based on an actual sanitized
  sample and current upstream documentation/source.
- `aiostreams validate-backup` and `redact-backup`.
- Profile representation for a separately provisioned primary and standby,
  referenced through distinct secret manifest-URL references.
- `aiostreams promote`, which creates a normal change plan replacing the installed
  configured endpoint with the already-provisioned standby endpoint.
- A promotion runbook covering native export, credential-safe import, standby
  validation, plan review, apply, verification, and rollback.

Restrictions:

- Never rewrite only the hostname of a configured URL.
- Never assume UUID/password portability.
- If AIOStreams lacks a stable documented import API, keep import as a manual UI
  step. Do not automate browser login or reverse-engineer credential submission.
- Promotion remains manual and plan-confirmed in v1.

Acceptance gate:

- Native backup round-trip preserves unknown fields.
- Credential-excluded fixtures contain no credential values.
- Promotion fails unless primary and standby have distinct, resolved endpoint
  references and the standby passes a manifest identity probe.
- Promotion produces an ordinary redacted plan and uses the Phase 5 safety path.
- Full suite passes.

### Phase 7 — Optional health history and recommendations

This phase is optional and must not delay a safe v1 release.

Potential deliverables:

- Append-only sanitized audit history.
- Availability and latency summaries.
- Duplicate-capability and manifest-drift reports.
- Markdown recommendations with evidence and confidence.
- Scheduler examples that run read-only probes only.

Restrictions:

- No unattended mutations.
- No raw URLs or response bodies in history.
- No runtime LLM dependency.
- Recommendations must identify the measured evidence and never invent content
  availability or quality claims.

## 14. Testing strategy

### Unit tests

Cover models, schemas, canonicalization, redaction, secret-reference parsing,
matching, ordering, planning, fingerprints, permission checks, and error mapping.

### Integration tests

Use HTTPX mock transports or respx. No test below `tests/live/` may access the
public network. Add a pytest autouse fixture that fails unexpected socket access.

### Live tests

Live tests are skipped unless all of the following are true:

- `STREMIOCTL_LIVE_TESTS=1`
- The specific required credential exists.
- The command is running interactively.
- For mutation tests, `STREMIOCTL_DISPOSABLE_ACCOUNT=1` is also set.

Never include live credentials or response bodies in pytest failure output.

### Required quality thresholds

- At least 90% line coverage for privacy, planning, account apply, and rollback
  modules.
- At least 80% overall line coverage.
- Zero Ruff errors.
- Zero mypy errors in `src/`.
- Zero leaked sentinel secrets in the full test output.

## 15. Definition of v1 done

V1 is complete after Phase 6 when:

- A user can inspect and redact the current export safely.
- A secret-free desired profile can create a deterministic plan.
- Add-on manifests can be audited without content-resource requests.
- Current account state can be pulled using a locally supplied auth key.
- A reviewed plan can be applied with drift protection, verified, and rolled back.
- A separately configured AIOStreams standby can be promoted without hostname
  substitution.
- All private artifacts are ignored by Git and permission-restricted.
- Tests prove sentinel credentials do not escape through normal outputs or error
  paths.
- README contains a start-to-finish backup, plan, apply, verify, and rollback
  example using synthetic values only.

## 16. Luna execution protocol

For each implementation run, give Luna this instruction:

```text
Read SPEC.md completely. Implement Phase N only. Do not begin later phases.
Preserve user files and do not inspect or print secret-bearing values from the
real backup. Run the phase acceptance commands, fix failures, and finish with:
1) files changed, 2) tests run and results, 3) acceptance criteria status,
4) security-relevant decisions, and 5) blockers or deliberate deferrals.
```

Additional rules for Luna:

- Read existing code before editing.
- Use `apply_patch` for manual file edits.
- Do not weaken or delete tests to make a phase pass.
- Do not add a dependency when the standard library or an existing dependency is
  sufficient and clear.
- Do not touch the real backup except for the explicitly allowed shape-safe
  acceptance command in Phase 1.
- Do not start live network or account operations without separate user authority.
- Treat this specification as the source of truth. If implementation reality
  conflicts with it, stop at the current phase and document the conflict.

## 17. Suggested phase prompts

Start with:

```text
Implement Phase 0 from SPEC.md. Stop after its acceptance gate.
```

Then, after reviewing the result and committing or otherwise checkpointing it:

```text
Implement Phase 1 from SPEC.md. Stop after its acceptance gate.
```

Continue one phase at a time. Phases 4-6 require extra scrutiny because they
introduce private state, authenticated access, and mutation behavior.

