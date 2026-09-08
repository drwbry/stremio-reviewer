# stremioctl

`stremioctl` is a local-first CLI for safely inspecting and managing Stremio
add-on collections. It is designed so that raw exports and
configured transport URLs stay private.

## Development

Create an environment and install the development dependencies:

```text
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

Run the checks:

```text
python -m pytest
coverage report --include='src/stremioctl/privacy.py' --fail-under=90
coverage report --include='src/stremioctl/diff.py,src/stremioctl/plans.py' --fail-under=90
coverage report --include='src/stremioctl/account.py' --fail-under=90
coverage report --include='src/stremioctl/apply.py' --fail-under=90
coverage report --include='src/stremioctl/aiostreams.py' --fail-under=90
ruff check .
mypy src
python -m build
python -m stremioctl --version
```

`python -m pytest` also enforces line coverage (80% overall) via the
configuration in `pyproject.toml`.

## Commands (Phases 1–6)

The `backup` and `profile` commands are entirely offline. `probe` and `account`
make network calls; `account` is the only command that authenticates.

```text
stremioctl backup inspect PATH [--json]
stremioctl backup validate PATH [--json]
stremioctl backup redact PATH --out PATH [--hide-hosts]
stremioctl profile init --from PATH --out PATH [--declare-public MANIFEST_ID ...]
stremioctl profile validate PATH
stremioctl profile diff --current PATH --desired PATH [--out-plan PATH]
stremioctl probe collection PATH [--json] [--allow-private-network]
stremioctl account pull --out PATH [--auth-key-file PATH] [--base-url URL]
stremioctl account plan --desired PATH --out PATH [--auth-key-file PATH] [--base-url URL]
stremioctl account apply PLAN_PATH --confirm PLAN_HASH [--auth-key-file PATH] [--base-url URL]
stremioctl account rollback SNAPSHOT_PATH --confirm SNAPSHOT_FINGERPRINT [--auth-key-file PATH] [--base-url URL]
stremioctl aiostreams validate-backup PATH
stremioctl aiostreams redact-backup PATH --out PATH
stremioctl aiostreams promote --profile PATH --standby KEY --out-plan PATH [--auth-key-file PATH] [--base-url URL]
```

- `backup inspect` — summarize a collection export: descriptor count, transport
  security, per-add-on metadata, and any findings. Endpoints are shown only as
  redacted labels.
- `backup validate` — check the export against the v1 contract. Exit `0` when
  valid, `2` when not. Warnings do not fail validation.
- `backup redact` — write a shareable copy with every transport URL and every
  secret-looking value removed. Output is written atomically with mode `0600`.
  `--hide-hosts` also masks host names.
- `profile init` — generate a starter desired profile from an export. Every
  add-on becomes a `present` entry managing `state` and `position`. A configured
  transport URL is copied into the profile **only** for a manifest id passed with
  `--declare-public` (repeatable); every other endpoint is left out entirely.
- `profile validate` — check a desired profile against the v1 contract and its
  semantic rules (unique keys, secret-reference syntax, `position`/`manage`
  coherence). Exit `0` when valid, `2` when not. Secret references are checked
  for syntax only; nothing is read or resolved.
- `profile diff` — compare a current export against a desired profile and emit a
  deterministic change plan. Exit `0` when the collection already matches, `10`
  when changes are planned, `2` on invalid input or an ambiguous selector.
  `--out-plan` writes the plan JSON atomically with mode `0600`.
- `probe collection` — fetch each descriptor's transport URL with a bounded,
  redirect-restricted `GET`, parse the manifest, and compare its identity. It
  never requests catalog/meta/stream/subtitles routes and refuses loopback,
  link-local, multicast, and private destinations unless
  `--allow-private-network` is given. Exit `0` when every endpoint is `healthy`
  or a plain `warning`, `3` when any endpoint is unreachable, blocked, insecure,
  invalid, or mismatched, `2` on invalid input. The audit report shows redacted
  endpoint labels only — never a complete URL, a response body, or a header.
- `account pull` — read the account's add-on collection over the authenticated
  Stremio API (`addonCollectionGet`) and write a **private** snapshot with mode
  `0600`. The snapshot is raw (it holds real transport URLs), so its parent
  directory must not be group- or world-accessible; point `--out` under
  `$STREMIOCTL_DATA_DIR` or another restricted directory.
- `account plan` — pull a fresh collection and diff it against a desired profile,
  producing a redacted change plan exactly like `profile diff` (exit `0`
  converged, `10` with planned changes).
- `account apply` — apply a change plan to the account. Requires `--confirm` set
  to the exact `planHash` printed with the plan; there is no `--yes` bypass. It
  pulls the current collection, refuses to write if it no longer matches the
  plan's base state (exit `5`), resolves any endpoint secret references, builds
  the complete target collection locally, writes a mandatory private pre-apply
  snapshot, pushes the whole collection once (`addonCollectionSet`), then pulls
  again and verifies the exact fingerprint. On a mismatch or an ambiguous write
  it makes exactly one rollback attempt and reports the result — `succeeded`,
  `failed`, or `unknown` — without concealing it (exit `6`). v1 apply cannot
  **add** an add-on (the plan carries no manifest), which is refused with exit
  `2`. A `replaceEndpoint` is applied from either a delayed secret reference or
  a URL explicitly declared public in the desired profile. Human output stays
  redacted; the plan carries a declared-public URL verbatim so it can apply it.
  Every newly written endpoint must be `https`. A Phase 6 replacement also
  binds the target manifest id and fingerprint; apply refetches it after the
  account drift guard and replaces the descriptor manifest and URL together.
- `account rollback` — restore the account to a previously written snapshot.
  Requires `--confirm` set to the snapshot's `collectionFingerprint`. There is no
  drift guard (this is a deliberate restore), but it still takes a mandatory
  private pre-rollback snapshot of the current state first, then pushes the
  snapshot's collection once and verifies. Exit `0` when the account matches the
  snapshot afterwards, `6` otherwise.
- `aiostreams validate-backup` — validate a native AIOStreams `UserData` export
  and report structural/privacy findings without printing stored values.
- `aiostreams redact-backup` — write a shape-preserving, mode-`0600` copy with
  credentials, complete URLs, and risky script/expression/template text masked.
- `aiostreams promote` — pull current Stremio state, resolve distinct primary
  and standby URL references locally, probe only the selected standby manifest,
  discover its possibly different UUID-derived identity, and write a
  secret-reference plan bound to that target manifest fingerprint. It does not
  mutate the account; review and apply the plan through `account apply`.

Pre-apply and pre-rollback snapshots are written under
`$STREMIOCTL_DATA_DIR/snapshots/` (mode `0600`, in a `0700` directory). They are
raw artifacts — keep that directory private. Filenames include a random suffix
to avoid same-second collisions.

The auth key is read only from `STREMIO_AUTH_KEY` or `--auth-key-file PATH` (a
regular file, owned by you, mode `0600`). There is no option that takes the key
as a value. It is never written to the snapshot, a URL, a header, a log line, or
an error message. See `docs/stremio-api-contract.md` for the verified wire
contract and how to obtain a key without giving the CLI a password.

Exit codes follow `SPEC.md` section 9: `0` success, `2` invalid input or
configuration, `3` a network/remote failure or a `probe` that found an unhealthy
endpoint, `4` a missing or rejected auth key, `5` the account changed since the
plan was built, `6` an apply or verification failed (the rollback status is
reported), `10` a `diff`/`plan` that found planned changes. Errors are printed to
stderr in redacted form.

See [`docs/data-formats.md`](docs/data-formats.md) for the report, profile, plan,
and schema details and [`docs/security.md`](docs/security.md) for the privacy
model. [`BACKLOG.md`](BACKLOG.md) tracks deferred work and known gaps.
See [`docs/phase-6-playbook.md`](docs/phase-6-playbook.md) for the exact Phase 6
unblocking, implementation, promotion, verification, and rollback procedure.

## Handling raw exports

Raw Stremio exports are sensitive: transport URLs may contain credentials in
their paths even when they have no query string. Do not commit, paste, log, or
place raw exports in tests. Private application state lives below the
permission-restricted data directory (overridable with `$STREMIOCTL_DATA_DIR`)
and is ignored by Git.

A **desired profile** (`profile init` / `profile validate` / `profile diff`) is
meant to be safe to commit: it holds no resolved secrets, only public URLs you
have explicitly declared public and unresolved secret references
(`env:NAME` / `file:/absolute/path`). `profile init` writes it with mode `0600`
as a precaution; loosen it yourself if you intend to check it in.

`probe collection` fetches manifests only, never content routes, and sends no
credentials. `account pull` / `account plan` are authenticated and read-only.
`account apply` / `account rollback` are the only commands that write to the
account: each requires an exact confirmation hash, takes a persisted private
snapshot before any write, sends the whole collection in one `addonCollectionSet`
call (never a sequence of per-add-on mutations), and reports a rollback result
plainly rather than claiming success it cannot verify.
