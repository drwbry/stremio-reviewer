# stremioctl

`stremioctl` is a local-first CLI for safely inspecting and, in later phases,
managing Stremio add-on collections. It is designed so that raw exports and
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
ruff check .
mypy src
python -m stremioctl --version
```

`python -m pytest` also enforces line coverage (80% overall) via the
configuration in `pyproject.toml`.

## Commands (Phases 1–3)

The `backup` and `profile` commands are entirely offline. Only `probe` makes
network calls.

```text
stremioctl backup inspect PATH [--json]
stremioctl backup validate PATH [--json]
stremioctl backup redact PATH --out PATH [--hide-hosts]
stremioctl profile init --from PATH --out PATH [--declare-public MANIFEST_ID ...]
stremioctl profile validate PATH
stremioctl profile diff --current PATH --desired PATH [--out-plan PATH]
stremioctl probe collection PATH [--json] [--allow-private-network]
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

Exit codes follow `SPEC.md` section 9: `0` success, `2` invalid input or
configuration, `3` a `probe` that found an unhealthy endpoint, `10` a `diff`
that found planned changes. Errors are printed to stderr in redacted form.

See [`docs/data-formats.md`](docs/data-formats.md) for the report, profile, plan,
and schema details and [`docs/security.md`](docs/security.md) for the privacy
model. [`BACKLOG.md`](BACKLOG.md) tracks deferred work and known gaps.

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

`probe collection` is the only command that touches the network. It is
read-only: it fetches manifests, never content routes, and never sends
credentials. Account operations are deliberately deferred to their specified
phases.
