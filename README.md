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

## Commands (Phase 1)

All of these are offline. None of them makes a network call.

```text
stremioctl backup inspect PATH [--json]
stremioctl backup validate PATH [--json]
stremioctl backup redact PATH --out PATH [--hide-hosts]
```

- `inspect` — summarize a collection export: descriptor count, transport
  security, per-add-on metadata, and any findings. Endpoints are shown only as
  redacted labels.
- `validate` — check the export against the v1 contract. Exit `0` when valid,
  `2` when not. Warnings do not fail validation.
- `redact` — write a shareable copy with every transport URL and every
  secret-looking value removed. Output is written atomically with mode `0600`.
  `--hide-hosts` also masks host names.

Exit codes follow `SPEC.md` section 9: `0` success, `2` invalid input. Errors are
printed to stderr in redacted form.

See [`docs/data-formats.md`](docs/data-formats.md) for the report and schema
details and [`docs/security.md`](docs/security.md) for the privacy model.

## Handling raw exports

Raw Stremio exports are sensitive: transport URLs may contain credentials in
their paths even when they have no query string. Do not commit, paste, log, or
place raw exports in tests. Private application state lives below the
permission-restricted data directory (overridable with `$STREMIOCTL_DATA_DIR`)
and is ignored by Git.

Planning, probing, and account operations are deliberately deferred to their
specified phases.
