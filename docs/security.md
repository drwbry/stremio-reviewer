# Security notes

The full requirements are in [`SPEC.md`](../SPEC.md) section 8. This is a summary
of what Phases 1–2 actually enforce.

## Sensitive data

- A raw collection export is sensitive. So is every complete `transportUrl`,
  including its path, because configured add-ons encode user data in the path.
- Raw exports are never committed, logged, pasted, or placed in test fixtures.
  Tests use synthetic fixtures whose secrets are obvious sentinels
  (`SENTINEL_...`), and assert those never reach any output.

## Redaction

- All rendering goes through `stremioctl.privacy`. URLs are replaced with keyed
  labels; values under secret-looking keys are dropped.
- Exception text printed to stderr is sanitized the same way before display.
- `assert_no_sentinels` is a fail-closed tripwire: every JSON report and every
  redacted file is checked for a leftover sentinel before it is emitted.
- The raw SHA-256 collection fingerprint is computed for later phases but is
  never printed; commands show the keyed display label instead.

## Files and permissions

- The private data directory is created with mode `0700` and the redaction key
  with mode `0600`; the tool refuses to continue if it cannot verify them.
- Outputs are written atomically: a same-directory temp file, `fsync`, then
  `rename`, followed by a directory `fsync`. Redacted exports, generated
  profiles (`profile init`), and change plans (`profile diff --out-plan`) are
  all mode `0600`.
- `backup redact` refuses to overwrite its own input; `profile init` and
  `profile diff` refuse an output path that resolves to one of their inputs.

## Desired profiles and change plans

- A desired profile holds no resolved secrets. `profile init` never copies a
  transport URL from the source export into the profile unless that specific
  manifest id was passed to `--declare-public`.
- Secret references (`env:NAME`, `file:/absolute/path`) are validated for syntax
  only. `profile validate` and `profile diff` never read the environment
  variable, open the file, or run the POSIX permission checks from `SPEC.md`
  section 7.2 — those belong to the phase that resolves the value.
- A change plan carries secret *references* verbatim and redacted endpoint
  *labels*, never a resolved URL or secret value. `baseCollectionFingerprint` is
  the raw SHA-256 of the collection: one-way, and not a transport URL.
- `assert_no_sentinels` guards the serialized plan and the generated profile
  before either is written, exactly as it guards Phase 1 output.

## Network

- `backup inspect`, `backup validate`, `backup redact`, `profile init`,
  `profile validate`, and `profile diff` make no network calls.
- The test suite installs an autouse guard that turns any unexpected socket
  connection into an immediate failure.

## Test isolation

- `$STREMIOCTL_DATA_DIR` overrides the private data directory location. The test
  suite points it at a temporary directory so a run never touches the real user
  profile. It is a testing aid, not a feature to rely on in production.
