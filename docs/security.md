# Security notes

The full requirements are in [`SPEC.md`](../SPEC.md) section 8. This is a summary
of what Phases 1–4 actually enforce.

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

## Probing (`probe collection`)

- `probe collection` is the only command that touches the network. It is
  read-only: it issues one `GET` per descriptor to the transport URL and never
  requests `catalog`, `meta`, `stream`, or `subtitles` routes.
- Before any connection, the host is resolved and **every** returned address is
  checked. Loopback, link-local, multicast, unspecified, reserved, and private
  addresses are refused (`blocked_destination`, no request made) unless
  `--allow-private-network` is given. IPv4-mapped IPv6 addresses are unwrapped
  and re-checked. `--allow-private-network` deliberately unblocks loopback,
  link-local, and private ranges together; multicast, unspecified, and reserved
  stay blocked.
- Redirects: at most one, and only same-origin. A cross-origin `Location` or a
  second redirect is `unreachable`. The redirect target is re-resolved and
  re-checked before it is followed.
- The response body is streamed and abandoned past 2 MiB. Only `manifest.id` is
  read from the parsed body; the body itself is never stored or reported.
- Every `detail` string is run through `sanitize_text`, so an `httpx` exception
  that embeds the request URL cannot leak it. The audit report and its schema
  allow a redacted endpoint label (`scheme://host/<redacted>#<fp>`) but no
  complete URL, response body, or header value.
- Known limitation: a DNS-rebinding race between the pre-flight resolution and
  `httpx`'s own resolution is not closed (no IP pinning). Acceptable because the
  URLs come from the user's own collection file, not untrusted input. Tracked in
  `BACKLOG.md`.

## Account access (`account pull` / `account plan`)

- The auth key is read only inside `account` commands, only from
  `STREMIO_AUTH_KEY` or `--auth-key-file`. There is no option that takes the key
  as a command-line value (SPEC §8.2). A key file must be a regular file, owned
  by the current user, mode with no group/other bits — the same rule as a
  profile `file:` secret reference.
- The key travels **only** in the JSON request body (`authKey`), verified against
  upstream source. Never a URL, never a header, never logged.
- Every failure path in `stremioctl.account` raises a typed error whose message
  is built from literals plus at most an HTTP status or the sanitized server
  `error.message`, and is then run through `sanitize_text(..., secrets_to_hide=(key,))`
  a second time at the CLI boundary. A test forces every failure mode with the
  key set to a sentinel and asserts it never appears in stdout, stderr, the
  snapshot, or the raised exception.
- A custom `--base-url` must be `https`. Plain `http` is accepted only for a
  loopback host and only with `STREMIOCTL_INSECURE_LOOPBACK=1` (test use).
- The **snapshot** written by `account pull` is the one raw artifact: it holds
  the collection verbatim. It is written atomically at mode `0600` under a parent
  directory that is verified private (created `0700`, or refused if it already
  exists group/world-accessible — the directory is never re-`chmod`-ed). It is
  not redacted and not sentinel-checked. The **plan** written by `account plan`
  is a normal redacted change plan (mode `0600`, overwrite-guarded).
- `account` performs no writes to the account in v1.

## Network

- Every command except `probe collection` and `account` makes no network calls.
- The test suite installs an autouse guard that turns any unexpected socket
  connection or DNS lookup into an immediate failure. Probe and account tests use
  `respx`, injected resolvers, and a loopback fake server, so the real suite runs
  fully offline. Tests under `tests/live/` opt out of the guard and are skipped
  unless `STREMIOCTL_LIVE_TESTS=1` plus the required credential and a TTY.

## Test isolation

- `$STREMIOCTL_DATA_DIR` overrides the private data directory location. The test
  suite points it at a temporary directory so a run never touches the real user
  profile. It is a testing aid, not a feature to rely on in production.
