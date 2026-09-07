# Data formats

This document describes the artifacts that Phases 1–2 read and write. All of them
are plain UTF-8 JSON.

## Add-on collection (input)

The input to every `backup` command is a Stremio add-on collection export: a JSON
**array** of descriptor objects. The structural contract lives in
[`schemas/addon-collection-v1.schema.json`](../schemas/addon-collection-v1.schema.json).

Each descriptor:

| Key             | Required | Notes                                                        |
| --------------- | -------- | ------------------------------------------------------------ |
| `manifest`      | yes      | Object. Must contain a non-empty string `id`.               |
| `transportUrl`  | yes      | Non-empty string. Treated as credential-bearing in full.    |
| `transportName` | no       | String, kept as-is.                                         |
| `flags`         | no       | Object, kept as-is.                                         |

The parser is **lossless**. Array order, every descriptor key, every manifest
key, and every JSON scalar type are preserved, including keys the tool does not
recognize. A parse followed by a serialize is deeply equal to the input.

`stremioctl.validation` adds semantic checks on top of the schema. Anything that
still lets the collection be handled safely is a **warning**; only genuinely
unusable input is an **error**.

| Code                         | Severity | Meaning                                             |
| ---------------------------- | -------- | -------------------------------------------------- |
| `invalid_root`               | error    | Root is not a JSON array.                          |
| `invalid_descriptor`         | error    | A list entry is not an object.                     |
| `schema`                     | error    | Fails the `addon-collection-v1` schema.            |
| `missing_manifest`           | error    | Descriptor has no manifest object.                 |
| `missing_manifest_id`        | error    | Manifest has no non-empty string `id`.             |
| `missing_transport_url`      | error    | Descriptor has no `transportUrl` string.           |
| `malformed_transport_url`    | error    | `transportUrl` is not a usable `http(s)` URL.      |
| `duplicate_manifest_id`      | error    | The same manifest `id` appears more than once.     |
| `missing_manifest_field`     | warning  | `name`, `version`, `resources`, or `types` absent. |
| `manifest_field_type`        | warning  | One of those fields has an unexpected type.        |
| `insecure_transport`         | warning  | `transportUrl` uses `http` instead of `https`.     |
| `credential_in_url`          | warning  | `transportUrl` carries a query string.             |
| `userinfo_in_url`            | warning  | `transportUrl` carries HTTP user-info.             |
| `unexpected_descriptor_field`| warning  | A top-level key outside the known four.            |
| `flags_type`                 | warning  | `flags` is present but not an object.              |

## Redacted endpoint labels

Wherever an endpoint is shown, it appears as:

```text
<scheme>://<host>/<redacted>#<keyed-fingerprint>
```

The fingerprint is `HMAC-SHA-256(url)` under a local random key, truncated to 12
lowercase hex characters. It is stable on one machine, so the same endpoint keeps
the same label across runs, but it cannot be reversed and differs between
machines. `--hide-hosts` replaces `<host>` with the literal `<host>`.

The local key is generated on first use and stored at
`<data-dir>/redaction.key` with mode `0600`. `<data-dir>` is the platform user
data directory, or `$STREMIOCTL_DATA_DIR` when set (used by the test suite).

## Backup report (`--json` output)

`backup inspect --json` and `backup validate --json` both emit an object matching
[`schemas/backup-report-v1.schema.json`](../schemas/backup-report-v1.schema.json).
The tool validates its own output against that schema before printing it.

Common fields: `schemaVersion` (1), `report` (`"inspect"` or `"validate"`),
`descriptorCount`, `errorCount`, `warningCount`, and `findings` (each with
`severity`, `code`, `message`, and optionally `descriptorIndex`, `manifestId`,
`endpoint`).

`inspect` adds `collectionFingerprint` (the keyed display label for the whole
collection, **not** the raw SHA-256), `transports` (`https` / `insecure` /
`other` counts), and `descriptors` (per-entry `manifestId`, `name`, `version`,
`resourceCount`, `types`, `transport` label, and lists of unknown field names).

`validate` adds `valid` (true when `errorCount` is 0). The command exits `0` when
valid and `2` when not.

## Redacted collection (`backup redact --out`)

The output keeps the descriptor array structure and all non-sensitive metadata so
it is still useful for debugging, but:

- every complete `http(s)` URL becomes a redacted endpoint label, and
- any value under a key whose name looks like a secret (`token`, `secret`,
  `password`, `authorization`, `apiKey`, `*key`, `bearer`, `credential`, and
  similar case-insensitive variants) is replaced with `<redacted>`.

Object keys are sorted for a stable diff. The file is written atomically with
mode `0600`.

`backup redact` is the most permissive of the three commands: a slightly
malformed export (for example a stray non-object entry in the array) is still
redacted so it can be shared when asking for help. Only two things are refused:
a non-array root (exit `2`), and an `--out` path that resolves to the input file
(exit `2`, so the raw export cannot be clobbered).

## Desired profile v1 (`profile` input)

A desired profile is a secret-free statement of the add-on collection you want.
It is meant to be committable. The structural contract is
[`schemas/desired-profile-v1.schema.json`](../schemas/desired-profile-v1.schema.json);
`stremioctl.profiles` adds the semantic rules below.

Top level: `schemaVersion` (`1`), `name` (non-empty string), `addons` (array),
and an optional `policy` object.

Each `addons` entry:

| Key       | Required | Notes                                                            |
| --------- | -------- | -------------------------------------------------------------- |
| `key`     | yes      | Unique local stable name for this entry.                       |
| `match`   | yes      | `{ "manifestId": "...", "transportFingerprint"?: "<12 hex>" }` |
| `state`   | yes      | `present` or `absent`. `absent` plans a removal.               |
| `position`| no       | Target index in the collection *after* removals.               |
| `endpoint`| no       | Exactly one of `publicUrl` or `secretRef` (see below).         |
| `manage`  | no       | Subset of `state`, `position`, `endpoint`. Only listed         |
|           |          | properties are enforced; the rest are advisory.               |

`policy` (all optional, defaults shown): `requireHttps` (`true`),
`manifestTimeoutSeconds` (`8`, 1–30), `maxConcurrentProbes` (`4`, 1–10),
`allowPrivateNetwork` (`false`), `preserveUnmanagedAddons` (`true`). The
network-shaped policy values are recorded now and consumed by Phase 3.

Semantic rules enforced by `profile validate` and `profile diff`:

- `key` values must be unique.
- Two entries may not select the same target. The target is
  `(manifestId, transportFingerprint)`, so the same `manifestId` with two
  distinct fingerprints is allowed.
- `endpoint.publicUrl` must be an `http(s)` URL. Use it only for a URL you have
  decided is genuinely public.
- `endpoint.secretRef` must be `env:NAME` (a valid environment-variable name) or
  `file:/absolute/path`. **Only the syntax is checked.** The variable is not
  read, the file is not opened, and the POSIX permission checks from `SPEC.md`
  section 7.2 happen later, when a phase actually resolves the value.
- `position` set without `position` in `manage`, `endpoint` set without
  `endpoint` in `manage`, and extra keys on an `absent` entry are **warnings**,
  not errors.

`profile init` generates one entry per descriptor with
`manage: ["state", "position"]` and no `endpoint`. A transport URL from the
source export is written into `endpoint.publicUrl` **only** for a manifest id
passed to `--declare-public`. When a `manifestId` occurs more than once in the
source, every generated entry for it also gets a `match.transportFingerprint`.

### `transportFingerprint`

This is the keyed display fingerprint of a descriptor's transport URL: the
12-hex-character value after `#` in the endpoint label shown by
`backup inspect --json`. It is stable on one machine but machine-specific,
because it depends on the local redaction key. A profile that pins a
`transportFingerprint` is therefore tied to the machine that generated it. It is
still the right identifier to use, because a plain hash of a transport URL would
be a reversible fingerprint of a secret.

## Change plan v1 (`profile diff --out-plan`)

A change plan is a deterministic, reviewable description of how to make a current
collection match a profile. Contract:
[`schemas/change-plan-v1.schema.json`](../schemas/change-plan-v1.schema.json).
`profile diff` validates its own output against that schema before printing or
writing it, and re-checks that `planHash` matches the plan body.

Fields:

- `schemaVersion` — `1`.
- `createdAt` — UTC, `YYYY-MM-DDTHH:MM:SSZ`, second precision.
- `baseCollectionFingerprint` — the **raw SHA-256** of the canonical current
  collection JSON (64 hex). It is a one-way base-state guard for the later apply
  path, not a redaction substitute; it is never a transport URL.
- `desiredProfileFingerprint` — raw SHA-256 of the canonical desired profile
  JSON (64 hex).
- `operations` — ordered list (see below).
- `warnings` — deduplicated, sorted strings.
- `planHash` — SHA-256 of the canonical plan JSON with **both `planHash` and
  `createdAt` removed**. Two diffs of unchanged inputs therefore produce
  byte-identical plans apart from `createdAt`, and an identical `planHash`.
  `createdAt` is excluded because the hash identifies the *operations a human
  reviewed*, not the moment the file was written.

Operation types and their fields:

| `op`             | Meaning                                             | Fields                                                    |
| ---------------- | -------------------------------------------------- | ------------------------------------------------------- |
| `remove`         | Descriptor deleted from the collection.            | `manifestId`, `fromIndex`, `key?`, `reason`             |
| `add`            | New descriptor introduced by the profile.          | `key`, `manifestId`, `finalIndex`, `endpoint?`/`endpointRef?` |
| `move`           | Surviving descriptor changes index.                | `manifestId`, `fromIndex`, `finalIndex`, `key?`, `reason` (`managed` or `unmanaged-shift`) |
| `replaceEndpoint`| Managed endpoint differs, or cannot be confirmed.  | `key`, `manifestId`, `finalIndex`, `endpoint?`/`endpointRef?`, `reason?` (`offline-unverifiable`) |
| `preserve`       | Existing descriptor retained, at `finalIndex`.     | `manifestId`, `finalIndex`, `key?`, `endpoint?`          |

`fromIndex` is the descriptor's index in the input collection; `finalIndex` is
its index in the target. `endpoint` is a redacted endpoint label; `endpointRef`
is a secret reference copied verbatim (for example `env:STREMIOCTL_X_URL`). A
plan never contains a resolved URL or secret value.

Every surviving existing descriptor gets exactly one `preserve` entry, so
`preserve` plus `add` is a complete, contiguous `0..n-1` map of the target
collection that the apply path (Phase 5) can build from directly. `move` and
`replaceEndpoint` are delta annotations layered on top of the descriptor's
`preserve` entry, not replacements for it.

Operations are ordered `remove`, `add`, `move`, `replaceEndpoint`, `preserve`,
and within a group by `manifestId` then `key`. This order is for human review;
the apply path builds the whole target locally in one step.

A **converged** profile produces `operations: []` and exit `0`. Any planned
change produces exit `10`; `preserve` entries appear only once there is at least
one mutating operation for them to complete into a target manifest. Matching follows
`SPEC.md` section 10: an explicit saved key map (not populated until a later
phase), then `manifestId` + `transportFingerprint`, then a unique `manifestId`,
otherwise an ambiguity error (exit `2`) telling you to add a
`match.transportFingerprint`.

## Audit report v1 (`probe collection`)

`probe collection` fetches each descriptor's transport URL and emits an audit
report matching
[`schemas/audit-report-v1.schema.json`](../schemas/audit-report-v1.schema.json).
`--json` validates the report against that schema before printing it. The report
carries identifiers, statuses, timings, warnings, and redacted endpoint labels
only — never a complete transport URL, a response body, a header value, or an
auth key.

Top level: `schemaVersion` (`1`), `report` (`"audit"`), `generatedAt` (UTC,
second precision), `descriptorCount`, `statusCounts` (a map of status → count),
and `entries`.

Each entry:

| Field        | Notes                                                               |
| ------------ | ----------------------------------------------------------------- |
| `index`      | Position in the collection.                                       |
| `manifestId` | The descriptor's declared id (or `null`).                         |
| `endpoint`   | Redacted label `scheme://host/<redacted>#<fingerprint>`, or `null`. |
| `secure`     | `true` when the transport URL is `https`.                         |
| `status`     | One of the statuses below.                                        |
| `httpStatus` | The final HTTP status code, or `null` if no response was received. |
| `latencyMs`  | Time to the final response in whole milliseconds, backoff excluded, or `null`. |
| `attempts`   | Total request attempts across retries and any followed redirect.  |
| `redirects`  | Number of redirects followed (0 or 1).                            |
| `warnings`   | Short strings: `http instead of https`, non-JSON content type, missing recommended manifest fields. |
| `detail`     | One sanitized sentence explaining a non-healthy status, or `null`. |

Statuses (SPEC §11):

| Status              | Meaning                                                        |
| ------------------- | ----------------------------------------------------------- |
| `healthy`           | `https`, 2xx, valid manifest, id matches, no warnings.       |
| `warning`           | Reached and usable, but something is off (for example a non-JSON content type). |
| `insecure_transport`| Would be healthy, but the transport URL is `http`.           |
| `unreachable`       | DNS failure, connection error, timeout, non-2xx after retries, a cross-origin redirect, or more than one redirect. |
| `invalid_manifest`  | 2xx, but the body is not JSON, not an object, has no string `id`, or exceeds 2 MiB. |
| `identity_mismatch` | Valid manifest whose `id` differs from the descriptor.      |
| `blocked_destination` | The host (or a redirect target) resolves to a loopback, link-local, multicast, unspecified, reserved, or private address and `--allow-private-network` was not given. No request is made. |

`insecure_transport` is also always present in `warnings` and reflected in
`secure`, so nothing is lost by it being the headline status.

Network behaviour is fixed for `probe collection`: `GET`, 3-second connect
timeout, 8-second overall timeout, concurrency 4, a 2 MiB response cap, at most
one same-origin redirect, and two attempts total for transient connection errors
and HTTP 429/502/503/504 with a small jittered backoff. The 1–30 second and 1–10
concurrency ranges from SPEC §11 apply to the profile `policy` values that will
drive later phases, not to this command.

Exit code: `0` when every entry is `healthy` or `warning`; `3` when any entry has
another status; `2` when the collection cannot be parsed or fails the structural
contract.

## Account snapshot v1 (`account pull --out`)

`account pull` performs an authenticated `addonCollectionGet` (see
[`stremio-api-contract.md`](stremio-api-contract.md)) and writes an
**account-snapshot** matching
[`schemas/account-snapshot-v1.schema.json`](../schemas/account-snapshot-v1.schema.json).

Unlike every other artifact, a snapshot is **raw**: `collection` is the API's
`result.addons` array verbatim, including transport URLs that may carry
credentials in their path. It is therefore only ever written under a private
directory (parent not group/world-accessible) with mode `0600`, and it is never
redacted or checked for sentinels. `account pull` refuses to write it to a
shared location such as `$HOME`.

Fields:

- `schemaVersion` — `1`.
- `artifact` — `"account-snapshot"`.
- `pulledAt` — UTC, `YYYY-MM-DDTHH:MM:SSZ`.
- `baseUrl` — the API base URL the pull used (the API host, not a transport URL).
- `lastModified` — the API's `result.lastModified`, or `null`.
- `collectionFingerprint` — raw SHA-256 of the canonical `collection` array. It
  is computed with the same function as a change plan's
  `baseCollectionFingerprint`, so a plan built from the same pull carries an
  identical value. Phase 5 uses this for drift detection and rollback
  confirmation.
- `collection` — the ordered descriptor array, verbatim.

`account plan --out` writes a normal **change plan v1** (see above), not a
snapshot: it is redacted, mode `0600`, and guarded against overwriting an
unrelated file. `account plan` does not write a snapshot — the plan's
`baseCollectionFingerprint`, taken from the fresh pull, is the drift guard.
