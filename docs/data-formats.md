# Data formats

This document describes the artifacts that Phase 1 reads and writes. All of them
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
