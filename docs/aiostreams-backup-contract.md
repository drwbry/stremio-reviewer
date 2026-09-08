# AIOStreams native backup contract

This is the evidence record for the Phase 6 adapter. It describes structure and
behavior only; no value from the private reference export is recorded here.

## Verified baseline

- Producer: AIOStreams `2.34.0`, confirmed by the user on 2026-09-07.
- Upstream source: commit
  [`90eaf921c6a99a9d7ff3856112c142a54c1e408f`](https://github.com/Viren070/AIOStreams/tree/90eaf921c6a99a9d7ff3856112c142a54c1e408f).
- Private reference: an ignored, mode-`0600` native export made with **Exclude
  Credentials**. It remains outside Git and is never used as a committed test
  fixture.
- Observed root: JSON object with 116 top-level `UserData` fields. Structural
  anchors present are `formatter`, `sortCriteria.global`, and `presets`.
- The native export has no trustworthy producer-version envelope. Producer
  version must be recorded alongside the file.

## Upstream behavior

The Save & Install export serializes the current `UserData` object directly.
Import rejects template artifacts, removes `uuid` and `trusted`, applies the
current migration chain, and merges the result into the configuration form.
This is unrelated to the server dashboard's
`{settings, maskedSecretKeys, exportedAt, version}` format.

The **Exclude Credentials** path removes the known top-level identity/API
fields, service credentials, proxy connection details, and password-typed
preset options. It deliberately retains arbitrary scripts and free text. The UI
also warns that custom and overridden URLs may remain.

Primary sources:

- [Save & Install backup documentation](https://github.com/Viren070/AIOStreams/blob/90eaf921c6a99a9d7ff3856112c142a54c1e408f/packages/docs/content/docs/configuration/options.mdx#L260-L277)
- [native export/import implementation](https://github.com/Viren070/AIOStreams/blob/90eaf921c6a99a9d7ff3856112c142a54c1e408f/packages/frontend/src/components/menu/save-install.tsx#L1594-L1649)
- [`UserDataSchema`](https://github.com/Viren070/AIOStreams/blob/90eaf921c6a99a9d7ff3856112c142a54c1e408f/packages/core/src/db/schemas.ts#L565-L1016)
- [credential sanitizer](https://github.com/Viren070/AIOStreams/blob/90eaf921c6a99a9d7ff3856112c142a54c1e408f/packages/core/src/utils/template-sanitise.ts#L29-L43)

## Adapter v1

[`schemas/aiostreams-backup-v1.schema.json`](../schemas/aiostreams-backup-v1.schema.json)
is intentionally narrower than upstream's full schema and more permissive about
unknown fields:

- the root must be an object;
- `formatter`, `sortCriteria.global`, and `presets` are required as structural
  discriminators;
- template and dashboard-settings artifacts are rejected semantically;
- every unknown object member and array element is retained losslessly;
- parsing deep-copies the input and round-trips it without normalization;
- validation reports counts and field categories, never stored values;
- redaction masks all complete URLs, known/suspicious credential fields, proxy
  details, and script/expression/regex/template fields while retaining object
  keys, array ordering, and JSON scalar types.

The committed synthetic fixture was authored from this contract and current
upstream defaults. It is not a copy of the private export.
