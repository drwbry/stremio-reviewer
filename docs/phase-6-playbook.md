# Phase 6 playbook — AIOStreams backup adapter and manual promotion

Status: **implementation complete; manual standby provisioning and promotion
remain**. The adapter was built from a private credential-excluded AIOStreams
2.34.0 export plus the verified upstream source. The private sample remains
ignored and is not a test fixture.

## Verified upstream baseline

This playbook was checked on 2026-09-07 against AIOStreams `2.34.0`, source
commit [`90eaf921`](https://github.com/Viren070/AIOStreams/tree/90eaf921c6a99a9d7ff3856112c142a54c1e408f).

- The official UI documents native backup export/import under **Save & Install
  → Backups** and an **Exclude Credentials** export option
  ([documentation](https://github.com/Viren070/AIOStreams/blob/90eaf921c6a99a9d7ff3856112c142a54c1e408f/packages/docs/content/docs/configuration/options.mdx#L260-L277)).
- The add-on configuration export is the current `UserData` object serialized
  directly as JSON; it is not the dashboard settings envelope. The UI imports
  that JSON, rejects template files, drops `uuid` and `trusted`, runs migrations,
  and merges it into the form
  ([source](https://github.com/Viren070/AIOStreams/blob/90eaf921c6a99a9d7ff3856112c142a54c1e408f/packages/frontend/src/components/menu/save-install.tsx#L1594-L1649)).
- **Exclude Credentials is necessary but not sufficient for sharing.** Upstream
  removes known identity/API-key fields, service credentials, proxy details,
  and password-typed preset options. It intentionally retains free text and
  variant scripts
  ([sanitizer source](https://github.com/Viren070/AIOStreams/blob/90eaf921c6a99a9d7ff3856112c142a54c1e408f/packages/core/src/utils/template-sanitise.ts#L29-L43),
  [behavior](https://github.com/Viren070/AIOStreams/blob/90eaf921c6a99a9d7ff3856112c142a54c1e408f/packages/core/src/utils/template-sanitise.ts#L125-L166)).
  The UI also warns that custom add-on URLs, overridden URLs, and variant
  scripts may still be sensitive.

These facts supersede the older backlog note about a dashboard
`{settings, maskedSecretKeys, exportedAt, version}` object. That is a separate
server-administration artifact and must not be used for Phase 6.

## 1. Unblock the implementation safely

Perform this part locally. Do not paste the backup, credentials, UUID, password,
or configured manifest URL into chat, an issue, or a commit.

1. Open the primary AIOStreams configuration UI.
2. Go to **Save & Install → Backups → Export Configuration**.
3. Turn on **Exclude Credentials**, then export the native JSON backup.
4. Record the exact AIOStreams version shown by the instance. The current code
   baseline above is `2.34.0`; the sample's producing version is authoritative.
5. Keep the downloaded original private. Prefer a directory outside the
   repository. If it must be staged inside this checkout, first give it a name
   matching `aiostreams-config-*.json` or `*.aiostreams-private.json`, then
   confirm the repository ignores that in-repository path:

   ```text
   git check-ignore -v -- aiostreams-config-YYYY-MM-DD.json
   ```

6. In a local editor, inspect every remaining string value—not just key names.
   Replace sensitive values while preserving object keys, nesting, arrays, and
   JSON scalar types. Pay special attention to:

   - custom add-on URLs and manually overridden URLs;
   - UUIDs, passwords, access keys, API tokens, service credentials, proxy URLs,
     parent-configuration credentials, and encrypted passwords;
   - query strings, URL path segments, synced-expression/regex URLs, webhook or
     private-host URLs;
   - variant scripts, formatter text, templates, and any other free-text field.

   Use structural placeholders such as `https://example.invalid/manifest.json`
   for URL strings and `REDACTED_EXAMPLE_VALUE` for other strings. Do not delete
   the surrounding field merely to sanitize it; Phase 6 needs the real shape.

7. Re-open the sanitized copy and confirm it contains no live value. Only then
   place that copy at an ignored in-repository path such as
   `aiostreams-config-sanitized.json` and tell the Phase 6 implementer the path,
   not its contents. Include:

   - the producing AIOStreams version;
   - whether it is stable or nightly;
   - whether the primary and standby are public, managed, or self-hosted
     instances (hostnames themselves are not needed).

Stop if there is any doubt that a value is credential-free. A structurally
smaller but demonstrably safe sample is preferable to exposing a secret.

## 2. Implemented Phase 6 contract and acceptance sequence

The implementation follows these gates. Re-run them after any adapter change
and stop at the first failure.

### A. Freeze the native backup contract

1. Add `docs/aiostreams-backup-contract.md` recording the sample version,
   observed root type and top-level keys, upstream commit, export behavior,
   import behavior, and known sensitive locations—without recording values.
2. Add a minimal versioned JSON schema based on the actual sample and upstream
   `UserDataSchema`. Validate only invariants needed for safe handling; allow
   unknown fields so future AIOStreams versions remain lossless.
3. Add a lossless model that deep-copies the parsed document and round-trips
   unknown keys, ordering of arrays, JSON numbers, booleans, and nulls.
4. Derive a synthetic credential-free fixture from the shape. Never commit the
   supplied sample itself.

Gate: parse → serialize → parse is deeply equal for the sanitized sample and all
synthetic fixtures; malformed roots and unsupported shapes exit `2` without
including an input value in the error.

### B. Implement native backup commands

Implemented commands:

```text
stremioctl aiostreams validate-backup PATH
stremioctl aiostreams redact-backup PATH --out PATH
```

Requirements:

- Both commands are offline and size-bounded.
- Validation reports shape/version compatibility and suspicious credential
  locations without printing their values.
- Redaction combines upstream's known sensitive-field behavior with
  `stremioctl.privacy`'s generic secret-key and URL handling. It must also handle
  custom/overridden URLs and variant/free-text fields that upstream intentionally
  retains.
- Redaction preserves document shape and unknown fields, writes atomically at
  mode `0600`, and refuses every existing output target.
- Add sentinel tests for top-level keys, nested services, preset password
  options, proxy settings, custom URLs, query/path credentials, scripts, and
  exception messages.

Gate: no sentinel appears in stdout, stderr, exceptions, reports, or redacted
files; Ruff, mypy, all tests, and coverage gates pass.

### C. Add the promotion profile contract

The desired profile has a Phase 6 block that maps the primary's installed
AIOStreams manifest identity to named endpoint references:

```json
{
  "aiostreamsPromotion": {
    "manifestId": "the-primary-id-observed-from-the-real-manifest",
    "primary": {"secretRef": "file:/absolute/private/primary.url"},
    "standbys": {
      "secondary": {"secretRef": "file:/absolute/private/secondary.url"}
    }
  }
}
```

These invariants are enforced:

- endpoint values are `env:` or absolute `file:` references only;
- primary and every standby have stable local keys;
- no resolved URL is serialized into the profile or plan;
- selected primary and standby must resolve to distinct complete URLs;
- the primary manifest id comes from a fetched real manifest, never from an
  assumed AIOStreams default;
- a separately imported standby may have a different UUID-derived manifest id;
  promotion discovers that identity from the selected standby rather than
  requiring it to equal the primary id.

Gate: profile validation catches duplicate keys, missing references, an unknown
standby key, identical resolved primary/standby URLs, and any resolved HTTP URL.

### D. Implement `aiostreams promote`

Implemented command:

```text
stremioctl aiostreams promote --profile PATH --standby KEY --out-plan PATH \
  [--auth-key-file PATH] [--base-url URL]
```

The safest interpretation of the existing contract is for this command to use
the normal account auth sources and runtime API-base option, pull fresh Stremio
state, and produce a normal `change-plan-v1` artifact. It does not write the
account.

Required flow:

1. Validate the profile and output path before reading secrets or making a
   request.
2. Pull the current collection using the Phase 4 account client.
3. Resolve primary and selected standby references locally with the Phase 5
   strict file/env reader. Confirm they differ.
4. Probe only the standby manifest URL. Feed
   `manifestTimeoutSeconds`, `maxConcurrentProbes`, and `allowPrivateNetwork`
   from profile policy into `ProbeConfig`.
5. Discover the standby's manifest id, then identify exactly one installed
   descriptor matching either the configured primary identity or the selected
   standby identity and its corresponding endpoint.
6. Require a usable HTTPS response. Do not probe catalog, meta, stream,
   subtitles, or playback routes.
7. Build an endpoint-replacement plan whose persisted form contains the standby
   `secretRef`, its manifest id, and a SHA-256 manifest fingerprint, never the
   resolved URL or response body. Use the fresh account fingerprint as the
   drift guard.
8. At apply time, refetch the target manifest after the account drift guard,
   require the planned id and fingerprint, and replace the descriptor's
   manifest and endpoint together before the single collection write.
9. Render the normal redacted plan and exit `10` when promotion is planned, `0`
   if the selected standby is already installed.

Gate: mocked tests cover distinct/equal references, unknown standby, no/multiple
installed matches, different primary/standby identities, blocked/private
destination, redirect, timeout, invalid JSON, apply-time manifest drift, current
already standby, sentinel leakage, and a valid plan. The plan must pass unchanged
through `account apply`.

### E. Final Phase 6 acceptance

Run:

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
git status --short
```

Also install the wheel outside the checkout and run both new backup commands on
synthetic fixtures. Do not run a live account mutation as part of implementation.

## 3. Provision the standby manually

The official UI import is the supported path. Do not automate browser login or
reverse-engineer a private write API.

1. Open the standby instance's configuration UI.
2. Import the native backup through **Save & Install → Backups → Import**.
3. Re-enter every credential manually on the standby. An excluded-credential
   backup intentionally cannot make a working clone by itself.
4. Review custom add-on URLs and instance-specific settings. Do not assume a
   primary UUID, password, encrypted path, or hostname is portable.
5. Save as a separately provisioned standby user/configuration.
6. Obtain its own configured manifest URL from the standby UI. Store primary
   and standby URLs in different strict-permission files:

   ```text
   chmod 600 /absolute/private/primary.url /absolute/private/secondary.url
   ```

7. Confirm each file is a regular file owned by the current user and that the
   two URLs are distinct. Do not print either file in logs or shell history.

## 4. Promote after Phase 6 is implemented

1. Run the full local acceptance suite above.
2. Validate and redact the native backup locally. Review only the redacted copy.
3. Generate the promotion plan:

   ```text
   stremioctl aiostreams promote --profile desired.json --standby secondary --out-plan promote.json
   ```

4. Review every mutating operation, warning, manifest id, redacted endpoint
   label, base fingerprint prefix, and the full `planHash`. There should be one
   AIOStreams endpoint replacement plus preserve operations; unexpected add,
   remove, or move operations are a stop condition.
5. Apply using the exact reviewed hash:

   ```text
   stremioctl account apply promote.json --confirm PLAN_HASH
   ```

6. Require exit `0` and exact post-write fingerprint verification. Record the
   printed pre-apply snapshot path. If verification reports normalization,
   mismatch, failed rollback, or unknown state, stop and inspect Stremio before
   another write.
7. Run a read-only account pull/plan and a manifest-only probe to confirm the
   selected standby is installed and healthy. Perform a small manual playback
   smoke test in Stremio; the CLI intentionally does not request content routes.

## 5. Roll back a promotion

Use the pre-apply snapshot created by the failed or unwanted promotion. Review
the snapshot filename and fingerprint from the apply output, then run:

```text
stremioctl account rollback SNAPSHOT_PATH --confirm SNAPSHOT_FINGERPRINT
```

Require exit `0` and a reported `succeeded` verification. Rollback itself writes
a pre-rollback snapshot, so that deliberate restore is recoverable. If status is
`failed` or `unknown`, make no further automated write; inspect the account in an
official Stremio client.

## Stop conditions

Stop Phase 6 or a promotion immediately if any of these is true:

- the sample may contain a live credential, UUID/password, configured manifest
  URL, private host, or token-bearing custom URL;
- the backup shape differs materially from both the recorded sample and current
  upstream source;
- the standby was made by rewriting only the primary hostname;
- primary and standby references resolve to the same URL;
- the standby manifest cannot be probed safely or its id differs;
- the generated plan contains an add/remove/reorder that was not explicitly
  intended;
- the account changed after planning;
- apply or rollback verification is not exact and successful.
