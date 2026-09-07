# Stremio API contract — `addonCollectionGet`

Research note for Phase 4. This records the exact current request and response
shapes for an authenticated add-on collection pull, verified against upstream
source. Phase 4 implements **only the read** (`addonCollectionGet`);
`addonCollectionSet` is recorded here for context but not implemented until
Phase 5.

## Sources inspected

| What | Repo / path | Ref | Date |
| ---- | ----------- | --- | ---- |
| Modern request enum, path, method, serialization | `Stremio/stremio-core` `src/types/api/request.rs` | blob `719b63ebd897c7146a4bf686ff1cdee464606760`, branch `development` @ `ab28e8423689ef8cca166cc097b8d6c2bc89f3df` | 2026-09-04 |
| URL assembly (`/api/` prefix, no query, body = serialized request) | `Stremio/stremio-core` `src/types/api/fetch_api.rs` | same tree | |
| `API_URL` constant | `Stremio/stremio-core` `src/constants.rs:85-86` | same tree | |
| Response envelope + `CollectionResponse` | `Stremio/stremio-core` `src/types/api/response.rs` | same tree | |
| Descriptor shape | `Stremio/stremio-core` `src/types/addon/descriptor.rs` | same tree | |
| Local profile storage key + auth-key path | `Stremio/stremio-core` `src/constants.rs:11`, `src/types/profile/profile.rs`, `src/types/profile/auth.rs` | same tree | |
| Documented JS client (SPEC §4.1 reference) | `Stremio/stremio-api-client` `apiClient.js` | blob `d38ad3cfa4c21988a2af0a7e1738dfa2872635ca`, unchanged since commit `4311d45` (2019-02-20) | |
| JS `pullAddonCollection` params | `Stremio/stremio-api-client` `apiStore.js` | branch `master` @ `c303559b9e314b691484cc6cfc07c141cef17767` | 2025-04-14 |

`stremio-core` is the Rust core that every current official Stremio app builds
on, so it is treated as authoritative where it and the older JS client differ.

## Base URL and routing

- Default API base URL: **`https://api.strem.io`** (`API_URL`, `stremio-core`
  `constants.rs`). Always HTTPS.
- Final URL: `endpoint.join("api/").join("<method>")`
  (`fetch_api.rs`) → **`https://api.strem.io/api/addonCollectionGet`**.
- Method: **POST**. No query string.
- Header: `content-type: application/json`. No `Authorization` header is used;
  the JS client sets only `content-type` (`apiClient.js`).

## Request body — `addonCollectionGet`

`stremio-core` `APIRequest::AddonCollectionGet` is
`#[serde(tag = "type")] #[serde(rename_all = "camelCase")]` over
`{ auth_key: AuthKey, update: bool }`, so the serialized body is:

```json
{ "type": "AddonCollectionGet", "authKey": "<AUTH_KEY>", "update": true }
```

The older JS client sends `{ "authKey": "<AUTH_KEY>", "update": true, "addFromURL": [] }`
without `type` (it relies on the path to route) and with a legacy
`addFromURL` migration array.

**`stremioctl` sends the `stremio-core` form** — `type`, `authKey`, `update: true` —
because that is what current servers expect from current clients. `addFromURL`
is omitted (legacy-only, and an empty array is a no-op).

**The auth key travels only in this JSON body.** Never in the URL, never in a
header, never logged. This is consistent across both sources.

## Response — `addonCollectionGet`

Envelope (`stremio-core` `APIResult<T>`), `#[serde(rename_all = "camelCase")]`:

```json
{ "result": { ... } }
```
or
```json
{ "error": { "message": "<string>", "code": <integer> } }
```

Exactly one of `result` / `error`. The JS client additionally treats any
non-`200` HTTP status as a hard failure before looking at the body
(`apiClient.js`).

`result` for `addonCollectionGet` is `CollectionResponse` (`response.rs`):

```json
{
  "addons": [ <Descriptor>, ... ],
  "lastModified": "<RFC 3339 UTC timestamp>"
}
```

- `addons` is the **ordered** array of descriptors, same structure as a local
  export: `{ "manifest": {...}, "transportUrl": "...", "flags": { "official": bool, "protected": bool } }`
  (`descriptor.rs`). `transportName` is not part of the `stremio-core` struct
  but may still appear; `stremioctl`'s lossless parser preserves it and any
  other unknown key either way.
- The old JS `test.js` also shows an `isInitial` boolean in the result;
  `stremio-core` ignores it. `stremioctl` preserves unknown result keys in the
  snapshot's raw metadata but does not depend on them.

## How `stremioctl` maps outcomes

| Condition | Exit | Type |
| --------- | ---- | ---- |
| 2xx, `result.addons` is a JSON array | 0 | success |
| 2xx, body has an `error` object | 4 | `AuthenticationError` |
| HTTP 401 / 403 | 4 | `AuthenticationError` |
| HTTP other non-2xx | 3 | `NetworkError` |
| connection error, timeout, DNS failure | 3 | `NetworkError` |
| 2xx, neither `result` nor `error`, or `result.addons` not an array | 3 | `NetworkError` ("malformed response") |
| response larger than 8 MiB | 3 | `NetworkError` |

Treating **any** body-level `error` on `addonCollectionGet` as an authentication
failure is a deliberate simplification: on a read of your own collection, the
only thing the client controls is the auth key, so a rejected request is
actionable as "your key is wrong or expired". The server's `error.code` table is
not publicly documented, so it is not branched on; the sanitized `error.message`
is surfaced.

## Obtaining an auth key without giving the CLI a password

`stremioctl` never logs in. You supply an already-issued session auth key, which
the official clients persist locally after you sign in. No password reaches this
tool.

**From the web app (verified against source).** `stremio-core` stores the whole
profile in `localStorage` under the key **`profile`**
(`constants.rs`: `PROFILE_STORAGE_KEY = "profile"`). The value is JSON; the auth
key is at **`.auth.key`** (`types/profile/profile.rs` `Profile.auth: Option<Auth>`,
`types/profile/auth.rs` `Auth.key: AuthKey(String)`, serialized `camelCase`). So
in the browser console on a signed-in <https://web.stremio.com>:

```js
JSON.parse(localStorage.getItem("profile")).auth.key
```

**From a desktop or mobile install (not verified here).** The same profile blob
is persisted by the app; the exact file location varies by platform and version.
Look for a JSON file in the app's data directory containing an `auth` object with
a `key` string. Confirm against your build rather than trusting a path from this
note.

**Device link, no password at all (API verified, flow not automated).** The
`link` API at `https://link.stremio.com` (`stremio-core`
`types/api/request.rs` `LinkRequest::Create` / `Read`, `VERSION = "v2"`) issues a
code you approve from an already-signed-in session; `Read` returns
`{ "authKey": "..." }` (`response.rs` `LinkAuthKey`). `stremioctl` does not drive
this in v1 — perform the exchange yourself and paste the result.

Provide the key to `stremioctl` as either:

- `export STREMIO_AUTH_KEY=<the-key>` (read only by `account` commands, never
  logged), or
- a file: `printf '%s' '<the-key>' > ~/.config/stremioctl/auth.key && chmod 600
  ~/.config/stremioctl/auth.key`, then
  `--auth-key-file ~/.config/stremioctl/auth.key`. It must be a regular file you
  own with no group/other access.

To invalidate a key, sign out of that session in a Stremio app; the server
revokes it. There is no local revocation.

## Request / response — `addonCollectionSet` (Phase 5)

Implemented in Phase 5 as `stremioctl.account.push_addon_collection`, used by
`account apply` and `account rollback`.

Sources inspected (same `stremio-core` tree as above unless noted):

| What | Path | Detail |
| ---- | ---- | ------ |
| Request enum, path, method | `src/types/api/request.rs` | `APIRequest::AddonCollectionSet { auth_key: AuthKey, addons: Vec<Descriptor> }`, `#[serde(tag = "type")] #[serde(rename_all = "camelCase")]`, `path() -> "addonCollectionSet"`, POST |
| Success envelope | `src/types/api/response.rs` | `pub struct SuccessResponse { pub success: True }` |
| `True` type | `src/types/true.rs` | deserializes **only** from JSON `true`; serializes as `true` |
| Exact wire body + response | `src/unit_tests/ctx/push_addons_to_api.rs` | request `{"type":"AddonCollectionSet","authKey":"…","addons":[{"manifest":{…},"transportUrl":"…","flags":{"official":false,"protected":false}}]}` → POST `https://api.strem.io/api/addonCollectionSet` → `APIResult::Ok(SuccessResponse { success: True {} })` |

Request body:

```json
{ "type": "AddonCollectionSet", "authKey": "<AUTH_KEY>", "addons": [ <Descriptor>, ... ] }
```

`addons` is the **complete, ordered** collection. There is no partial or
per-add-on mutation call; an apply sends the whole target once.

Response:

```json
{ "result": { "success": true } }
```

`stremioctl` treats anything other than `result.success === true` as a failure:
a body-level `error` object or HTTP 401/403 → `AuthenticationError` (exit 4);
any other non-2xx, a transport error, a non-JSON body, or `success` not exactly
`true` → `NetworkError` (exit 3). Messages are scrubbed of the auth key exactly
as on the read path.

The auth key travels only in the JSON body, never a URL, header, or log line —
identical to `addonCollectionGet`.

## Not implemented

- Any email/password `login` / `register` / `loginWithToken` flow — out of scope
  by SPEC §3. The user supplies an already-issued auth key.
- The `link` device-pairing exchange is described above but not automated in v1.
