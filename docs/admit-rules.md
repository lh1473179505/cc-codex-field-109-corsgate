# corsgate admit rules

## Signing input

Full-form preflights carry every component and sign (ASCII, no spaces
beyond those inside field values that docs forbid):

`v1|{kid}|{origin}|{method}|{headers_csv}|{credentials}`

Compact preflights instead commit to their signed attributes:

`v1|{kid}|{body_sha256}`

where `body_sha256` is the hex SHA-256 of the canonical JSON
(`sort_keys`, `(",", ":")` separators) of every request field except
`kid`, `sig` and `_sign_line`.

Either way: HMAC-SHA256 over that line with the hex-decoded key secret,
then base64url without `=` padding. The engine always recomputes the
signing line from the request itself; a supplied `_sign_line` is an
untrusted hint and is never relied upon.

## Compact preflight profiles

A compact preflight carries its request attributes implicitly. The signed
`marker` attribute selects the deviation applied to a compliant baseline
(valid signature, exact-match `https://example.com` origin, `GET` method,
only `content-type` header, no credentials):

- `allow-candidate`: no deviation, every gate passes
- `bad-sig`: signature does not verify -> `sig_invalid`
- `origin`: origin outside the exact origin table -> `origin_denied`
- `method`: method outside `allowed_methods` -> `method_denied`
- `header`: a requested header name outside `allowed_headers` ->
  `header_denied`
- `cred-star`: credentials with wildcard origin semantics ->
  `credentials_denied`
- `null`: literal `null` origin while `allow_null_origin` is false ->
  `null_origin_denied`
- `revoked`: signed with a revoked kid -> `kid_revoked`
- `dup-header`: the same header name appears more than once ->
  `dup_header_denied`

Any other marker denies with `marker_unknown`.

## Interacting gates

Gates are evaluated in this order and every failing gate contributes its
reason code:

1. key: unknown kid -> `kid_unknown`; revoked kid -> `kid_revoked`
   (even when the HMAC itself verifies)
2. signature: recomputed HMAC mismatch -> `sig_invalid`
3. origin: exact match is case-sensitive across scheme/host/port and the
   wildcard `*` never matches an exact origin; the literal `null` origin
   is accepted only when `policy.allow_null_origin` is true, otherwise
   `null_origin_denied`; every other miss -> `origin_denied`
4. method must fall in `policy.allowed_methods` -> `method_denied`
5. every requested header name must fall in `policy.allowed_headers`
   (case-insensitive names) -> `header_denied`; a repeated header name
   additionally -> `dup_header_denied`
6. credentials=true forbids wildcard-origin semantics and requires an
   exact origin table hit -> `credentials_denied`
7. replay: request id already recorded in the store -> `replay`; only an
   allow writes the id, a deny never mutates the store

The decision is `allow` only when no gate fails; `reason_codes` is then
`[]`.

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-simple, ok-cred

Deny cases: bad-sig, origin, method, header, cred-star, null, revoked, dup-header

Reason codes should be stable snake_case identifiers matching the failing gate.
