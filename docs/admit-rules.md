# corsgate admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{origin}|{method}|{headers_csv}|{credentials}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- Origin 精确匹配（含大小写敏感 scheme/host/port），null 仅当 allow_null_origin
- method 在 allowed_methods；headers 每个都在 allowed_headers（大小写不敏感名）
- credentials=true 时禁止 Origin=* 语义，且必须命中 exact origin 表
- kid 撤销与请求签名绑定

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-simple, ok-cred

Deny cases: bad-sig, origin, method, header, cred-star, null, revoked, dup-header

Reason codes should be stable snake_case identifiers matching the failing gate.
