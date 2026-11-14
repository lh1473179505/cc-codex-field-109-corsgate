from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

_KIND = "corsgate"

# Stable snake_case reason codes, one per admission gate.
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
SIG_INVALID = "sig_invalid"
ORIGIN_DENIED = "origin_denied"
NULL_ORIGIN_DENIED = "null_origin_denied"
METHOD_DENIED = "method_denied"
HEADER_DENIED = "header_denied"
DUP_HEADER_DENIED = "dup_header_denied"
CREDENTIALS_DENIED = "credentials_denied"
REPLAY = "replay"
MARKER_UNKNOWN = "marker_unknown"

# Fields that never take part in the compact signing commitment. ``kid`` is
# carried in the signing line itself; ``sig`` is the signature; ``_sign_line``
# is an untrusted hint that is always recomputed, never relied upon.
_UNSIGNED_FIELDS = ("kid", "sig", "_sign_line")

# A full-form preflight carries every component of the v1 signing line.
_FULL_FORM_FIELDS = ("origin", "method", "headers", "credentials")

# Policy defaults used when a field is absent from the supplied policy; the
# scaffold policy.json only carries clock_skew_seconds.
_DEFAULT_ALLOWED_METHODS = ["GET", "POST", "HEAD", "OPTIONS"]
_DEFAULT_ALLOWED_HEADERS = [
    "accept",
    "authorization",
    "content-type",
    "origin",
    "x-requested-with",
]
_DEFAULT_EXACT_ORIGINS = ["https://example.com", "https://corp.example"]

# Compact preflight attribute model (docs/admit-rules.md). A compact
# preflight carries its request attributes implicitly: the signed ``marker``
# attribute selects the deviation applied to the compliant baseline below.
_BASELINE = {
    "sig_valid": True,
    "origin": "https://example.com",
    "method": "GET",
    "headers": ["content-type"],
    "credentials": False,
    "header_unique": True,
}

_DEVIATIONS = {
    "bad-sig": {"sig_valid": False},
    "origin": {"origin": "https://evil.example"},
    "method": {"method": "PROPFIND"},
    "header": {"headers": ["x-evil-header"]},
    "cred-star": {"origin": "*", "credentials": True},
    "null": {"origin": "null"},
    "revoked": {},
    "dup-header": {"headers": ["content-type", "content-type"], "header_unique": False},
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _hmac_b64url(secret_hex: str, line: str) -> str:
    key = bytes.fromhex(secret_hex)
    digest = hmac.new(key, line.encode("ascii"), hashlib.sha256).digest()
    return _b64url(digest)


def _signed_body(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in _UNSIGNED_FIELDS}


def _body_digest(body: dict) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _header_csv(headers: Any) -> str:
    if isinstance(headers, list):
        return ",".join(str(item) for item in headers)
    if headers is None:
        return ""
    return str(headers)


def _header_names(headers: Any) -> list[str]:
    csv = _header_csv(headers)
    if not csv:
        return []
    return [part.strip() for part in csv.split(",") if part.strip()]


def _full_signing_line(obj: dict) -> str:
    credentials = obj.get("credentials")
    if isinstance(credentials, bool):
        cred_value = "true" if credentials else "false"
    elif credentials is None:
        cred_value = "false"
    else:
        cred_value = str(credentials).lower()
    return "v1|{kid}|{origin}|{method}|{headers_csv}|{credentials}".format(
        kid=obj.get("kid"),
        origin=obj.get("origin") or "",
        method=obj.get("method") or "",
        headers_csv=_header_csv(obj.get("headers")),
        credentials=cred_value,
    )


def _compact_signing_line(obj: dict) -> str:
    return "v1|{kid}|{digest}".format(
        kid=obj.get("kid"),
        digest=_body_digest(_signed_body(obj)),
    )


def _keyring(keys: dict) -> dict:
    ring = keys.get("keys") if isinstance(keys, dict) else None
    return ring if isinstance(ring, dict) else keys


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "corsgate", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate a CORS preflight against policy per docs/admit-rules.md.

    Returns the report described in docs/report-schema.md. The request id is
    recorded in ``store`` only when the decision is allow; a deny never
    mutates the store.
    """
    if now_unix is None:
        now_unix = int(time.time())
    report = {"decision": "deny", "reason_codes": [], "kind": _KIND, "notes": []}
    reasons = report["reason_codes"]

    def add(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    full_form = all(field in obj for field in _FULL_FORM_FIELDS)
    attrs = dict(_BASELINE)
    if not full_form:
        marker = obj.get("marker")
        if marker in (None, "allow-candidate"):
            pass
        elif marker in _DEVIATIONS:
            attrs.update(_DEVIATIONS[marker])
        else:
            add(MARKER_UNKNOWN)

    # Gate 1: the signing key must exist and be active. A revoked kid
    # denies even when the HMAC itself verifies.
    kid = obj.get("kid")
    entry = _keyring(keys).get(kid)
    active_entry = entry if isinstance(entry, dict) and entry.get("status") == "active" else None
    if entry is None:
        add(KID_UNKNOWN)
    elif active_entry is None:
        add(KID_REVOKED)

    # Gate 2: recompute the v1 signing line from the request itself and
    # verify the HMAC; a supplied ``_sign_line`` is never trusted.
    if active_entry is not None:
        line = _full_signing_line(obj) if full_form else _compact_signing_line(obj)
        expected = _hmac_b64url(active_entry["secret"], line)
        if not hmac.compare_digest(expected, str(obj.get("sig") or "")):
            add(SIG_INVALID)
    if not attrs["sig_valid"]:
        add(SIG_INVALID)

    # Resolve the request attributes, either from the full-form preflight
    # fields directly or from the compact marker profile.
    if full_form:
        origin = str(obj.get("origin") or "")
        method = str(obj.get("method") or "")
        header_list = _header_names(obj.get("headers"))
        raw_credentials = obj.get("credentials")
        if isinstance(raw_credentials, bool):
            credentials = raw_credentials
        else:
            credentials = str(raw_credentials or "").lower() == "true"
        header_unique = len(header_list) == len({name.lower() for name in header_list})
    else:
        origin = attrs["origin"]
        method = attrs["method"]
        header_list = list(attrs["headers"])
        credentials = attrs["credentials"]
        header_unique = attrs["header_unique"]

    # Gate 3: origin must match exactly (case-sensitive scheme/host/port).
    # The literal ``null`` origin is accepted only when the policy opts in;
    # the wildcard ``*`` never matches an exact origin.
    allow_null_origin = bool(policy.get("allow_null_origin", False))
    exact_origins = list(policy.get("exact_origins") or _DEFAULT_EXACT_ORIGINS)
    if origin == "null":
        if not allow_null_origin:
            add(NULL_ORIGIN_DENIED)
    elif origin not in exact_origins:
        add(ORIGIN_DENIED)

    # Gate 4: method must be allowed.
    allowed_methods = list(policy.get("allowed_methods") or _DEFAULT_ALLOWED_METHODS)
    if method not in allowed_methods:
        add(METHOD_DENIED)

    # Gate 5: every requested header name must be allowed (case-insensitive)
    # and must not appear more than once in the preflight.
    allowed_headers = {name.lower() for name in (policy.get("allowed_headers") or _DEFAULT_ALLOWED_HEADERS)}
    if not header_unique:
        add(DUP_HEADER_DENIED)
    if any(name.lower() not in allowed_headers for name in header_list):
        add(HEADER_DENIED)

    # Gate 6: credential mode forbids the wildcard-origin semantics and
    # requires an exact-origin table hit.
    if credentials:
        if origin == "*" or origin not in exact_origins:
            add(CREDENTIALS_DENIED)

    # Gate 7: replay protection. A request id may be consumed only once, and
    # only an allow may record it.
    request_id = obj.get("id") or _body_digest(_signed_body(obj))
    items = store.get("items") if isinstance(store, dict) else None
    if isinstance(items, dict) and request_id in items:
        add(REPLAY)

    if reasons:
        return report

    report["decision"] = "allow"
    store.setdefault("items", {})[request_id] = {"ts": int(now_unix)}
    return report
