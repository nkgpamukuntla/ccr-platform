"""Offline collector bundles: the envelope, how it is opened, and what it becomes.

A bundle is one device's facts, encrypted on the county PC for one office (walkthrough slide 8).
The collector has no AWS access, so it uses the office key's public half:

    K   = 64 random bytes                       mac_key = K[:32], enc_key = K[32:]
    ek  = RSA-OAEP-SHA-256(office public key, K)
    ct  = AES-256-CBC(enc_key, iv, PKCS#7(facts JSON))
    tag = HMAC-SHA-512(mac_key, aad || iv || ct || bitlen(aad) as uint64 BE)[:32]
    aad = "ccr-bundle/1|<office id>|<key ARN>"

which is JWE's A256CBC-HS512 (RFC 7516 / 7518 section 5.2.2), chosen because Windows
PowerShell 5.1 (.NET Framework) has AES-CBC and HMAC but no AES-GCM. Only the portal can
unwrap K (kms:Decrypt, RSAES_OAEP_SHA_256). The tag proves the bundle was not altered; the
download token inside proves which issued collector made it.
"""

import base64
import hashlib
import hmac
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FORMAT = "ccr-bundle/1"
ENC = "RSA-OAEP-256/A256CBC-HS512"
MAX_BYTES = 2 * 1024 * 1024
STALE_DAYS = 30


class BundleError(ValueError):
    """The bundle is refused, with a reason fit to show the county."""


def aad(office_id: str, key_arn: str) -> bytes:
    return f"{FORMAT}|{office_id}|{key_arn}".encode()


def _b64(env: dict[str, Any], field: str) -> bytes:
    try:
        return base64.b64decode(env[field], validate=True)
    except (KeyError, TypeError, ValueError) as e:
        raise BundleError(f"bundle field '{field}' missing or not base64") from e


def parse_envelope(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_BYTES:
        raise BundleError("bundle over 2 MB; not a collector bundle")
    try:
        env = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise BundleError("not a collector bundle (expected a .ccre file)") from e
    if not isinstance(env, dict) or env.get("format") != FORMAT:
        raise BundleError(f"not a collector bundle (format must be {FORMAT})")
    if env.get("enc") != ENC:
        raise BundleError(f"unsupported encryption '{env.get('enc')}'")
    for f in ("office_id", "key_arn"):
        if not isinstance(env.get(f), str) or not env[f]:
            raise BundleError(f"bundle field '{f}' missing")
    return env


def open_bundle(env: dict[str, Any], unwrap: Callable[[bytes], bytes]) -> dict[str, Any]:
    """Unwrap the content key, check the tag, decrypt. Raises BundleError on any failure."""
    ek, iv, ct, tag = (_b64(env, f) for f in ("ek", "iv", "ct", "tag"))
    if len(iv) != 16 or len(tag) != 32 or not ct or len(ct) % 16:
        raise BundleError("bundle is malformed")
    try:
        key = unwrap(ek)
    except Exception as e:
        raise BundleError("bundle was not made for this office's key") from e
    if len(key) != 64:
        raise BundleError("bundle content key has the wrong length")
    a = aad(env["office_id"], env["key_arn"])
    mac = hmac.new(key[:32], a + iv + ct + (len(a) * 8).to_bytes(8, "big"), hashlib.sha512).digest()[:32]
    if not hmac.compare_digest(mac, tag):
        raise BundleError("bundle was altered after it was written (integrity check failed)")
    dec = Cipher(algorithms.AES(key[32:]), modes.CBC(iv)).decryptor()
    unpad = padding.PKCS7(128).unpadder()
    try:
        plain = unpad.update(dec.update(ct) + dec.finalize()) + unpad.finalize()
        facts = json.loads(plain.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as e:
        raise BundleError("bundle content is unreadable") from e
    if not isinstance(facts, dict):
        raise BundleError("bundle content is unreadable")
    return facts


def seal(facts: dict[str, Any], office_id: str, key_arn: str, wrap: Callable[[bytes], bytes], key: bytes, iv: bytes) -> bytes:
    """The collector's half, in Python: used by tests and to document the format exactly."""
    enc = Cipher(algorithms.AES(key[32:]), modes.CBC(iv)).encryptor()
    pad = padding.PKCS7(128).padder()
    ct = enc.update(pad.update(json.dumps(facts).encode()) + pad.finalize()) + enc.finalize()
    a = aad(office_id, key_arn)
    tag = hmac.new(key[:32], a + iv + ct + (len(a) * 8).to_bytes(8, "big"), hashlib.sha512).digest()[:32]
    b = base64.b64encode
    env = {"format": FORMAT, "enc": ENC, "office_id": office_id, "key_arn": key_arn}
    env |= {"ek": b(wrap(key)).decode(), "iv": b(iv).decode(), "ct": b(ct).decode(), "tag": b(tag).decode()}
    return json.dumps(env).encode()


def _dt(v: Any) -> datetime | None:
    if not isinstance(v, str) or not v:
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def _s(v: Any) -> str | None:
    return v.strip() if isinstance(v, str) and v.strip() else None


def check(facts: dict[str, Any], now: datetime | None = None) -> list[str]:
    """Content checks after decryption. Returns warnings; raises BundleError if unusable."""
    now = now or datetime.now(UTC)
    col = facts.get("collector") or {}
    dev = facts.get("device") or {}
    if not isinstance(col, dict) or not isinstance(dev, dict) or not _s(col.get("token")):
        raise BundleError("bundle has no collector token")
    if not (_s(dev.get("hostname")) or _s(dev.get("serial"))):
        raise BundleError("bundle has neither hostname nor serial")
    warnings = []
    collected = _dt(col.get("finished"))
    if collected is None:
        raise BundleError("bundle has no collection time")
    if collected > now + timedelta(days=1):
        raise BundleError("bundle collection time is in the future (check the PC clock)")
    if collected < now - timedelta(days=STALE_DAYS):
        warnings.append(f"collected {collected.date()}, over {STALE_DAYS} days ago")
    if not col.get("elevated"):
        warnings.append("collector was not run as administrator: BitLocker, TPM and Secure Boot may be incomplete")
    for e in (facts.get("errors") or [])[:10]:
        warnings.append(f"collector could not read {e}")
    return warnings


def observation(facts: dict[str, Any]) -> dict[str, Any]:
    """A device_observation row (same shape as an imported CSV row), source 'collector'."""
    dev = facts.get("device") or {}
    sec = facts.get("security") or {}
    agents = [a for a in (sec.get("edr_agents") or []) if isinstance(a, dict)]
    running = [a for a in agents if a.get("running")]
    status = "active" if running else ("inactive" if agents else "none")
    named = running or agents
    product = ", ".join(sorted({str(a.get("product")) for a in named if a.get("product")})) or None
    macs = [m for m in (dev.get("macs") or []) if isinstance(m, str)]
    av = sec.get("defender") or {}
    av_status = None
    if isinstance(av, dict) and "realtime" in av:
        av_status = "active" if av.get("realtime") else "inactive"
    return {
        "hostname": (_s(dev.get("hostname")) or "").upper() or None,
        "serial": (_s(dev.get("serial")) or "").upper() or None,
        "mac": macs[0] if macs else None,
        "os": _s(dev.get("os")),
        "os_build": _s(dev.get("os_build")),
        "last_seen": _dt((facts.get("collector") or {}).get("finished")),
        "edr_product": product,
        "edr_status": status,
        "managed": None,  # domain or Entra join is not device management; that comes from RMM/Intune
        "site": None,
        "attributes": {"av_status": av_status, "collected": facts} if av_status else {"collected": facts},
    }
