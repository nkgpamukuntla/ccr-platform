"""Offline collector bundles: format, integrity, content checks, and the real PowerShell collector."""

import base64
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.collector import bundle

KEY = rsa.generate_private_key(public_exponent=65537, key_size=3072)
OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
OFFICE = "e9661935-f043-42ad-bda5-c793698385af"
ARN = "arn:aws:kms:us-east-1:555509860132:key/test-collector"
SCRIPT = Path(__file__).resolve().parents[2] / "collector" / "Collect-CCREvidence.ps1"


def wrap(k: bytes) -> bytes:
    return KEY.public_key().encrypt(k, OAEP)


def unwrap(ek: bytes) -> bytes:
    return KEY.decrypt(ek, OAEP)


def facts(**over: Any) -> dict[str, Any]:
    f: dict[str, Any] = {
        "collector": {"version": "1.0.0", "token": "tok-1", "finished": datetime.now(UTC).isoformat(), "elevated": True},
        "device": {"hostname": "clerk-front-01", "serial": "5cg3201a01", "os": "Microsoft Windows 11 Pro", "macs": ["AA:BB"]},
        "security": {
            "edr_agents": [{"product": "CrowdStrike Falcon", "service": "CSFalconService", "running": True}],
            "defender": {"realtime": False},
        },
        "errors": [],
    }
    for k, v in over.items():
        f[k] = v
    return f


def sealed(f: dict[str, Any] | None = None) -> bytes:
    return bundle.seal(f or facts(), OFFICE, ARN, wrap, os.urandom(64), os.urandom(16))


def test_round_trip() -> None:
    env = bundle.parse_envelope(sealed())
    assert bundle.open_bundle(env, unwrap)["device"]["hostname"] == "clerk-front-01"


def test_any_change_is_detected() -> None:
    env = json.loads(sealed())
    ct = bytearray(base64.b64decode(env["ct"]))
    ct[5] ^= 1
    env["ct"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(bundle.BundleError, match="altered"):
        bundle.open_bundle(env, unwrap)
    env = json.loads(sealed())
    env["office_id"] = "another-office"  # bound into the tag
    with pytest.raises(bundle.BundleError, match="altered"):
        bundle.open_bundle(env, unwrap)


def test_other_key_is_refused() -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    env = bundle.parse_envelope(sealed())
    with pytest.raises(bundle.BundleError, match="not made for this office"):
        bundle.open_bundle(env, lambda ek: other.decrypt(ek, OAEP))


def test_not_a_bundle() -> None:
    for raw in (b"Hostname,Serial\nPC1,S1\n", b'{"format": "something-else"}'):
        with pytest.raises(bundle.BundleError, match="not a collector bundle"):
            bundle.parse_envelope(raw)


def test_content_checks() -> None:
    now = datetime.now(UTC)
    assert bundle.check(facts()) == []
    old = facts(collector={"token": "t", "finished": (now - timedelta(days=45)).isoformat(), "elevated": False})
    w = bundle.check(old)
    assert any("over 30 days" in x for x in w) and any("not run as administrator" in x for x in w)
    with pytest.raises(bundle.BundleError, match="future"):
        bundle.check(facts(collector={"token": "t", "finished": (now + timedelta(days=3)).isoformat()}))
    with pytest.raises(bundle.BundleError, match="token"):
        bundle.check(facts(collector={"finished": now.isoformat()}))
    with pytest.raises(bundle.BundleError, match="neither hostname nor serial"):
        bundle.check(facts(device={"hostname": ""}))


def test_observation_mapping() -> None:
    o = bundle.observation(facts())
    assert (o["hostname"], o["serial"], o["edr_status"], o["edr_product"]) == (
        "CLERK-FRONT-01",
        "5CG3201A01",
        "active",
        "CrowdStrike Falcon",
    )
    assert o["attributes"]["av_status"] == "inactive" and o["managed"] is None
    stopped = bundle.observation(facts(security={"edr_agents": [{"product": "SentinelOne", "running": False}]}))
    assert stopped["edr_status"] == "inactive" and stopped["edr_product"] == "SentinelOne"
    assert bundle.observation(facts(security={"edr_agents": []}))["edr_status"] == "none"


def _b64int(n: int) -> str:
    return base64.b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode()


@pytest.mark.skipif(shutil.which("powershell.exe") is None, reason="Windows PowerShell not available")
def test_real_powershell_collector_round_trip() -> None:
    """The shipped script, run here, writes a bundle this code opens: same format on both sides."""
    with tempfile.TemporaryDirectory() as d:
        pub = KEY.public_key().public_numbers()
        cfg = {
            "format": "ccr-collector-config/1",
            "office_id": OFFICE,
            "office_name": "Test office",
            "key_arn": ARN,
            "public_key": {"kty": "RSA", "n": _b64int(pub.n), "e": _b64int(pub.e)},
            "token": "tok-ps",
        }
        (Path(d) / "office.json").write_text(json.dumps(cfg))
        ps = shutil.which("powershell.exe") or "powershell.exe"
        args = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT)]
        args += ["-ConfigPath", str(Path(d) / "office.json"), "-OutputPath", d]
        r = subprocess.run(args, capture_output=True, text=True, timeout=180, check=False)  # noqa: S603 (fixed arguments)
        assert r.returncode == 0, r.stderr
        files = list(Path(d).glob("*.ccre"))
        assert len(files) == 1
        env = bundle.parse_envelope(files[0].read_bytes())
        f = bundle.open_bundle(env, unwrap)
        assert f["collector"]["token"] == "tok-ps"  # noqa: S105 and f["device"]["hostname"] == os.environ.get("COMPUTERNAME")
        bundle.check(f)
        assert bundle.observation(f)["hostname"] == os.environ["COMPUTERNAME"].upper()
