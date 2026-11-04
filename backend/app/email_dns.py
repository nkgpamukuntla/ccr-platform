"""Email authentication from public DNS: SPF, DMARC and Microsoft 365 DKIM for each verified domain.

The worker looks the records up (`lookup`) and seals them in the bundle like any Graph read; the
evaluator, which has no internet, scores what was recorded (`evaluate`). Public DNS needs no
consent from the tenant. A lookup that failed is reported as not checked, never as missing.
"""

from typing import Any

import dns.exception
import dns.resolver

MAX_DOMAINS = 20
DKIM_SELECTORS = ("selector1", "selector2")  # Microsoft 365's own DKIM selectors


def _txt(r: dns.resolver.Resolver, name: str) -> dict[str, Any]:
    try:
        ans = r.resolve(name, "TXT")
        return {"status": "ok", "records": [b"".join(x.strings).decode(errors="replace") for x in ans]}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {"status": "none", "records": []}
    except dns.exception.DNSException as e:
        return {"status": "error", "error": type(e).__name__, "records": []}


def _cname(r: dns.resolver.Resolver, name: str) -> dict[str, Any]:
    try:
        return {"status": "ok", "records": [str(x.target).rstrip(".") for x in r.resolve(name, "CNAME")]}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {"status": "none", "records": []}
    except dns.exception.DNSException as e:
        return {"status": "error", "error": type(e).__name__, "records": []}


def domains(graph_domains: list[dict[str, Any]]) -> list[str]:
    """Verified custom domains (not *.onmicrosoft.com), default first."""
    own = [d for d in graph_domains if d.get("isVerified") and not str(d.get("id", "")).lower().endswith(".onmicrosoft.com")]
    own.sort(key=lambda d: (not d.get("isDefault"), d["id"]))
    return [str(d["id"]).lower() for d in own][:MAX_DOMAINS]


def lookup(names: list[str]) -> dict[str, Any]:
    r = dns.resolver.Resolver()
    r.lifetime = 5.0
    return {
        d: {
            "spf": _txt(r, d),
            "dmarc": _txt(r, f"_dmarc.{d}"),
            "dkim": {s: _cname(r, f"{s}._domainkey.{d}") for s in DKIM_SELECTORS},
        }
        for d in names
    }


def _tag(record: str, tag: str) -> str | None:
    for part in record.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip().lower() == tag:
            return v.strip().lower()
    return None


def domain_result(d: str, rec: dict[str, Any]) -> dict[str, Any]:
    spf_r = [x for x in rec["spf"]["records"] if x.lower().startswith("v=spf1")]
    if rec["spf"]["status"] == "error":
        spf = "not_checked"
    elif not spf_r:
        spf = "missing"
    elif len(spf_r) > 1:
        spf = "broken"  # more than one SPF record makes every check fail
    elif spf_r[0].lower().rstrip().endswith(("-all", "~all")):
        spf = "ok"
    else:
        spf = "weak"  # ?all or +all lets anyone send as the domain
    dm_r = [x for x in rec["dmarc"]["records"] if x.lower().startswith("v=dmarc1")]
    if rec["dmarc"]["status"] == "error":
        dmarc = "not_checked"
    elif not dm_r:
        dmarc = "missing"
    else:
        dmarc = _tag(dm_r[0], "p") or "none"
    dk = rec["dkim"]
    if any(v["status"] == "ok" and v["records"] for v in dk.values()):
        dkim = "on"
    elif any(v["status"] == "error" for v in dk.values()):
        dkim = "not_checked"
    else:
        dkim = "not_found"  # not Microsoft 365 DKIM; another mail service may sign instead
    return {
        "domain": d,
        "spf": spf,
        "spf_record": spf_r[0] if spf_r else None,
        "dmarc": dmarc,
        "dmarc_record": dm_r[0] if dm_r else None,
        "dkim": dkim,
    }


def evaluate(recorded: dict[str, Any] | None) -> dict[str, Any] | None:
    """Per-domain result and the overall state: met only when every domain has SPF and an enforcing DMARC."""
    if not recorded:
        return None
    rows = [domain_result(d, r) for d, r in recorded.items()]
    if not rows:
        return None
    unsafe = [r["domain"] for r in rows if r["spf"] in ("missing", "broken") or r["dmarc"] == "missing"]
    loose = [r["domain"] for r in rows if r["domain"] not in unsafe and (r["spf"] == "weak" or r["dmarc"] == "none")]
    unknown = [r["domain"] for r in rows if "not_checked" in (r["spf"], r["dmarc"])]
    state = "gap" if unsafe else "weak" if loose else "not_observed" if unknown else "met"
    return {"state": state, "domains": rows, "unsafe": unsafe, "loose": loose}
