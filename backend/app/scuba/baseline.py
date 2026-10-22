"""Requirement text for each SCuBA policy, read from the vendored baseline document (CC0)."""

import re
from functools import cache

from app.scuba.evaluate import REGO_DIR


@cache
def requirements(product: str = "aad") -> dict[str, str]:
    """{'MS.AAD.3.2v2': 'If phishing-resistant MFA has not been enforced, ...', ...}"""
    text = (REGO_DIR / f"{product}.md").read_text(encoding="utf-8")
    out: dict[str, str] = {}
    for m in re.finditer(r"^#{3,5}\s+(MS\.[A-Z]+\.\d+\.\d+v\d+)\s*\n+(.+?)\n", text, re.MULTILINE):
        out[m.group(1)] = m.group(2).strip().replace("**", "")
    return out


def requirement(policy_id: str) -> str:
    product = policy_id.split(".")[1].lower()
    try:
        return requirements(product).get(policy_id, "")
    except FileNotFoundError:
        return ""
