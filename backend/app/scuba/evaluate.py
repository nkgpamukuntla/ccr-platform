"""Run ScubaGear's own SCuBA rules with OPA, exactly as ScubaGear does, and classify each result.

    opa eval data.aad.tests -i <input> -d AADConfig.rego -d Utils -f values

Results keep ScubaGear's fields (PolicyId, Criticality, RequirementMet, ReportDetails,
Commandlet, ActualValue). The status follows ScubaGear's report: Pass, Fail (a SHALL not met),
Warning (a SHOULD not met), N/A (not implemented / not applicable), and Error when a command the
policy depends on failed, so a missing permission or licence is never reported as a failure.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

BASELINE = "v1.8.0"
REGO_DIR = Path(__file__).parent / "rego" / BASELINE

Status = Literal["pass", "fail", "warning", "na", "error"]


class ScubaResult(BaseModel):
    policy_id: str
    product: str
    criticality: str
    status: Status
    requirement_met: bool
    details: str
    commandlets: list[str]


def opa_path() -> str:
    found = os.environ.get("OPA_PATH") or shutil.which("opa")
    if not found:
        raise RuntimeError("OPA is not installed (set OPA_PATH)")
    return found


def run_opa(product_input: dict[str, Any], package: str = "aad", rego: str = "AADConfig.rego") -> list[dict[str, Any]]:
    with tempfile.TemporaryDirectory() as tmp:
        input_file = Path(tmp) / "input.json"
        input_file.write_text(json.dumps(product_input), encoding="utf-8")
        cmd = [
            opa_path(),
            "eval",
            f"data.{package}.tests",
            "-i",
            str(input_file),
            "-d",
            str(REGO_DIR / rego),
            "-d",
            str(REGO_DIR / "Utils"),
            "-f",
            "values",
        ]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)  # noqa: S603 - fixed argv, no shell
    if out.returncode != 0:
        raise RuntimeError(f"opa eval failed: {out.stderr[:1000]}")
    values = json.loads(out.stdout)
    tests: list[dict[str, Any]] = values[0] if values else []
    return tests


def classify(test: dict[str, Any], failed_commands: set[str], product: str = "aad") -> ScubaResult:
    crit = str(test.get("Criticality", ""))
    commandlets = [str(c) for c in (test.get("Commandlet") or [])]
    met = bool(test.get("RequirementMet"))
    status: Status
    if failed_commands & set(commandlets):
        status = "error"
    elif "Not-Implemented" in crit or "3rd Party" in crit:
        status = "na"
    elif met:
        status = "pass"
    elif crit.startswith("Shall"):
        status = "fail"
    else:
        status = "warning"
    return ScubaResult(
        policy_id=str(test.get("PolicyId")),
        product=product,
        criticality=crit,
        status=status,
        requirement_met=met,
        details=str(test.get("ReportDetails", "")),
        commandlets=commandlets,
    )


def evaluate_aad(opa_doc: dict[str, Any]) -> list[ScubaResult]:
    failed = set(opa_doc.get("aad_unsuccessful_commands") or [])
    # The privileged-user and -role commands in the tracker map to the Graph cmdlets the rules name.
    if "Get-PrivilegedUser" in failed or "Get-PrivilegedRole" in failed:
        failed |= {
            "Get-MgBetaUser",
            "Get-MgBetaDirectoryRoleMember",
            "Get-MgBetaDirectoryRole",
            "Get-MgBetaRoleManagementDirectoryRoleAssignmentScheduleInstance",
            "Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance",
            "Get-MgBetaPolicyRoleManagementPolicyAssignment",
            "Get-MgBetaPolicyRoleManagementPolicyRule",
            "Get-PrivilegedUser",
            "Get-PrivilegedRole",
        }
    return sorted((classify(t, failed) for t in run_opa(opa_doc)), key=lambda r: _order(r.policy_id))


def _order(policy_id: str) -> tuple[int, ...]:
    """MS.AAD.3.10v1 sorts after MS.AAD.3.9v1."""
    nums = policy_id.split(".")[2:]
    try:
        return tuple(int(n.split("v")[0]) for n in nums)
    except ValueError:
        return (999,)


# ---------- IRMA roll-up ----------
# Which SCuBA policies establish each IRMA control. "required" failing makes the control a gap;
# "advisory" failing (with required met) makes it weak; missing or errored required -> not observed.
IRMA_MAP: dict[int, dict[str, list[str]]] = {
    1: {"required": ["MS.AAD.3.2v1", "MS.AAD.1.1v1"], "advisory": ["MS.AAD.3.1v1", "MS.AAD.3.5v1", "MS.AAD.3.9v1"]},
    2: {"required": ["MS.AAD.3.2v1"], "advisory": ["MS.AAD.8.1v1", "MS.AAD.8.2v1", "MS.AAD.8.3v1"]},
    3: {
        "required": ["MS.AAD.3.6v1"],
        "advisory": [
            "MS.AAD.3.5v1",
            "MS.AAD.7.1v1",
            "MS.AAD.7.2v1",
            "MS.AAD.7.3v1",
            "MS.AAD.7.4v1",
            "MS.AAD.7.5v1",
            "MS.AAD.7.6v1",
            "MS.AAD.7.7v1",
            "MS.AAD.7.8v1",
            "MS.AAD.7.9v1",
        ],
    },
}


def rollup(control: int, results: list[ScubaResult]) -> tuple[str, dict[str, Any]] | None:
    m = IRMA_MAP.get(control)
    if not m:
        return None
    by = {r.policy_id: r for r in results}
    req = [by.get(p) for p in m["required"]]
    adv = [by[p] for p in m["advisory"] if p in by]
    detail = {
        "scuba_baseline": BASELINE,
        "required": {p: (by[p].status if p in by else "missing") for p in m["required"]},
        "advisory_not_met": [r.policy_id for r in adv if r.status in ("fail", "warning")],
    }
    if any(r is None or r.status in ("error", "na") for r in req):
        return "not_observed", detail
    if any(r.status in ("fail", "warning") for r in req if r):
        return "gap", detail
    if detail["advisory_not_met"]:
        return "weak", detail
    return "met", detail
