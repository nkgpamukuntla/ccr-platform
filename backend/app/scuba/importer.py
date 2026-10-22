"""Parse a ScubaGear results file (ScubaResults_*.json) that an office ran itself and uploaded.

Covers the products we do not read under R7 (Exchange Online, Defender for Office 365,
SharePoint, Teams, Power Platform, Power BI) as well as Entra. Results stay labelled as
imported: the office ran the tool, we did not.
"""

import html
import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.scuba.evaluate import Status

RESULT_STATUS: dict[str, Status] = {"pass": "pass", "fail": "fail", "warning": "warning", "n/a": "na"}
_TAGS = re.compile(r"<[^>]+>")


class ImportedResult(BaseModel):
    product: str
    policy_id: str
    requirement: str
    criticality: str
    status: Status
    details: str


class ImportedReport(BaseModel):
    tenant_id: str
    tenant_name: str
    tool_version: str
    assessed_at: datetime
    products: list[str]
    summary: dict[str, dict[str, int]]
    results: list[ImportedResult]


class ImportError(ValueError):
    pass


def plain(text: Any) -> str:
    return html.unescape(_TAGS.sub(" ", str(text or ""))).replace("  ", " ").strip()


def status_of(result: str) -> Status:
    r = (result or "").strip().lower()
    if r.startswith("error"):
        return "error"
    if r.startswith("omitted") or r.startswith("incorrect"):
        return "na"
    return RESULT_STATUS.get(r, "na")


def parse(doc: dict[str, Any]) -> ImportedReport:
    meta = doc.get("MetaData") or {}
    if meta.get("Tool") != "ScubaGear" or not isinstance(doc.get("Results"), dict):
        raise ImportError("not a ScubaGear results file (expected MetaData.Tool = ScubaGear and a Results section)")
    tenant = str(meta.get("TenantId") or "").lower()
    if not re.fullmatch(r"[0-9a-f-]{36}", tenant):
        raise ImportError("the file has no tenant id")
    try:
        when = datetime.fromisoformat(str(meta.get("TimestampZulu")).replace("Z", "+00:00"))
    except ValueError as e:
        raise ImportError("the file has no valid timestamp") from e
    results: list[ImportedResult] = []
    for product, groups in doc["Results"].items():
        for group in groups or []:
            for c in group.get("Controls") or []:
                results.append(
                    ImportedResult(
                        product=str(product),
                        policy_id=str(c.get("Control ID")),
                        requirement=plain(c.get("Requirement")),
                        criticality=str(c.get("Criticality") or ""),
                        status=status_of(str(c.get("Result"))),
                        details=plain(c.get("Details")),
                    )
                )
    if not results:
        raise ImportError("the file contains no results")
    return ImportedReport(
        tenant_id=tenant,
        tenant_name=str(meta.get("DisplayName") or ""),
        tool_version=str(meta.get("ToolVersion") or ""),
        assessed_at=when,
        products=sorted({r.product for r in results}),
        summary={k: {kk: int(vv) for kk, vv in v.items() if isinstance(vv, int)} for k, v in (doc.get("Summary") or {}).items()},
        results=results,
    )
