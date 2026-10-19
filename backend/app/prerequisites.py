"""Step 3: turn the path into a role-tagged checklist (walkthrough slides 17 and 26).

Only the prerequisites for this office's path appear. Indicative until design phase 0.
"""

from pydantic import BaseModel

from app.profiles import PathItem


class Prerequisite(BaseModel):
    group: str
    item: str
    who: str


def _microsoft(mode: str) -> list[Prerequisite]:
    if mode == "import":
        return [Prerequisite(group="Microsoft 365", item="Users and devices export using template v1", who="Cloud engineer")]
    return [
        Prerequisite(group="Microsoft 365", item="Tenant ID and primary domain", who="Cloud engineer"),
        Prerequisite(group="Microsoft 365", item="Global Administrator for one-time consent", who="Cloud engineer"),
        Prerequisite(group="Microsoft 365", item="Entra ID P1 (Conditional Access reporting)", who="Cloud engineer"),
    ]


EDR_CONNECT = {
    "crowdstrike": [
        ("API client: Hosts Read, Alerts Read, Prevention Policies Read", "Security engineer"),
        ("Falcon cloud region (GovCloud or commercial)", "Security engineer"),
    ],
    "defender": [("Covered by the Microsoft consent (Machine and Alert read)", "Security engineer")],
    "sentinelone": [("Viewer-role API token, key ID and tenant URL", "Console administrator")],
    "cortex": [("Read-only API key, key ID and tenant URL", "Console administrator")],
    "other": [("Read-only API credentials for the console", "Console administrator")],
}


def generate(path: list[PathItem]) -> list[Prerequisite]:
    items: list[Prerequisite] = []
    for p in path:
        if p.source == "microsoft365":
            items += _microsoft(p.mode)
        elif p.source == "identity":
            items.append(Prerequisite(group="Identity", item="Questionnaire on accounts and MFA", who="Site IT"))
        elif p.source == "intune":
            items.append(
                Prerequisite(group="Intune", item="Covered by the Microsoft consent", who="Cloud engineer")
                if p.mode == "connect"
                else Prerequisite(group="Intune", item="Devices export from the admin centre", who="Cloud engineer")
            )
        elif p.source == "rmm":
            items.append(Prerequisite(group="RMM import", item="Device inventory export using template v1", who="MSP"))
        elif p.source in EDR_CONNECT:
            if p.mode == "connect":
                items += [Prerequisite(group=p.label, item=i, who=w) for i, w in EDR_CONNECT[p.source]]
            else:
                items.append(Prerequisite(group=p.label, item="Host list export using template v1", who="Security engineer"))
        elif p.source == "collector":
            items.append(Prerequisite(group="Collector", item="Local admin on each PC; PowerShell 5.1+", who="Site IT"))
            items.append(Prerequisite(group="Collector", item="HTTPS upload, or USB to one PC that has it", who="Site IT"))
    items.append(Prerequisite(group="Attestations", item="Backup design, DR plan, training roster (signed)", who="Signatory"))
    return items
