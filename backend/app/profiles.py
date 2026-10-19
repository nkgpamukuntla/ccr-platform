"""Step 2 environment profiler: five answers decide the county profile (A-E) and the path.

Profiles and paths follow the solution walkthrough (slides 5 and 16). Deterministic and
pure, so the same answers always give the same path.
"""

from typing import Literal

from pydantic import BaseModel

M365 = Literal["commercial", "gcc", "none", "unsure"]
DeviceMgmt = Literal["intune", "rmm", "gpo", "none", "unsure"]
Edr = Literal["crowdstrike", "defender", "sentinelone", "cortex", "other", "none", "unsure"]
ItAdmin = Literal["county", "msp", "none", "unsure"]
ApiAllowed = Literal["yes", "export_only", "unsure"]
Mode = Literal["connect", "import", "collect", "questionnaire"]


class EnvironmentAnswers(BaseModel):
    m365: M365
    device_mgmt: DeviceMgmt
    edr: Edr
    it_admin: ItAdmin
    api_allowed: ApiAllowed


class PathItem(BaseModel):
    source: str
    label: str
    mode: Mode


class ProfileResult(BaseModel):
    profile: Literal["A", "B", "C", "D", "E"]
    profile_name: str
    site_effort: str
    path: list[PathItem]
    unsure: list[str]  # answers the engineer must confirm in step 3


PROFILE_NAMES = {
    "A": ("Fully managed", "None"),
    "B": ("M365, no Intune", "Low"),
    "C": ("MSP-managed", "Low"),
    "D": ("No M365 tenant", "County runs collector"),
    "E": ("Nothing managed", "Guided call or visit"),
}

EDR_LABELS = {
    "crowdstrike": "CrowdStrike",
    "defender": "Microsoft Defender",
    "sentinelone": "SentinelOne",
    "cortex": "Cortex XDR",
    "other": "Endpoint protection",
}


def classify(a: EnvironmentAnswers) -> ProfileResult:
    """'Not sure' is read as the less-managed answer, so a path is never over-promised."""
    has_m365 = a.m365 in ("commercial", "gcc")
    managed = a.device_mgmt in ("intune", "rmm")
    has_edr = a.edr not in ("none", "unsure")
    apis = a.api_allowed == "yes"

    profile: Literal["A", "B", "C", "D", "E"]
    if not has_m365 and not managed and not has_edr:
        profile = "E"
    elif not has_m365:
        profile = "D"
    elif a.it_admin == "msp":
        profile = "C"
    elif a.device_mgmt == "intune" and has_edr and apis:
        profile = "A"
    else:
        profile = "B"

    path: list[PathItem] = []

    if has_m365:
        path.append(PathItem(source="microsoft365", label="Microsoft 365", mode="connect" if apis else "import"))
    else:
        path.append(PathItem(source="identity", label="Identity (no tenant)", mode="questionnaire"))

    if a.device_mgmt == "intune":
        path.append(PathItem(source="intune", label="Devices (Intune)", mode="connect" if apis else "import"))
    elif a.device_mgmt == "rmm":
        path.append(PathItem(source="rmm", label="Devices (RMM)", mode="import"))

    if has_edr:
        path.append(PathItem(source=a.edr, label=EDR_LABELS[a.edr], mode="connect" if apis else "import"))

    if a.device_mgmt != "intune":
        path.append(PathItem(source="collector", label="Unmanaged PCs", mode="collect"))

    unsure = [k for k, v in a.model_dump().items() if v == "unsure"]
    name, effort = PROFILE_NAMES[profile]
    return ProfileResult(profile=profile, profile_name=name, site_effort=effort, path=path, unsure=unsure)
