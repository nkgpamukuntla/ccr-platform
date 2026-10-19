"""The profiler must reproduce the walkthrough's examples exactly (slides 5 and 16)."""

import pytest

from app.prerequisites import generate
from app.profiles import EnvironmentAnswers, classify


def answers(**kw: str) -> EnvironmentAnswers:
    base = {"m365": "commercial", "device_mgmt": "intune", "edr": "crowdstrike", "it_admin": "county", "api_allowed": "yes"}
    base.update(kw)
    return EnvironmentAnswers(**base)  # type: ignore[arg-type]


def modes(a: EnvironmentAnswers) -> dict[str, str]:
    return {p.source: p.mode for p in classify(a).path}


def test_profile_a_fully_managed_connects_everything() -> None:
    r = classify(answers())
    assert r.profile == "A"
    assert r.site_effort == "None"
    assert modes(answers()) == {"microsoft365": "connect", "intune": "connect", "crowdstrike": "connect"}


def test_profile_b_m365_without_intune_imports_rmm_and_collects() -> None:
    a = answers(device_mgmt="rmm")
    assert classify(a).profile == "B"
    assert modes(a) == {"microsoft365": "connect", "rmm": "import", "crowdstrike": "connect", "collector": "collect"}


def test_profile_c_slide_16_example() -> None:
    # Slide 16: Commercial M365, RMM, CrowdStrike, MSP, APIs yes -> Connect, Import, Connect, Collect.
    a = answers(device_mgmt="rmm", it_admin="msp")
    r = classify(a)
    assert r.profile == "C"
    assert [(p.label, p.mode) for p in r.path] == [
        ("Microsoft 365", "connect"),
        ("Devices (RMM)", "import"),
        ("CrowdStrike", "connect"),
        ("Unmanaged PCs", "collect"),
    ]


def test_profile_d_no_tenant() -> None:
    a = answers(m365="none", device_mgmt="gpo", edr="defender")
    assert classify(a).profile == "D"
    assert modes(a)["identity"] == "questionnaire"


def test_profile_e_nothing_managed_still_gets_a_path() -> None:
    a = answers(m365="none", device_mgmt="none", edr="none", it_admin="none")
    r = classify(a)
    assert r.profile == "E"
    assert r.site_effort == "Guided call or visit"
    assert modes(a) == {"identity": "questionnaire", "collector": "collect"}


def test_export_only_switches_connect_to_import() -> None:
    assert modes(answers(api_allowed="export_only")) == {"microsoft365": "import", "intune": "import", "crowdstrike": "import"}


@pytest.mark.parametrize("field", ["m365", "device_mgmt", "edr", "it_admin", "api_allowed"])
def test_unsure_is_listed_for_the_engineer(field: str) -> None:
    assert field in classify(answers(**{field: "unsure"})).unsure


def test_unsure_never_overpromises() -> None:
    assert classify(answers(device_mgmt="unsure")).profile == "B"
    assert "intune" not in modes(answers(device_mgmt="unsure"))


def test_prerequisites_only_for_this_path() -> None:
    items = generate(classify(answers(device_mgmt="rmm", it_admin="msp")).path)
    groups = {i.group for i in items}
    assert {"Microsoft 365", "RMM import", "CrowdStrike", "Collector", "Attestations"} == groups
    assert all(i.who for i in items)
