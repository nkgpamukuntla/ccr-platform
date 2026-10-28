"""Import validation and reconciliation (walkthrough slides 9 and 29: rejected or warned, never silently loaded)."""

from app.imports import edr_coverage, reconcile, template_csv, validate

# A CrowdStrike-style host export, headers as the console writes them.
FALCON = """Hostname,Agent ID,Sensor Version,Status,Last Seen,Serial Number,Platform
CLERK-FRONT-01,aid-1,7.18.19105,Online,2026-10-20T14:02:11Z,SN001,Windows
CLERK-FRONT-02,aid-2,7.18.19105,Offline,2026-10-01T09:00:00Z,SN002,Windows
PUBLIC-KIOSK-1,aid-3,7.17.18911,Online,10/21/2026 08:15:00,SN003,Windows
"""

RMM = """Device Name;Serial Number;OS Build;Last Patch Date;AV Status;Site
CLERK-FRONT-01;SN001;10.0.22631;2026-10-10;Protected;LAB-A1
SCANNER-PC;SN009;10.0.19045;2026-06-01;Disabled;LAB-A1
"""


def test_vendor_headers_are_recognised_as_aliases() -> None:
    v = validate("edr_hosts", FALCON)
    assert v.accepted and v.rows_ok == 3 and v.rows_rejected == 0
    assert v.columns["agent_version"] == "Sensor Version" and v.columns["edr_status"] == "Status"
    assert [d["edr_status"] for d in v.devices] == ["active", "inactive", "active"]
    assert v.devices[2]["last_seen"] is not None  # US date format parsed


def test_semicolon_rmm_export_and_av_state() -> None:
    v = validate("rmm_inventory", RMM)
    assert v.accepted and v.rows_ok == 2
    # AV status is antivirus, not EDR: it is kept apart and never sets EDR coverage.
    assert v.devices[1]["av_status"] == "inactive" and v.devices[1]["edr_status"] is None
    assert v.devices[1]["managed"] is True


def test_missing_required_column_rejects_the_file() -> None:
    v = validate("edr_hosts", "Hostname,Status\nPC1,Online\n")
    assert not v.accepted and v.rows_ok == 0
    assert "agent_id" in v.issues[0].message


def test_bad_rows_are_rejected_individually_and_listed() -> None:
    good = "PC-4,aid-4,7.1,Online,2026-10-20,SN004,Windows\nPC-5,aid-5,7.1,Online,2026-10-20,SN005,Windows\n"
    text = FALCON + good + "BADROW,aid-6,7.1,Online,yesterday,SN006,Windows\n"
    v = validate("edr_hosts", text)
    assert v.accepted and v.rows_ok == 5 and v.rows_rejected == 1  # 1 of 6 is under the 20% limit
    assert v.issues[0].row == 7 and "not a date" in v.issues[0].message


def test_too_many_bad_rows_reject_the_file() -> None:
    text = "Hostname,Agent ID,Agent Version,Status,Last Seen\nA,1,1,Online,never\nB,2,1,Online,never\nC,3,1,Online,2026-10-01\n"
    v = validate("edr_hosts", text)
    assert not v.accepted and "over 20%" in v.issues[0].message


def test_duplicates_and_unknown_os_are_warned_not_dropped() -> None:
    text = "Hostname,Serial,OS\nPC1,S1,Windows 11\nPC1,S1,Windows 11\nPC2,S2,TempleOS\n"
    v = validate("generic_v1", text)
    assert v.accepted and v.rows_ok == 3
    levels = [(i.row, i.level) for i in v.issues]
    assert (3, "warning") in levels and (4, "warning") in levels


def test_reconcile_matches_by_serial_then_hostname_and_keeps_unmatched() -> None:
    obs = [
        {
            "source": "import:edr_hosts",
            "hostname": "CLERK-FRONT-01",
            "serial": "SN001",
            "os": "Windows",
            "last_seen": None,
            "edr_status": "active",
            "managed": None,
            "site": None,
        },
        {
            "source": "import:rmm_inventory",
            "hostname": "CLERK-FRONT-01",
            "serial": "SN001",
            "os": None,
            "last_seen": None,
            "edr_status": "active",
            "managed": True,
            "site": "LAB-A1",
        },
        {
            "source": "import:rmm_inventory",
            "hostname": "SCANNER-PC",
            "serial": "SN009",
            "os": None,
            "last_seen": None,
            "edr_status": "inactive",
            "managed": True,
            "site": "LAB-A1",
        },
        {
            "source": "import:asset_register",
            "hostname": "SCANNER-PC",
            "serial": None,
            "os": None,
            "last_seen": None,
            "edr_status": None,
            "managed": None,
            "site": "LAB-A1",
        },
        {
            "source": "import:asset_register",
            "hostname": "ORPHAN-1",
            "serial": None,
            "os": None,
            "last_seen": None,
            "edr_status": None,
            "managed": None,
            "site": "LAB-A1",
        },
    ]
    devs = reconcile(obs)
    assert len(devs) == 3
    by = {d["hostname"]: d for d in devs}
    assert by["CLERK-FRONT-01"]["matched"] and by["SCANNER-PC"]["matched"] and not by["ORPHAN-1"]["matched"]
    assert edr_coverage(devs) == {"devices": 3, "covered": 1, "uncovered": 2}


def test_rmm_av_protected_does_not_count_as_edr() -> None:
    edr = validate(
        "edr_hosts", "Hostname,Agent ID,Sensor Version,Status,Last Seen,Serial Number\nPC1,a1,7,Offline,2026-09-01,S1\n"
    )
    rmm = validate("rmm_inventory", RMM.replace("SN001", "S1").replace("CLERK-FRONT-01", "PC1"))
    obs = [{**d, "source": "import:edr_hosts"} for d in edr.devices] + [
        {**d, "source": "import:rmm_inventory"} for d in rmm.devices
    ]
    devs = {d["hostname"]: d for d in reconcile(obs)}
    assert devs["PC1"]["edr"] == "inactive" and devs["PC1"]["av"] == "active"
    assert devs["SCANNER-PC"]["edr"] == "none"
    assert edr_coverage(list(devs.values()))["covered"] == 0


def test_template_download_has_required_columns() -> None:
    assert template_csv("edr_hosts").startswith("Hostname,Agent Id,Agent Version,Status,Last Seen")


def test_falcon_host_management_export_headers() -> None:
    text = "Hostname,Host ID,Last Seen,Sensor Version,Status,Platform,Serial Number\nDBIZ-LT-01,abc123,2026-10-27T10:00:00Z,7.18.19105,Online,Windows,DX000B84\n"
    v = validate("edr_hosts", text)
    assert v.accepted and v.columns["agent_id"] == "Host ID" and v.devices[0]["edr_status"] == "active"
