"""Sample console exports for a small county court office (Lab County A), for testing step 5.

Writes samples/imports/*.csv. The fleet is fixed so results are repeatable:
- 18 devices in the asset register; 15 have the EDR agent, 2 of them offline for weeks.
- The RMM export misses 2 devices and has one the asset register doesn't know.
- Each file has deliberate faults, so the preview shows rejected rows and warnings.

    uv run python ../scripts/make_import_samples.py   (from backend/)
"""

from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples" / "imports"

# hostname, serial, role, model
FLEET = [
    ("CLERK-FRONT-01", "5CG3201A01", "Clerk front counter", "HP EliteDesk 800 G6"),
    ("CLERK-FRONT-02", "5CG3201A02", "Clerk front counter", "HP EliteDesk 800 G6"),
    ("CLERK-FRONT-03", "5CG3201A03", "Clerk front counter", "HP EliteDesk 800 G6"),
    ("CLERK-BACK-01", "5CG3201B01", "Clerk back office", "HP EliteBook 840 G8"),
    ("CLERK-BACK-02", "5CG3201B02", "Clerk back office", "HP EliteBook 840 G8"),
    ("CLERK-BACK-03", "5CG3201B03", "Clerk back office", "HP EliteBook 840 G8"),
    ("JUDGE-CHAMB-01", "PF3KX101", "Judge chambers", "Lenovo ThinkPad T14"),
    ("JUDGE-CHAMB-02", "PF3KX102", "Judge chambers", "Lenovo ThinkPad T14"),
    ("COURTRM-A-BENCH", "PF3KX201", "Courtroom bench", "Lenovo ThinkCentre M70q"),
    ("COURTRM-B-BENCH", "PF3KX202", "Courtroom bench", "Lenovo ThinkCentre M70q"),
    ("EFILE-REVIEW-01", "5CG3201C01", "E-filing review", "HP EliteDesk 800 G6"),
    ("EFILE-REVIEW-02", "5CG3201C02", "E-filing review", "HP EliteDesk 800 G6"),
    ("CASHIER-01", "5CG3201D01", "Cashier", "HP EliteDesk 800 G6"),
    ("PUBLIC-KIOSK-1", "MXL9900K1", "Public kiosk", "HP ProOne 440"),
    ("PUBLIC-KIOSK-2", "MXL9900K2", "Public kiosk", "HP ProOne 440"),
    ("SCANNER-PC", "MXL9900S1", "Document scanning", "HP ProDesk 400"),
    ("IT-ADMIN-01", "PF3KX301", "IT administration", "Lenovo ThinkPad T14"),
    ("RECORDS-ARCH-01", "5CG3201E01", "Records archive", "HP EliteDesk 800 G6"),
]

# EDR export (CrowdStrike Falcon style headers). Missing: SCANNER-PC, PUBLIC-KIOSK-2, RECORDS-ARCH-01.
EDR_OFFLINE = {"JUDGE-CHAMB-02", "COURTRM-B-BENCH"}
EDR_MISSING = {"SCANNER-PC", "PUBLIC-KIOSK-2", "RECORDS-ARCH-01"}


def edr() -> str:
    rows = ["Hostname,Agent ID,Sensor Version,Status,Last Seen,Serial Number,Platform"]
    for i, (h, s, _, _) in enumerate(FLEET):
        if h in EDR_MISSING:
            continue
        status, seen = ("Offline", "2026-09-28T10:14:00Z") if h in EDR_OFFLINE else ("Online", "2026-10-25T21:40:00Z")
        rows.append(f"{h},a1f0c0de{i:04d},7.18.19105,{status},{seen},{s},Windows")
    rows.append("COURTRM-A-BENCH,a1f0c0de0008,7.18.19105,Online,2026-10-25T21:40:00Z,PF3KX201,Windows")  # duplicate -> warning
    rows.append("TEMP-LAPTOP,a1f0c0de0099,7.18.19105,Online,last week,,Windows")  # bad date -> row rejected
    return "\n".join(rows) + "\n"


# RMM export, semicolon separated (as many RMM tools write it). Misses IT-ADMIN-01 and PUBLIC-KIOSK-1;
# includes VENDOR-LAPTOP, which is in no other source.
def rmm() -> str:
    rows = ["Device Name;Serial Number;OS Build;Last Patch Date;AV Status;Site;Operating System"]
    for h, s, _, _ in FLEET:
        if h in {"IT-ADMIN-01", "PUBLIC-KIOSK-1"}:
            continue
        av = "Disabled" if h in {"SCANNER-PC"} else "Protected"
        patched = "2026-06-14" if h in {"SCANNER-PC", "RECORDS-ARCH-01"} else "2026-10-15"
        build = "10.0.19045" if h in {"SCANNER-PC", "RECORDS-ARCH-01"} else "10.0.22631"
        rows.append(f"{h};{s};{build};{patched};{av};LAB-A1;Windows")
    rows.append("VENDOR-LAPTOP;R90ZZ123;10.0.22631;2026-10-02;Protected;LAB-A1;Windows")
    rows.append("PRINT-SRV;;10.0.17763;not patched;Protected;LAB-A1;Windows Server 2019")  # bad date -> row rejected
    return "\n".join(rows) + "\n"


def assets() -> str:
    rows = ["Asset Tag,Computer Name,Serial No,Location,Device Role,Make/Model,Operating System"]
    for i, (h, s, role, model) in enumerate(FLEET):
        rows.append(f"LCA-{1001 + i},{h},{s},LAB-A1,{role},{model},Windows 11")
    rows.append("LCA-1099,,,LAB-A1,Spare,HP EliteDesk 800 G6,")  # neither hostname nor serial -> rejected
    return "\n".join(rows) + "\n"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in (("lab-a-edr-falcon.csv", edr()), ("lab-a-rmm-inventory.csv", rmm()), ("lab-a-asset-register.csv", assets())):
        (OUT / name).write_text(text, encoding="utf-8", newline="")
        print(OUT / name)


if __name__ == "__main__":
    main()
