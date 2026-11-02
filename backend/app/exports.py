"""Exports: the same rows as the screen, as CSV or Excel. Every export is audited with its hash."""

import csv
import io
import json
from datetime import date, datetime
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Font
from openpyxl.utils import get_column_letter

FORMATS = {
    "csv": "text/csv; charset=utf-8",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


def _cell(v: Any) -> Any:
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M UTC") if v.tzinfo else v.strftime("%Y-%m-%d %H:%M")
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, default=str)
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@"):
        return "'" + v  # no formula injection when the file is opened in Excel
    return v


def render(fmt: str, sheets: dict[str, tuple[list[str], list[list[Any]]]], title: str = "") -> bytes:
    """sheets: name -> (headers, rows). CSV carries the first sheet only."""
    if fmt == "csv":
        headers, rows = next(iter(sheets.values()))
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(headers)
        w.writerows([[_cell(v) for v in r] for r in rows])
        return ("﻿" + buf.getvalue()).encode("utf-8")  # BOM so Excel reads UTF-8
    wb = Workbook()
    wb.remove(wb.worksheets[0])
    for name, (headers, rows) in sheets.items():
        ws = wb.create_sheet(name[:31])
        ws.append(headers)
        for c in ws[1]:
            c.font = Font(bold=True)
        for r in rows:
            ws.append([_cell(v) for v in r])
        ws.freeze_panes = "A2"
        for i, h in enumerate(headers, start=1):
            width = max([len(str(h))] + [len(str(_cell(r[i - 1]))) for r in rows[:500]])
            ws.column_dimensions[get_column_letter(i)].width = min(max(width + 2, 10), 70)
    if title:
        wb.properties.title = title
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()
