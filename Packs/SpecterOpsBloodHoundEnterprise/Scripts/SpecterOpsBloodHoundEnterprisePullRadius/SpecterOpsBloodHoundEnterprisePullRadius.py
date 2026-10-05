import json
from datetime import datetime, timezone
from html import escape

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DISPLAY_TYPES = {
    "User": "User",
    "Computer": "Computer",
    "Group": "Group",
}
FONT_WRAP = (
    "font-family:Roboto,'Segoe UI','Helvetica Neue',Arial,sans-serif;color:inherit;font-size:13px;line-height:1.5;width:100%"
)
ROWS_SHOWN = 25
TITLE = "margin:0 0 6px;font-size:15px;font-weight:600"
SUB = "margin:0 0 2px;font-weight:600"
MUTED = "margin:0 0 6px;font-size:12px;opacity:0.8"
TABLE = "width:100%;border-collapse:separate;border-spacing:0;table-layout:fixed"
FRAME = (
    "box-sizing:border-box;width:100%;max-height:280px;overflow-x:hidden;overflow-y:auto;"
    "scrollbar-gutter:stable;border:1px solid rgba(128,128,128,0.35);border-radius:4px"
)
TH = (
    "position:sticky;top:0;z-index:1;box-sizing:border-box;padding:8px;text-align:left;"
    "font-size:12px;font-weight:600;line-height:16px;color:#f8fafc;background-color:#374151;"
    "border-bottom:1px solid #374151;box-shadow:0 1px 0 #374151"
)
TD = (
    "box-sizing:border-box;padding:6px 8px;text-align:left;vertical-align:top;font-size:12px;"
    "line-height:16px;color:inherit;word-break:break-word;border-top:1px solid rgba(128,128,128,0.22)"
)
def _indicator(args: dict) -> tuple[str, str]:
    indicator = args.get("indicator")
    if isinstance(indicator, str):
        indicator = json.loads(indicator)
    if not isinstance(indicator, dict):
        raise DemistoException("The indicator button did not receive an indicator.")
    value = str(indicator.get("value") or "").strip()
    raw_type = str(indicator.get("indicator_type") or "").strip()
    if raw_type.startswith("SpecterOps "):
        raw_type = raw_type[len("SpecterOps ") :]
    indicator_type = DISPLAY_TYPES.get(raw_type)
    if not value or not indicator_type:
        raise DemistoException("The indicator value or type is missing.")
    return value, indicator_type


def _impact(value: str, indicator_type: str) -> dict:
    result = demisto.executeCommand(
        "bloodhound-principal-impact-get",
        {"name": value, "indicator_type": indicator_type, "view": "radius"},
    )
    if not result or isError(result[0]):
        raise DemistoException(get_error(result[0]) if result else "BloodHound Enterprise did not return a result.")
    entry = result[0]
    context = (entry.get("EntryContext") or {}).get("SpecterOpsBloodHoundEnterprise.Impact")
    if isinstance(context, list):
        context = context[0] if context else None
    if isinstance(context, dict):
        return context
    contents = entry.get("Contents")
    if isinstance(contents, dict) and "Categories" in contents:
        return contents
    raise DemistoException("BloodHound Enterprise returned no radius targets.")


def _targets_table(targets: list) -> str:
    rows = []
    for target in targets:
        rows.append(
            "<tr>"
            f'<td style="{TD};width:54%">{escape(str(target.get("Name") or ""))}</td>'
            f'<td style="{TD};width:16%">{escape(str(target.get("Type") or ""))}</td>'
            f'<td style="{TD};width:30%">{escape(str(target.get("Domain") or ""))}</td>'
            "</tr>"
        )
    return (
        f'<div style="{FRAME}"><table style="{TABLE}">'
        '<colgroup><col style="width:54%"><col style="width:16%"><col style="width:30%"></colgroup>'
        "<thead><tr>"
        f'<th style="{TH};width:54%">Target</th>'
        f'<th style="{TH};width:16%">Type</th>'
        f'<th style="{TH};width:30%">Domain</th>'
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
    )


def _section_refreshed() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _radius_html(value: str, impact: dict) -> str:
    principal_type = str(impact.get("PrincipalType") or "User")
    parts = [
        f'<div style="{TITLE}">BHE RADIUS</div>',
        f'<div style="{SUB}">BHE {escape(principal_type)} Radius Targets</div>',
        f'<div style="{MUTED};margin:0">Section refreshed: {escape(_section_refreshed())}</div>',
        f'<div style="{MUTED};margin:0">Entity: {escape(str(impact.get("Name") or value))}</div>',
        f'<div style="{MUTED}">Entity Type: {escape(principal_type.lower())}</div>',
    ]
    categories = impact.get("Categories") or []
    if not categories:
        parts.append(f'<div style="margin-top:8px">No outbound control targets were returned.</div>')
    for category in categories:
        returned = int(category.get("Returned") or 0)
        targets = (category.get("Targets") or [])[:ROWS_SHOWN]
        shown = f" &middot; Showing {len(targets)} of {returned}" if returned > len(targets) else ""
        parts.append(
            f'<div style="{SUB};margin-top:14px">Control Category: {escape(str(category.get("ControlCategory") or ""))}</div>'
        )
        parts.append(f'<div style="{MUTED}">Returned: {returned} results{shown}</div>')
        parts.append(_targets_table(targets))
    if impact.get("Partial"):
        parts.append(
            f'<div style="{MUTED};margin-top:10px">The result is partial. Paging stopped before every target was collected.</div>'
        )
    return f'<div style="{FONT_WRAP}">{"".join(parts)}</div>'


def main():
    try:
        value, indicator_type = _indicator(demisto.args())
        impact = _impact(value, indicator_type)
        html = _radius_html(value, impact)
        saved = demisto.executeCommand("setIndicator", {"value": value, "bloodhoundradiustable": html})
        if not saved or isError(saved[0]):
            raise DemistoException(get_error(saved[0]) if saved else "The indicator was not updated.")
        return_results(html)
    except Exception as exc:
        return_error(f"Pull BHE Radius failed. The indicator fields were not changed.\n{exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
