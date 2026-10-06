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
SOURCE_INSTANCE_FIELD = "sourceinstance"
BHE_INTEGRATION_NAME = "SpecterOpsBloodHoundEnterprise"
KEY_LINE = (
    "T0=Tier Zero | AP=Direct Attack Paths | OOC=Outbound Object Control | "
    "AR=Admin Rights | RDP=RDP Rights | DCOM=DCOM Rights | PS=PowerShell Remoting | "
    "SQL=SQL Admin | CD=Constrained Delegation | Sess=Sessions"
)
COLUMNS = ["T0", "AP", "OOC", "AR", "RDP", "DCOM", "PS", "SQL", "CD", "Sess"]
GRAY = ("#9ca3af", "#111111")
PURPLE = ("#7c3aed", "#ffffff")
YELLOW = ("#eab308", "#111111")
ORANGE = ("#f97316", "#111111")
RED = ("#dc2626", "#ffffff")
FONT_WRAP = (
    "font-family:Roboto,'Segoe UI','Helvetica Neue',Arial,sans-serif;color:inherit;font-size:13px;line-height:1.5;width:100%"
)
TITLE = "margin:0 0 4px;font-size:15px;font-weight:600"
MUTED = "margin:0 0 8px;font-size:12px;opacity:0.8"
TABLE = "width:100%;border-collapse:separate;border-spacing:0;table-layout:fixed"
FRAME_BORDER = (
    "box-sizing:border-box;width:100%;border:1px solid rgba(128,128,128,0.35);"
    "border-radius:4px;overflow:hidden"
)
GRID_COLGROUP = (
    '<colgroup><col style="width:28%">'
    + "".join('<col style="width:7.2%">' for _ in COLUMNS)
    + "</colgroup>"
)
TH = (
    "position:sticky;top:0;z-index:1;box-sizing:border-box;padding:8px 6px;text-align:center;"
    "font-size:12px;font-weight:600;line-height:16px;color:#f8fafc;background-color:#374151;"
    "border-bottom:1px solid #374151;box-shadow:0 1px 0 #374151"
)
TD = "padding:6px 4px;text-align:center;color:inherit;border-top:1px solid rgba(128,128,128,0.22)"
TD_DOMAIN = (
    "box-sizing:border-box;padding:6px 6px;text-align:left;font-weight:600;vertical-align:top;"
    "line-height:16px;color:inherit;word-break:break-word;overflow-wrap:break-word;"
    "border-top:1px solid rgba(128,128,128,0.22)"
)
# Explicit link styling: indicator HTML inherits table text color; inherit on <a> hides hyperlinks.
LINK = (
    "color:#4dabf7;text-decoration:underline;text-underline-offset:2px;"
    "font-weight:500;cursor:pointer"
)


def _indicator(args: dict) -> tuple[str, str, dict]:
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
    return value, indicator_type, indicator


def _field_from_indicator_record(record: dict) -> str:
    for key in ("fields", "CustomFields", "customFields"):
        container = record.get(key)
        if isinstance(container, dict):
            stored = container.get(SOURCE_INSTANCE_FIELD)
            if stored not in (None, ""):
                return str(stored).strip()
    stored = record.get(SOURCE_INSTANCE_FIELD)
    return str(stored or "").strip()


def _source_instance_from_indicator_payload(indicator: dict) -> str:
    direct = _field_from_indicator_record(indicator)
    if direct:
        return direct
    nested = indicator.get("indicator")
    if isinstance(nested, dict):
        return _field_from_indicator_record(nested)
    return ""


def _indicator_tim_search_query(value: str, indicator_type: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'value:"{escaped}" and type:{indicator_type}'


def _source_instance_from_search(value: str, indicator_type: str) -> str:
    try:
        data = demisto.searchIndicators(
            query=_indicator_tim_search_query(value, indicator_type),
            size=1,
        )
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    iocs = data.get("iocs") or data.get("iocObjects") or []
    if not iocs or not isinstance(iocs[0], dict):
        return ""
    return _field_from_indicator_record(iocs[0])


def _source_instance_from_get_indicator(value: str, indicator_type: str) -> str:
    result = demisto.executeCommand(
        "getIndicator",
        {"value": value, "type": indicator_type},
    )
    if not result or isError(result[0]):
        return ""
    contents = result[0].get("Contents")
    if isinstance(contents, list):
        contents = contents[0] if contents else {}
    if isinstance(contents, dict):
        return _field_from_indicator_record(contents)
    return ""


def _resolve_bhe_integration_instance(indicator: dict, value: str, indicator_type: str) -> str:
    instance = _source_instance_from_indicator_payload(indicator)
    if instance:
        return instance
    instance = _source_instance_from_search(value, indicator_type)
    if instance:
        return instance
    return _source_instance_from_get_indicator(value, indicator_type)


def _persist_source_instance(value: str, instance: str) -> None:
    if not value or not instance:
        return
    demisto.executeCommand("setIndicator", {"value": value, SOURCE_INSTANCE_FIELD: instance})


def _risk_table(rows_html: str, head_html: str, colgroup: str = "") -> str:
    """Risk section tables grow with row count; the layout section scrolls when needed."""
    return (
        f'<div style="{FRAME_BORDER}"><table style="{TABLE}">'
        f"{colgroup}<thead><tr>{head_html}</tr></thead><tbody>{rows_html}</tbody></table></div>"
    )


def _impact(value: str, indicator_type: str, using: str) -> dict:
    if not using:
        raise DemistoException(
            "Cannot determine which BloodHound Enterprise instance owns this indicator. "
            "Re-run fetch with Create indicators on the correct instance so Source Instance is set."
        )
    command_args = {
        "name": value,
        "indicator_type": indicator_type,
        "view": "risk",
        "using": using,
        "using-brand": BHE_INTEGRATION_NAME,
    }
    result = demisto.executeCommand("bloodhound-principal-impact-get", command_args)
    if not result or isError(result[0]):
        raise DemistoException(get_error(result[0]) if result else "BloodHound Enterprise did not return a result.")
    entry = result[0]
    context = (entry.get("EntryContext") or {}).get("SpecterOpsBloodHoundEnterprise.Impact")
    if isinstance(context, list):
        context = context[0] if context else None
    if isinstance(context, dict):
        return context
    contents = entry.get("Contents")
    if isinstance(contents, dict) and contents.get("PrincipalType"):
        return contents
    raise DemistoException("BloodHound Enterprise returned no principal impact.")


def _display_time(value) -> str:
    text = str(value or "").strip()
    if "T" not in text:
        return text
    date, clock = text.split("T", 1)
    return f"{date} {clock.rstrip('Z').split('.')[0]} UTC"


def _section_refreshed() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _colors(column: str, value) -> tuple[str, str]:
    if column == "T0":
        return PURPLE if value == "Y" else GRAY
    count = int(value or 0)
    if count <= 0:
        return GRAY
    if column == "AP":
        return RED
    if count < 1000:
        return YELLOW
    if count < 10000:
        return ORANGE
    return RED


def _badge(column: str, value, text=None) -> str:
    background, ink = _colors(column, value)
    shown = value if value not in (None, "") else 0
    text = escape(str(shown if text is None else text))
    return (
        f'<span style="display:inline-block;min-width:34px;padding:3px 8px;border-radius:4px;'
        f'text-align:center;font-weight:600;font-size:12px;line-height:16px;background:{background};color:{ink}">'
        f"{text}</span>"
    )


def _grid(rows: list) -> str:
    if not rows:
        return f'<p style="margin:8px 0">No domains with outbound rights or direct attack paths.</p>'
    head = f'<th style="{TH};text-align:left">Domain</th>' + "".join(
        f'<th style="{TH}">{escape(column)}</th>' for column in COLUMNS
    )
    body = []
    for row in rows:
        cells = f'<td style="{TD_DOMAIN}">{escape(str(row.get("Domain") or ""))}</td>'
        cells += "".join(f'<td style="{TD}">{_badge(column, row.get(column, 0))}</td>' for column in COLUMNS)
        body.append(f"<tr>{cells}</tr>")
    return _risk_table("".join(body), head, GRID_COLGROUP)


def _risk_html(value: str, impact: dict) -> str:
    principal_type = escape(str(impact.get("PrincipalType") or "User"))
    shown = escape(str(impact.get("Name") or value))
    tier = str(impact.get("TierZero") or "No")
    domains = impact.get("TierZeroDomains") or []
    domain_suffix = ""
    if tier == "Yes" and domains:
        domain_suffix = f" ({escape(', '.join(str(domain) for domain in domains))})"
    attack_count = int(impact.get("AttackPathCount") or 0)
    parts = [
        f'<div style="{TITLE}">BHE {principal_type}: {shown}</div>',
        f'<div style="{MUTED}">BloodHound last seen: {escape(_display_time(impact.get("LastUpdated")) or "Not available")}</div>',
        f'<div style="{MUTED}">Section refreshed: {escape(_section_refreshed())}</div>',
        f'<div style="{MUTED}">Key: {escape(KEY_LINE)}</div>',
    ]
    paths = impact.get("DirectAttackPaths") or []
    if attack_count and paths:
        path_rows_list = []
        for path in paths:
            domain_cell = escape(str(path.get("Domain") or ""))
            attack_label = str(path.get("AttackPath") or "")
            graph_url = str(path.get("GraphViewUrl") or "").strip()
            if graph_url:
                attack_cell = (
                    f'<a href="{escape(graph_url)}" target="_blank" rel="noopener noreferrer" '
                    f'style="{LINK}"><u>{escape(attack_label)}</u></a>'
                )
            else:
                attack_cell = escape(attack_label)
            count_cell = escape(str(int(path.get("Count") or 0)))
            path_rows_list.append(
                f'<tr><td style="{TD};text-align:left">{domain_cell}</td>'
                f'<td style="{TD};text-align:left">{attack_cell}</td>'
                f'<td style="{TD}">{count_cell}</td></tr>'
            )
        path_rows = "".join(path_rows_list)
        parts.append(f'<div style="margin:0 0 6px;font-weight:600">Direct attack paths</div>')
        path_head = (
            f'<th style="{TH};text-align:left">Domain</th>'
            f'<th style="{TH};text-align:left">Attack path</th>'
            f'<th style="{TH}">Findings</th>'
        )
        parts.append(_risk_table(path_rows, path_head))
        parts.append(f'<div style="height:12px"></div>')
    parts.append(
        f'<div style="margin:0 0 2px"><strong>AP:</strong> {_badge("AP", attack_count)} direct attack paths</div>'
    )
    parts.append(
        f'<div style="margin:0 0 12px"><strong>T0:</strong> {_badge("T0", "Y" if tier == "Yes" else "N", tier)}'
        f"{domain_suffix}</div>"
    )
    parts.append(_grid(impact.get("Rows") or []))
    if impact.get("Partial"):
        parts.append(
            f'<div style="{MUTED}">The result is partial. Paging stopped before every finding or relationship was collected.</div>'
        )
    return f'<div style="{FONT_WRAP}">{"".join(parts)}</div>'


def main():
    try:
        value, indicator_type, indicator = _indicator(demisto.args())
        using = _resolve_bhe_integration_instance(indicator, value, indicator_type)
        _persist_source_instance(value, using)
        impact = _impact(value, indicator_type, using)
        html = _risk_html(value, impact)
        saved = demisto.executeCommand("setIndicator", {"value": value, "bloodhoundriskdetails": html})
        if not saved or isError(saved[0]):
            raise DemistoException(get_error(saved[0]) if saved else "The indicator was not updated.")
        return_results(html)
    except Exception as exc:
        return_error(f"Update BHE Risk failed. The indicator fields were not changed.\n{exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
