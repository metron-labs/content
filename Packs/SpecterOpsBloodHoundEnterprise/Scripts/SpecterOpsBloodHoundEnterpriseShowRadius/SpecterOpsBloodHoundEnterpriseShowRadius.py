import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

FIELD = "bloodhoundradiustable"
EMPTY_BOX = (
    "box-sizing:border-box;width:100%;margin:0;padding:32px 16px;text-align:center;"
    "font-family:Roboto,'Segoe UI','Helvetica Neue',Arial,sans-serif;color:inherit;"
    "border:1px solid rgba(128,128,128,0.35);border-radius:4px"
)
EMPTY_TITLE = "margin:0 0 4px;font-size:14px;font-weight:600;line-height:20px"
EMPTY_BODY = "margin:0;font-size:13px;line-height:1.5;opacity:0.8"


def _indicator() -> dict:
    args = demisto.args() or {}
    indicator = args.get("indicator")
    if not indicator:
        indicator = (demisto.callingContext.get("args") or {}).get("indicator")
    if isinstance(indicator, str) and indicator:
        try:
            indicator = json.loads(indicator)
        except json.JSONDecodeError:
            indicator = {"value": indicator}
    return indicator if isinstance(indicator, dict) else {}


def _field(indicator: dict) -> str:
    custom = indicator.get("CustomFields") or indicator.get("customFields") or {}
    if isinstance(custom, str):
        try:
            custom = json.loads(custom)
        except json.JSONDecodeError:
            custom = {}
    if isinstance(custom, dict) and custom.get(FIELD):
        return str(custom.get(FIELD)).strip()
    return str(indicator.get(FIELD) or "").strip()


def _with_stored_field(indicator: dict) -> dict:
    if _field(indicator):
        return indicator
    value = str(indicator.get("value") or "").strip()
    if not value:
        return indicator
    result = demisto.executeCommand("getIndicator", {"value": value})
    if not result or isError(result[0]):
        return indicator
    contents = result[0].get("Contents")
    if isinstance(contents, list):
        contents = next((item for item in contents if isinstance(item, dict)), None)
    return contents if isinstance(contents, dict) else indicator


def main():
    try:
        html = _field(_with_stored_field(_indicator()))
        if not html:
            html = (
                f'<div style="{EMPTY_BOX}">'
                f'<div style="{EMPTY_TITLE}">Radius targets are not loaded</div>'
                f'<div style="{EMPTY_BODY}">Click the Pull BHE Radius button above to load outbound control targets.</div>'
                f"</div>"
            )
        return_results(
            {
                "ContentsFormat": formats["html"],
                "Type": entryTypes["note"],
                "Contents": html,
            }
        )
    except Exception as exc:
        return_error(f"Failed to display the BloodHound Enterprise radius section.\n{exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
