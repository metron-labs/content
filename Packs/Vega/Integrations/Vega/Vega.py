import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import html as html_module
import re
from collections.abc import Callable
from datetime import datetime, timedelta, UTC

# requests.packages.urllib3.disable_warnings() # pylint: disable=no-member

VEGA_SEVERITY_TO_XSOAR = {
    "LOW": IncidentSeverity.LOW,
    "MEDIUM": IncidentSeverity.MEDIUM,
    "HIGH": IncidentSeverity.HIGH,
    "CRITICAL": IncidentSeverity.CRITICAL,
}

GET_ALERTS_QUERY = (
    "query GetAlerts($alertNames: [String!], $alertIds: [ID!], $alertSeverities: [AlertSeverity!], "
    "$statuses: [AlertStatus!], $detectionIds: [ID!], $dataSourceNames: [String!], "
    "$alertVerdicts: [AlertVerdict!], $from: Time, $to: Time, $originType: AlertOriginType, "
    "$limit: Int, $offset: Int) { "
    " getAlerts(alertNames: $alertNames, alertIds: $alertIds, alertSeverities: $alertSeverities, "
    "statuses: $statuses, detectionIds: $detectionIds, dataSourceNames: $dataSourceNames, "
    "alertVerdicts: $alertVerdicts, from: $from, to: $to, originType: $originType, "
    "limit: $limit, offset: $offset) { "
    "  alerts { id detectionId name severity status "
    "   assignee { userId displayName email } "
    "   dataSources createdAt "
    "   mitre { mitreTactics mitreTechniques } "
    "   relatedIncidents { incidentId name } "
    "   detectionSource detectionDescription detectionQuery eventCount isTestMode verdict verdictReasoning } "
    "  total limit offset "
    "  error { code message } } }"
)

GET_INCIDENTS_QUERY = (
    "query GetIncidents($incidentNames: [String!], $incidentIds: [ID!], $severities: [IncidentSeverity!], "
    "$statuses: [IncidentStatusPublic!], $verdicts: [IncidentVerdictPublic!], "
    "$from: Time, $to: Time, $limit: Int, $offset: Int) { "
    " getIncidents(incidentNames: $incidentNames, incidentIds: $incidentIds, severities: $severities, "
    "statuses: $statuses, verdicts: $verdicts, from: $from, to: $to, "
    "limit: $limit, offset: $offset) { "
    "  incidents { id name createdBy createdAt lastUpdated severity status dataSources verdict verdictReasoning "
    "   assignee { userId displayName email } "
    "   comments { text addedBy addedAt } "
    "   incidentSummary incidentFindings assets observables alertsCount "
    "   alerts { alertId name createdAt } link } "
    "  total limit offset "
    "  error { code message } } }"
)

GET_INCIDENT_DETAILS_QUERY = (
    "query getIncidentsDetails($id: UUID!) { "
    " incident(id: $id) { "
    "  ...IncidentDetailFields "
    "  timelineEvents { ...IncidentTimelineEventFields } "
    " } "
    "} "
    "fragment UserIdentityFields on User { id email name } "
    "fragment DataSourceListFields on DataSource { id vendor displayName } "
    "fragment IncidentBaseFields on Incident { "
    " id incidentId name description status createdAt "
    " createdBy { ...UserIdentityFields } lastUpdate firstSeen "
    " assignee { ...UserIdentityFields } severity alertCount alertIds "
    " dataSources { ...DataSourceListFields } state verdict "
    "} "
    "fragment FeedbackFields on Feedback { id liked comment } "
    "fragment EntityFields on Entity { id type category value reputationData } "
    "fragment RecommendedActionSummaryFields on RecommendedAction { "
    " id actionName actionDescription actionPriority "
    "} "
    "fragment RecommendedActionFields on RecommendedAction { "
    " ...RecommendedActionSummaryFields feedback { ...FeedbackFields } "
    "} "
    "fragment IncidentDetailFields on Incident { "
    " ...IncidentBaseFields userVerdict keyFindings verdictReasoning "
    " investigationNotebookID userNotebookIDs "
    " keyFindingsFeedback { ...FeedbackFields } entities { ...EntityFields } "
    " recommendedActions { ...RecommendedActionFields } connectorTypes "
    "} "
    "fragment IncidentTimelineEventFields on IncidentTimelineEvent { "
    " id timestamp summary entities { ...EntityFields } dataSourceIds "
    " dataSources { ...DataSourceListFields } "
    " alert { id displayName severity } "
    "}"
)

VEGA_TIMELINE_ALERT_SEVERITY_LABELS: dict[int, str] = {
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
}

BACKFILL_DAYS_MIN = 0
BACKFILL_DAYS_MAX = 365
DEFAULT_BACKFILL_DAYS = 30
GET_ALERTS_FETCH_LIMIT = None  # Set to None for production (unlimited alert fetch)


def _parse_backfill_days(backfill_days: str | int | float | None) -> int | None:
    """Parse a backfill day count from integration params."""
    if backfill_days is None or str(backfill_days).strip() == "":
        return None
    try:
        return int(float(str(backfill_days).strip()))
    except (TypeError, ValueError):
        return None


def _normalize_to_midnight_utc(value: datetime) -> datetime:
    """Return the same calendar date at 00:00:00 UTC."""
    return value.replace(hour=0, minute=0, second=0, microsecond=0)


def parse_backfill_days(
    backfill_days: str | int | None,
    legacy_first_fetch: str | None = None,
) -> str:
    """Convert a backfill day count to an ISO 8601 UTC timestamp for the first fetch.

    Args:
        backfill_days: Days before today (0 = start of today UTC, max 365).
        legacy_first_fetch: Deprecated relative time string from older instances (e.g. "30 days").

    Returns:
        An ISO 8601 UTC timestamp string, e.g. "2026-01-01T00:00:00Z".
    """
    days = _parse_backfill_days(backfill_days)

    if days is None and legacy_first_fetch:
        parsed = arg_to_datetime(legacy_first_fetch, is_utc=True)
        if parsed:
            start = _normalize_to_midnight_utc(parsed)  # type: ignore[arg-type]
            return start.strftime("%Y-%m-%dT%H:%M:%SZ")

    if days is None:
        days = DEFAULT_BACKFILL_DAYS

    days = max(BACKFILL_DAYS_MIN, min(BACKFILL_DAYS_MAX, days))
    today_start = _normalize_to_midnight_utc(datetime.now(UTC))
    start = today_start - timedelta(days=days)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_backfill_days(backfill_days: str | int | None) -> None:
    """Validate that backfill_days is an integer between 0 and 365 inclusive.

    Args:
        backfill_days: Days before today (0 = start of today UTC, max 365).

    Raises:
        ValueError: If the value is not an integer or is outside the allowed range.
    """
    if backfill_days is None or str(backfill_days).strip() == "":
        return

    try:
        days = int(backfill_days)
    except (TypeError, ValueError):
        raise ValueError("backfill_days must be an integer between 0 and 365.")

    if days < BACKFILL_DAYS_MIN or days > BACKFILL_DAYS_MAX:
        raise ValueError("backfill_days must be between 0 and 365.")


class Client(BaseClient):
    """
    Client Class For Vega API Integration
    """

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        access_key: str,
        access_key_id: str = "",
    ):
        if base_url:
            base_url = base_url.rstrip("/")
            if not base_url.lower().endswith("/api/v1"):
                base_url = f"{base_url}/api/v1"
            base_url = f"{base_url}/"

        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.access_key = access_key
        self.access_key_id = access_key_id
        self._session_jwt: str | None = None

    def _authenticate(self) -> str:
        """Authenticate with the Vega API and return a session JWT token."""
        if self._session_jwt:
            return self._session_jwt

        login_res: dict = self._http_request(
            method="POST",
            url_suffix="login_machine",
            json_data={"access_key": self.access_key},
            resp_type="json",
            ok_codes=(200,),
        )

        session_jwt: str = login_res.get("session_jwt", "") if login_res else ""
        if not session_jwt:
            raise ValueError("Authentication failed: no session JWT received.")

        self._session_jwt = session_jwt
        return session_jwt

    def _auth_headers(self, session_jwt: str) -> dict[str, str]:
        """Build authentication headers for authenticated Vega API requests."""
        return {
            "JWTSessionToken": session_jwt,
            "X-Vega-Key-Id": self.access_key_id,
        }

    def _graphql_request(self, query: str, variables: dict | None = None) -> dict:
        """Execute a GraphQL query against the Vega API.

        Args:
            query: The GraphQL query string.
            variables: Optional variables for the query.

        Returns:
            The full JSON response from the API.
        """
        session_jwt = self._authenticate()
        json_data: dict[str, Any] = {"query": query}
        if variables:
            json_data["variables"] = variables

        response: dict = self._http_request(
            method="POST",
            url_suffix="query",
            headers=self._auth_headers(session_jwt),
            json_data=json_data,
            resp_type="json",
            ok_codes=(200,),
        )

        errors = response.get("errors")
        if errors:
            raise DemistoException(f"GraphQL error: {errors}")

        return response

    def test_connection(self, backfill_days: str | int | None = None) -> dict:
        validate_backfill_days(backfill_days)

        try:
            login_res: dict = self._http_request(
                method="POST",
                url_suffix="login_machine",
                json_data={"access_key": self.access_key},
                resp_type="json",
                ok_codes=(200,),
            )
        except Exception:
            raise ValueError("Incorrect Access Key. Please Check your Credentials.")

        session_jwt: str = login_res.get("session_jwt", "") if login_res else ""

        query_data: dict = {
            "query": (
                "query GetAccessKey($id: String!) {  getAccessKey(id: $id) {    id    name    description    "
                "status    createdBy    createdAt    expireTime    roles    bindings {      role      "
                "scopeId      scopeName    }    secretValue  }}"
            ),
            "variables": {"id": self.access_key_id},
        }

        query_res = self._http_request(
            method="POST",
            url_suffix="query",
            headers=self._auth_headers(session_jwt),
            json_data=query_data,
            resp_type="json",
            ok_codes=(200,),
        )

        errors = query_res.get("errors")
        data = query_res.get("data") or {}
        get_access_key = data.get("getAccessKey")

        if errors or get_access_key is None:
            raise ValueError("Incorrect Access Key ID. Please Check your Credentials")

        roles = get_access_key.get("roles") or []

        if not any(re.search(r"(?i)editor|admin", role) for role in roles):
            raise ValueError("You do not have required access to fetch incidents.")

        return query_res

    def get_alerts(
        self,
        severities: list[str] | None = None,
        statuses: list[str] | None = None,
        verdicts: list[str] | None = None,
        from_time: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict:
        """Fetch alerts from the Vega API.

        Args:
            severities: Filter by alert severities.
            statuses: Filter by alert statuses.
            verdicts: Filter by alert verdicts.
            from_time: Fetch alerts created after this time (ISO 8601).
            limit: Optional maximum number of alerts per request. When omitted, the API default is used.
            offset: Offset for pagination.

        Returns:
            The getAlerts response data.
        """
        variables: dict[str, Any] = {"offset": offset}
        if limit is not None:
            variables["limit"] = limit
        if severities:
            variables["alertSeverities"] = severities
        if statuses:
            variables["statuses"] = statuses
        if verdicts:
            variables["alertVerdicts"] = verdicts
        if from_time:
            variables["from"] = from_time

        response = self._graphql_request(GET_ALERTS_QUERY, variables)
        data = response.get("data", {})
        return data.get("getAlerts", {})

    def get_incidents(
        self,
        severities: list[str] | None = None,
        statuses: list[str] | None = None,
        verdicts: list[str] | None = None,
        from_time: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict:
        """Fetch incidents from the Vega API.

        Args:
            severities: Filter by incident severities.
            statuses: Filter by incident statuses.
            verdicts: Filter by incident verdicts.
            from_time: Fetch incidents created after this time (ISO 8601).
            limit: Optional maximum number of incidents per request. When omitted, the API default is used.
            offset: Offset for pagination.

        Returns:
            The getIncidents response data.
        """
        variables: dict[str, Any] = {"offset": offset}
        if limit is not None:
            variables["limit"] = limit
        if severities:
            variables["severities"] = severities
        if statuses:
            variables["statuses"] = statuses
        if verdicts:
            variables["verdicts"] = verdicts
        if from_time:
            variables["from"] = from_time

        response = self._graphql_request(GET_INCIDENTS_QUERY, variables)
        data = response.get("data", {})
        return data.get("getIncidents", {})

    def get_incident_details(self, incident_id: str) -> dict:
        """Fetch full incident details including timeline events.

        Args:
            incident_id: Vega incident UUID.

        Returns:
            The incident object from the GraphQL response, or an empty dict if not found.
        """
        response = self._graphql_request(GET_INCIDENT_DETAILS_QUERY, {"id": incident_id})
        data = response.get("data", {})
        incident = data.get("incident")
        return incident if isinstance(incident, dict) else {}


def _normalize_list_items(value: Any) -> list[str]:
    """Extract string items from a list or scalar field value."""
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        if item is None:
            continue
        if isinstance(item, dict):
            label = _mitre_item_label(item)
            if label:
                items.append(label)
            else:
                items.append(json.dumps(item))
        else:
            text = str(item).strip()
            if text:
                items.append(text)
    return items


def _format_bullet_list(value: Any) -> Any:
    """Format a list field as newline-separated bullet points."""
    if value is None or not isinstance(value, list) or not value:
        return value
    items = _normalize_list_items(value)
    if not items:
        return value
    return "\n".join(f"• {item}" for item in items)


VEGA_EMPTY_FIELD_DISPLAY = "N/A"


def _empty_to_na(value: Any) -> str:
    """Return a display placeholder when a Vega text field is missing or blank."""
    if value is None:
        return VEGA_EMPTY_FIELD_DISPLAY
    text = str(value).strip()
    return text if text else VEGA_EMPTY_FIELD_DISPLAY


def _format_vega_detection_query_for_display(value: Any) -> str:
    """Format a detection SQL query for markdown display, or N/A when empty."""
    query = _empty_to_na(value)
    if query == VEGA_EMPTY_FIELD_DISPLAY:
        return query
    return f"```sql\n{query}\n```"


def _mitre_item_label(item: dict) -> str:
    """Extract a display label from a MITRE tactic/technique object."""
    for key in ("name", "displayName", "techniqueName", "tacticName", "id", "techniqueId", "tacticId"):
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


MITRE_TACTIC_KEYS = ("mitreTactics", "mitre_tactics", "tactics")
MITRE_TECHNIQUE_KEYS = ("mitreTechniques", "mitre_techniques", "techniques")


def _get_first_mitre_value(mitre: dict, keys: tuple[str, ...]) -> Any:
    """Return the first present MITRE tactic/technique value from supported API key names."""
    for key in keys:
        if key in mitre and mitre.get(key) is not None:
            return mitre.get(key)
    return None


def _format_mitre_attack(mitre: Any) -> str | None:
    """Merge MITRE tactics and techniques into a newline-separated bullet list."""
    if not isinstance(mitre, dict):
        return None
    tactics = _get_first_mitre_value(mitre, MITRE_TACTIC_KEYS)
    techniques = _get_first_mitre_value(mitre, MITRE_TECHNIQUE_KEYS)
    items = _normalize_list_items(tactics) + _normalize_list_items(techniques)
    if not items:
        return None
    return "\n".join(f"• {item}" for item in items)


def _apply_vega_mitre_attack_format(raw: dict) -> None:
    """Populate vegaMitreAttack in raw JSON for visibility in the incident context."""
    mitre = raw.get("mitre")
    if isinstance(mitre, dict):
        mitre_payload: dict[str, Any] = mitre
    elif raw.get("mitreTactics") is not None or raw.get("mitreTechniques") is not None:
        mitre_payload = {
            "mitreTactics": raw.get("mitreTactics"),
            "mitreTechniques": raw.get("mitreTechniques"),
        }
    else:
        demisto.debug("Vega alert has no MITRE data to format.")
        return

    mitre_attack = _format_mitre_attack(mitre_payload)
    if mitre_attack:
        raw["vegaMitreAttack"] = mitre_attack
    else:
        demisto.debug(f"Vega MITRE payload could not be formatted: {mitre_payload!r}")


def _build_vega_alert_custom_fields(raw: dict) -> dict[str, str]:
    """Build CustomFields for Vega alerts (set directly on ingest, not via mapper)."""
    custom_fields: dict[str, str] = {}
    mitre_attack = raw.get("vegaMitreAttack")
    if mitre_attack:
        custom_fields["vegamitreattack"] = str(mitre_attack)
    created_at = raw.get("createdAt")
    if created_at:
        custom_fields["vegacreatedat"] = str(created_at)
    return custom_fields


def _timeline_alert_severity_label(severity: Any) -> str:
    """Map Vega numeric alert severity to a human-readable label."""
    if severity is None:
        return "N/A"
    try:
        return VEGA_TIMELINE_ALERT_SEVERITY_LABELS.get(int(severity), str(severity))
    except (TypeError, ValueError):
        return str(severity)


def _escape_html(text: str) -> str:
    """Escape text for safe inclusion in timeline HTML."""
    return html_module.escape(str(text))


def _format_timeline_display_timestamp(timestamp: Any) -> str:
    """Convert an ISO timestamp to the timeline display format (YYYY-MM-DD HH:MM:SS)."""
    text = str(timestamp or "").strip()
    if not text:
        return "—"
    text = text.replace("T", " ").replace("Z", "").strip()
    if "." in text:
        text = text.split(".", maxsplit=1)[0]
    return text


def _timeline_severity_bars_html(severity: Any) -> str:
    """Render alert severity as vertical bars (Vega UI style)."""
    try:
        level = max(1, min(4, int(severity)))
    except (TypeError, ValueError):
        level = 2
    bar_heights = (8, 11, 14, 16)
    bars: list[str] = []
    for index, height in enumerate(bar_heights, start=1):
        color = "#f97316" if index <= level else "#404040"
        bars.append(f"<div style='width:4px;height:{height}px;background:{color};border-radius:1px;'></div>")
    return f"<div style='display:flex;gap:2px;align-items:flex-end;'>{''.join(bars)}</div>"


_TIMELINE_PILL_STYLE = (
    "display:inline-block;padding:4px 10px;border-radius:999px;"
    "background:#2a2a2a;border:1px solid #404040;color:#f5f5f5;"
    "font-size:11px;line-height:1.4;white-space:normal;max-width:100%;"
)

_VEGA_DARK_UI_FONT = "-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif"

_KEY_FINDINGS_NUMBER_STYLE = (
    "display:flex;align-items:center;justify-content:center;flex-shrink:0;"
    "width:28px;height:28px;background:#141414;border:1px solid #333333;"
    "border-radius:8px;color:#9ca3af;font-size:12px;font-weight:600;"
)


def _timeline_data_source_label(source: dict) -> str:
    """Build the full display name for a timeline data source."""
    vendor = str(source.get("vendor", "")).strip()
    display_name = str(source.get("displayName", "")).strip()
    if vendor and display_name:
        return f"{vendor} · {display_name}"
    if display_name:
        return display_name
    if vendor:
        return vendor
    return ""


def _timeline_footer_html(event: dict) -> str:
    """Build footer badges (data sources, severity, entities) for a timeline event."""
    parts: list[str] = []

    data_sources = event.get("dataSources")
    if isinstance(data_sources, list):
        for source in data_sources:
            if not isinstance(source, dict):
                continue
            label = _timeline_data_source_label(source)
            if label:
                parts.append(f"<span style='{_TIMELINE_PILL_STYLE}'>{_escape_html(label)}</span>")

    alert = event.get("alert")
    if isinstance(alert, dict) and alert.get("displayName"):
        severity_label = _timeline_alert_severity_label(alert.get("severity"))
        parts.append(f"<span style='{_TIMELINE_PILL_STYLE}'>Severity: {_escape_html(severity_label)}</span>")

    entities = event.get("entities")
    if isinstance(entities, list):
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            entity_type = str(entity.get("type", "")).strip()
            category = str(entity.get("category", "")).strip()
            value = str(entity.get("value", "")).strip()
            if not value:
                continue
            meta_parts = [part for part in (entity_type, category) if part]
            pill_text = value
            if meta_parts:
                pill_text = f"{pill_text} ({', '.join(meta_parts)})"
            parts.append(f"<span style='{_TIMELINE_PILL_STYLE}'>{_escape_html(pill_text)}</span>")

    if not parts:
        return ""

    return f"<div style='display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:12px;'>" f"{''.join(parts)}</div>"


def _timeline_axis_html(is_last: bool) -> str:
    """Render the vertical timeline axis (line only; Vega API has no timeline event type field)."""
    line_bottom = "bottom:0;" if is_last else "bottom:-28px;"
    return (
        f"<div style='width:20px;flex-shrink:0;position:relative;align-self:stretch;min-height:20px;'>"
        f"<div style='position:absolute;left:50%;top:0;width:2px;{line_bottom}"
        f"background:#404040;transform:translateX(-50%);'></div></div>"
    )


def _timeline_event_row_html(event: dict, is_last: bool) -> str:
    """Render a single timeline row (timestamp, axis line, content)."""
    timestamp = _escape_html(_format_timeline_display_timestamp(event.get("timestamp")))
    summary = _escape_html(str(event.get("summary", "")).strip() or "No summary provided.")
    alert_data = event.get("alert")
    content_parts: list[str] = []
    if isinstance(alert_data, dict) and str(alert_data.get("displayName", "")).strip():
        alert_name = _escape_html(str(alert_data.get("displayName", "")).strip())
        severity_bars = _timeline_severity_bars_html(alert_data.get("severity"))
        content_parts.append(
            f"<div style='display:inline-flex;align-items:center;gap:10px;"
            f"background:#141414;border:1px solid #333333;border-radius:10px;"
            f"padding:10px 14px;margin-bottom:12px;max-width:100%;'>"
            f"{severity_bars}"
            f"<span style='color:#ffffff;font-size:14px;font-weight:600;line-height:1.4;'>"
            f"{alert_name}</span></div>"
        )

    content_parts.append(f"<p style='margin:0;color:#e5e5e5;font-size:13px;line-height:1.65;'>{summary}</p>")
    footer = _timeline_footer_html(event)
    if footer:
        content_parts.append(footer)

    return (
        f"<div style='display:flex;align-items:stretch;margin-bottom:28px;position:relative;'>"
        f"<div style='width:148px;flex-shrink:0;text-align:right;padding-right:14px;"
        f"padding-top:2px;color:#9ca3af;font-size:12px;font-family:monospace;'>{timestamp}</div>"
        f"{_timeline_axis_html(is_last)}"
        f"<div style='flex:1;min-width:0;padding-left:12px;padding-top:0;'>"
        f"{''.join(content_parts)}</div></div>"
    )


def _format_timeline_events_html(timeline_events: list[dict]) -> str:
    """Render Vega incident timeline as HTML (dark theme, three-column layout)."""
    if not timeline_events:
        return (
            "<div style='background:#000000;color:#ffffff;padding:16px;font-family:"
            "-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;'>"
            "<div style='font-size:15px;font-weight:600;margin-bottom:8px;'>Timeline</div>"
            "<p style='margin:0;color:#9ca3af;font-size:13px;'>"
            "No timeline events are available for this incident.</p></div>"
        )

    sorted_events = sorted(
        timeline_events,
        key=lambda event: str(event.get("timestamp", "")),
    )
    rows = [_timeline_event_row_html(event, is_last=index == len(sorted_events) - 1) for index, event in enumerate(sorted_events)]

    return (
        "<div style='background:#000000;color:#ffffff;padding:16px 16px 8px 16px;"
        "font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;'>"
        "<div style='font-size:15px;font-weight:600;margin-bottom:20px;color:#ffffff;'>"
        "Timeline</div>"
        f"<div style='position:relative;'>{''.join(rows)}</div></div>"
    )


def _build_vega_incident_custom_fields(raw: dict) -> dict[str, str]:
    """Build CustomFields for Vega incidents (set directly on ingest, not via mapper)."""
    custom_fields: dict[str, str] = {}
    timeline_html = raw.get("vegaTimelineEvents")
    if timeline_html:
        custom_fields["vegatimelineevents"] = str(timeline_html)
    findings_html = raw.get("vegaIncidentFindings")
    if findings_html:
        custom_fields["vegaincidentfindings"] = str(findings_html)
    return custom_fields


def _finding_text(finding: Any) -> str:
    """Normalize a single finding entry to display text."""
    if isinstance(finding, dict):
        return json.dumps(finding)
    return str(finding).strip()


def _normalize_findings_list(findings: Any) -> list[str]:
    """Extract non-empty finding strings from API data."""
    if findings is None or not isinstance(findings, list):
        return []
    texts: list[str] = []
    for finding in findings:
        text = _finding_text(finding)
        if text:
            texts.append(text)
    return texts


def _highlight_values_in_html(text: str, values: set[str]) -> str:
    """Wrap occurrences of known asset/observable values in timeline-style pills."""
    escaped = _escape_html(text)
    if not values:
        return escaped
    result = escaped
    for value in sorted(values, key=len, reverse=True):
        if not value:
            continue
        escaped_value = _escape_html(value)
        if escaped_value not in result:
            continue
        pill = f"<span style='{_TIMELINE_PILL_STYLE}'>{escaped_value}</span>"
        result = result.replace(escaped_value, pill)
    return result


def _key_finding_item_html(number: int, text: str, highlight_values: set[str], is_last: bool) -> str:
    """Render one numbered key finding row (screenshot-style layout, dark theme)."""
    body = _highlight_values_in_html(text, highlight_values)
    border = "" if is_last else "border-bottom:1px solid #333333;"
    return (
        f"<div style='display:flex;gap:14px;padding:16px 0;{border}align-items:flex-start;'>"
        f"<div style='{_KEY_FINDINGS_NUMBER_STYLE}'>{number}</div>"
        f"<p style='margin:0;flex:1;color:#e5e5e5;font-size:13px;line-height:1.65;'>{body}</p>"
        f"</div>"
    )


def _format_key_findings_html(findings: Any, assets: Any, observables: Any) -> str:
    """Render Vega key findings as HTML (black background, numbered list, entity pills)."""
    finding_texts = _normalize_findings_list(findings)
    highlight_values = set(_normalize_list_items(assets) + _normalize_list_items(observables))
    header = "<div style='font-size:15px;font-weight:600;margin-bottom:4px;color:#ffffff;'>" "Key findings</div>"
    container_style = f"background:#000000;color:#ffffff;padding:16px;" f"font-family:{_VEGA_DARK_UI_FONT};"

    if not finding_texts:
        return (
            f"<div style='{container_style}'>"
            f"{header}"
            f"<p style='margin:8px 0 0;color:#9ca3af;font-size:13px;'>"
            f"No key findings are available for this incident.</p></div>"
        )

    rows = [
        _key_finding_item_html(
            index,
            text,
            highlight_values,
            is_last=index == len(finding_texts),
        )
        for index, text in enumerate(finding_texts, start=1)
    ]
    return f"<div style='{container_style}'>{header}{''.join(rows)}</div>"


def _api_to_app_url(url: str) -> str:
    """Replace the api host subdomain with app in a Vega platform URL."""
    return url.strip().replace("://api.", "://app.")


def _platform_ui_base_url(integration_url: str) -> str:
    """Derive the Vega app UI base URL from the configured integration URL."""
    base = integration_url.rstrip("/")
    if base.lower().endswith("/api/v1"):
        base = base[: -len("/api/v1")]
    return _api_to_app_url(base)


def _apply_vega_entity_link(raw: dict, integration_url: str | None = None) -> None:
    """Normalize or build Vega platform UI links before XSOAR ingestion."""
    api_link = raw.get("link")
    if api_link:
        raw["link"] = _api_to_app_url(str(api_link))
        return

    entity_type = raw.get("vegaEntityType")
    entity_id = raw.get("id", "")
    if entity_type == "Vega Alert" and entity_id and integration_url:
        platform_base = _platform_ui_base_url(integration_url)
        raw["link"] = f"{platform_base.rstrip('/')}/incidents/alerts/investigation/{entity_id}"


def _format_raw_entity_for_xsoar(raw: dict) -> None:
    """Format display-oriented list fields in raw entity data before XSOAR ingestion."""
    if raw.get("vegaEntityType") == "Vega Alert":
        raw["detectionDescription"] = _empty_to_na(raw.get("detectionDescription"))
        raw["detectionQuery"] = _format_vega_detection_query_for_display(raw.get("detectionQuery"))

    if "dataSources" in raw:
        raw["dataSources"] = _format_bullet_list(raw.get("dataSources"))

    assets = raw.get("assets")
    observables = raw.get("observables")

    if "assets" in raw:
        raw["assets"] = _format_bullet_list(assets)
    if "observables" in raw:
        raw["observables"] = _format_bullet_list(observables)
    findings_source = raw.get("keyFindings") or raw.get("incidentFindings")
    if findings_source is not None:
        raw["vegaIncidentFindings"] = _format_key_findings_html(findings_source, assets, observables)
    _apply_vega_mitre_attack_format(raw)


def alert_to_incident(alert: dict, integration_url: str | None = None) -> dict:
    """Convert a Vega alert to an XSOAR incident.

    Args:
        alert: A single alert dict from the Vega API.
        integration_url: The Vega integration instance URL used to derive alert links.

    Returns:
        An XSOAR incident dict.
    """
    severity = VEGA_SEVERITY_TO_XSOAR.get(alert.get("severity", "").upper(), IncidentSeverity.UNKNOWN)
    created_at = alert.get("createdAt", "")

    # Inject vegaEntityType so the classifier transformer can route correctly
    raw = dict(alert)
    raw["vegaEntityType"] = "Vega Alert"
    _apply_vega_entity_link(raw, integration_url=integration_url)
    _format_raw_entity_for_xsoar(raw)

    xsoar_incident: dict[str, Any] = {
        "name": f"{raw.get('name', 'Unknown')}",
        "occurred": created_at,
        "severity": severity,
        "type": "Vega Alert",
        "rawJSON": json.dumps(raw),
    }
    custom_fields = _build_vega_alert_custom_fields(raw)
    if custom_fields:
        xsoar_incident["CustomFields"] = custom_fields
    return xsoar_incident


def incident_to_xsoar_incident(incident: dict, timeline_events: list[dict] | None = None) -> dict:
    """Convert a Vega incident to an XSOAR incident.

    Args:
        incident: A single incident dict from the Vega API.
        timeline_events: Optional timeline events from getIncidentsDetails.

    Returns:
        An XSOAR incident dict.
    """

    severity = VEGA_SEVERITY_TO_XSOAR.get(incident.get("severity", "").upper(), IncidentSeverity.UNKNOWN)
    created_at = incident.get("createdAt", "")

    # Inject vegaEntityType so the classifier transformer can route correctly
    raw = dict(incident)
    raw["vegaEntityType"] = "Vega Incident"
    if timeline_events is not None:
        raw["timelineEvents"] = timeline_events
        raw["vegaTimelineEvents"] = _format_timeline_events_html(timeline_events)
    _apply_vega_entity_link(raw)
    _format_raw_entity_for_xsoar(raw)

    xsoar_incident: dict[str, Any] = {
        "name": f"{raw.get('name', 'Unknown')}",
        "occurred": created_at,
        "severity": severity,
        "type": "Vega Incident",
        "rawJSON": json.dumps(raw),
    }
    custom_fields = _build_vega_incident_custom_fields(raw)
    if custom_fields:
        xsoar_incident["CustomFields"] = custom_fields
    return xsoar_incident


def _normalize_entity_id(entity: dict, id_key: str = "id") -> str:
    """Return a stable string ID for deduplication."""
    entity_id = entity.get(id_key)
    if entity_id is None or entity_id == "":
        return ""
    return str(entity_id)


def _parse_entity_created_at(created_at: Any) -> datetime | None:
    """Parse a Vega createdAt value to UTC datetime."""
    if not created_at:
        return None
    return arg_to_datetime(str(created_at), is_utc=True)  # type: ignore[return-value]


def _format_fetch_timestamp(created_at: datetime) -> str:
    """Format a datetime as the canonical ISO 8601 timestamp stored in last_run."""
    return created_at.strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_seen_ids(last_run: dict, seen_key: str, legacy_ids_key: str) -> set[str]:
    """Load cumulative seen IDs, including legacy boundary IDs from older last_run objects."""
    seen_ids: set[str] = set()
    for entity_id in last_run.get(seen_key, []):
        if entity_id is not None and entity_id != "":
            seen_ids.add(str(entity_id))
    for entity_id in last_run.get(legacy_ids_key, []):
        if entity_id is not None and entity_id != "":
            seen_ids.add(str(entity_id))
    return seen_ids


def _register_seen_entities(entities: list[dict], seen_ids: set[str], id_key: str = "id") -> None:
    """Add all fetched entity IDs to the cumulative seen set."""
    for entity in entities:
        entity_id = _normalize_entity_id(entity, id_key)
        if entity_id:
            seen_ids.add(entity_id)


def _fetch_paginated_entities(
    fetch_func: Callable[..., dict],
    entities_key: str,
    max_entities: int | None = None,
    **fetch_kwargs: Any,
) -> list[dict]:
    """Fetch entities from the Vega API with offset-based pagination.

    Paginates through all available pages until the API reports no more results,
    or until max_entities is reached when set.

    Args:
        fetch_func: Client method (get_alerts or get_incidents).
        entities_key: Response key holding the entity list ('alerts' or 'incidents').
        max_entities: Optional cap on total entities to retrieve across all pages.
        **fetch_kwargs: Keyword arguments forwarded to fetch_func (excluding limit/offset).

    Returns:
        Combined list of all entities returned by the API for the given filters.
    """
    entities: list[dict] = []
    offset = 0

    while True:
        request_kwargs = dict(fetch_kwargs)
        if max_entities is not None:
            remaining = max_entities - len(entities)
            if remaining <= 0:
                break
            request_kwargs["limit"] = remaining

        response = fetch_func(offset=offset, **request_kwargs)

        api_error = response.get("error")
        if api_error and api_error.get("message"):
            demisto.debug(f"Vega API error during pagination: {api_error.get('message')}")

        page = response.get(entities_key) or []
        if not page:
            break

        entities.extend(page)
        if max_entities is not None and len(entities) >= max_entities:
            entities = entities[:max_entities]
            break

        total = response.get("total")

        if total is not None and offset + len(page) >= total:
            break

        offset += len(page)

    demisto.debug(f"Paginated fetch for {entities_key}: retrieved {len(entities)} entities (offset up to {offset}).")
    return entities


def _update_fetch_state(
    fetched_entities: list[dict],
    previous_last_fetch: str,
    previous_last_ids: list[str],
    id_key: str = "id",
    time_key: str = "createdAt",
) -> tuple[str, list[str]]:
    """Calculate next-run last_fetch and last_ids from a paginated API response.

    Uses parsed UTC datetimes for comparisons so mixed timestamp formats (e.g. with/without
    milliseconds) do not break cursor advancement or boundary ID tracking.

    Args:
        fetched_entities: All entities returned across paginated API calls.
        previous_last_fetch: ISO 8601 timestamp from the previous run.
        previous_last_ids: Entity IDs seen at the previous last_fetch timestamp.
        id_key: Field name for the entity ID.
        time_key: Field name for the entity creation timestamp.

    Returns:
        Tuple of (new_last_fetch, new_last_ids).
    """
    if not fetched_entities:
        return previous_last_fetch, previous_last_ids

    parsed_entities: list[tuple[dict, datetime]] = []
    for entity in fetched_entities:
        parsed_time = _parse_entity_created_at(entity.get(time_key))
        if parsed_time is not None:
            parsed_entities.append((entity, parsed_time))

    if not parsed_entities:
        return previous_last_fetch, previous_last_ids

    max_dt = max(parsed_time for _, parsed_time in parsed_entities)
    max_time = _format_fetch_timestamp(max_dt)
    previous_dt = _parse_entity_created_at(previous_last_fetch)
    previous_last_ids_normalized = [str(entity_id) for entity_id in previous_last_ids if entity_id]

    ids_at_max: list[str] = []
    for entity, parsed_time in parsed_entities:
        if parsed_time == max_dt:
            entity_id = _normalize_entity_id(entity, id_key)
            if entity_id:
                ids_at_max.append(entity_id)

    if previous_dt is None or max_dt > previous_dt:
        return max_time, ids_at_max
    if max_dt == previous_dt:
        return max_time, list(set(previous_last_ids_normalized + ids_at_max))

    # Edge case: API returned entities older than last_fetch (inclusive from filter).
    return previous_last_fetch, list(set(previous_last_ids_normalized + ids_at_max))


def _should_use_stored_fetch_cursor(
    last_run: dict,
    last_fetch_key: str,
    backfill_days: str | int | None,
) -> bool:
    """Return True when an incremental fetch cursor from last_run should be reused."""
    stored_backfill = last_run.get("vega_backfill_days")
    if stored_backfill is None or str(stored_backfill) != str(backfill_days):
        return False
    stored_fetch = last_run.get(last_fetch_key)
    return stored_fetch not in (None, "")


def _resolve_fetch_from_time(
    last_run: dict,
    last_fetch_key: str,
    first_fetch_time: str,
    backfill_days: str | int | None,
) -> str:
    """Resolve the Vega API `from` timestamp for the current fetch run."""
    if _should_use_stored_fetch_cursor(last_run, last_fetch_key, backfill_days):
        stored = str(last_run[last_fetch_key])
        demisto.debug(f"Vega {last_fetch_key}: using stored cursor from_time={stored}")
        return stored

    demisto.debug(f"Vega {last_fetch_key}: using backfill from_time={first_fetch_time}")
    return first_fetch_time


def fetch_incidents_command(
    client: Client,
    last_run: dict,
    fetch_alerts: bool,
    fetch_incidents: bool,
    alert_severities: list[str] | None,
    alert_statuses: list[str] | None,
    alert_verdicts: list[str] | None,
    incident_severities: list[str] | None,
    incident_statuses: list[str] | None,
    incident_verdicts: list[str] | None,
    first_fetch_time: str,
    backfill_days: str | int | None,
    integration_url: str | None = None,
) -> tuple[dict, list[dict]]:
    """Fetch alerts and/or incidents from Vega and return them as XSOAR incidents.

    Args:
        client: The Vega API client.
        last_run: The last run dict from demisto.getLastRun().
        integration_url: The Vega integration instance URL used to derive alert links.
        fetch_alerts: Whether to fetch alerts.
        fetch_incidents: Whether to fetch incidents.
        alert_severities: Filter alerts by severity.
        alert_statuses: Filter alerts by status.
        alert_verdicts: Filter alerts by verdict.
        incident_severities: Filter incidents by severity.
        incident_statuses: Filter incidents by status.
        incident_verdicts: Filter incidents by verdict.
        first_fetch_time: ISO 8601 timestamp to use as the start time on the first run.
        backfill_days: Configured backfill day count used to anchor first-fetch cursors.

    Returns:
        A tuple of (next_run, xsoar_incidents).
    """
    xsoar_incidents: list[dict] = []
    next_run: dict = dict(last_run)
    next_run["vega_backfill_days"] = str(backfill_days)

    alerts_last_fetch = _resolve_fetch_from_time(last_run, "alerts_last_fetch", first_fetch_time, backfill_days)
    incidents_last_fetch = _resolve_fetch_from_time(last_run, "incidents_last_fetch", first_fetch_time, backfill_days)
    alerts_last_ids: list[str] = last_run.get("alerts_last_ids", [])
    incidents_last_ids: list[str] = last_run.get("incidents_last_ids", [])
    alerts_seen_ids = _load_seen_ids(last_run, "alerts_seen_ids", "alerts_last_ids")
    incidents_seen_ids = _load_seen_ids(last_run, "incidents_seen_ids", "incidents_last_ids")

    if fetch_alerts:
        demisto.debug("Fetching Vega alerts...")
        try:
            alerts = _fetch_paginated_entities(
                client.get_alerts,
                entities_key="alerts",
                max_entities=GET_ALERTS_FETCH_LIMIT,
                severities=alert_severities,
                statuses=alert_statuses,
                verdicts=alert_verdicts,
                from_time=alerts_last_fetch,
            )
            demisto.debug(f"Fetched {len(alerts)} alerts from Vega. Seen IDs before dedup: {len(alerts_seen_ids)}.")

            new_alerts = 0
            for alert in alerts:
                alert_id = _normalize_entity_id(alert)
                if not alert_id or alert_id in alerts_seen_ids:
                    continue
                xsoar_incidents.append(alert_to_incident(alert, integration_url=integration_url))
                new_alerts += 1

            _register_seen_entities(alerts, alerts_seen_ids)
            next_run["alerts_seen_ids"] = sorted(alerts_seen_ids)
            next_run["alerts_last_fetch"], next_run["alerts_last_ids"] = _update_fetch_state(
                alerts, alerts_last_fetch, alerts_last_ids
            )
            demisto.debug(
                f"Vega alerts ingest: {new_alerts} new, {len(alerts) - new_alerts} skipped as duplicates. "
                f"Total seen IDs: {len(alerts_seen_ids)}."
            )

        except Exception as e:
            demisto.debug(f"Error fetching Vega alerts: {e}")
            raise

    if fetch_incidents:
        demisto.debug("Fetching Vega incidents...")
        try:
            incidents = _fetch_paginated_entities(
                client.get_incidents,
                entities_key="incidents",
                severities=incident_severities,
                statuses=incident_statuses,
                verdicts=incident_verdicts,
                from_time=incidents_last_fetch,
            )
            demisto.debug(f"Fetched {len(incidents)} incidents from Vega. Seen IDs before dedup: {len(incidents_seen_ids)}.")

            new_incidents = 0
            for incident in incidents:
                incident_id = _normalize_entity_id(incident)
                if not incident_id or incident_id in incidents_seen_ids:
                    continue
                timeline_events: list[dict] = []
                if incident_id:
                    try:
                        details = client.get_incident_details(str(incident_id))
                        fetched_events = details.get("timelineEvents")
                        if isinstance(fetched_events, list):
                            timeline_events = [event for event in fetched_events if isinstance(event, dict)]
                        key_findings = details.get("keyFindings")
                        if isinstance(key_findings, list) and key_findings:
                            incident["keyFindings"] = key_findings
                    except Exception as details_error:
                        demisto.debug(f"Could not fetch incident details for Vega incident {incident_id}: {details_error}")
                xsoar_incidents.append(incident_to_xsoar_incident(incident, timeline_events=timeline_events))
                new_incidents += 1

            _register_seen_entities(incidents, incidents_seen_ids)
            next_run["incidents_seen_ids"] = sorted(incidents_seen_ids)
            next_run["incidents_last_fetch"], next_run["incidents_last_ids"] = _update_fetch_state(
                incidents, incidents_last_fetch, incidents_last_ids
            )
            demisto.debug(
                f"Vega incidents ingest: {new_incidents} new, {len(incidents) - new_incidents} skipped as duplicates. "
                f"Total seen IDs: {len(incidents_seen_ids)}."
            )

        except Exception as e:
            demisto.debug(f"Error fetching Vega incidents: {e}")
            raise

    demisto.debug(f"Total XSOAR incidents to ingest: {len(xsoar_incidents)}")
    return next_run, xsoar_incidents


def test_module(client: Client, backfill_days: str | int | None = None):
    try:
        client.test_connection(backfill_days)
        return "ok"
    except Exception as e:
        return str(e)


def main() -> None:
    params = demisto.params()
    command = demisto.command()

    access_key = params.get("access_key")
    access_key_id = params.get("access_key_id")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    base_url = params.get("url")

    demisto.debug(f"Command being called is {command}")

    try:
        vega_entities = argToList(
            params.get("vega_entities") if params.get("vega_entities") is not None else ["Alerts", "Incidents"]
        )
        fetch_alerts = "Alerts" in vega_entities
        fetch_incidents = "Incidents" in vega_entities
        if not fetch_alerts and not fetch_incidents:
            raise ValueError("At least one of 'Fetch Alerts' or 'Fetch Incidents' must be checked.")

        # Parse filter parameters
        alert_severities = argToList(params.get("alert_severities")) or None
        alert_statuses = argToList(params.get("alert_statuses")) or None
        alert_verdicts = argToList(params.get("alert_verdicts")) or None
        incident_severities = argToList(params.get("incident_severities")) or None
        incident_statuses = argToList(params.get("incident_statuses")) or None
        incident_verdicts = argToList(params.get("incident_verdicts")) or None

        backfill_days = params.get("backfill_days")
        first_fetch_time = parse_backfill_days(
            backfill_days,
            legacy_first_fetch=params.get("first_fetch"),
        )

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            access_key=access_key,
            access_key_id=access_key_id,
        )

        if command == "test-module":
            result = test_module(client, backfill_days)
            return_results(result)

        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            next_run, xsoar_incidents = fetch_incidents_command(
                client=client,
                last_run=last_run,
                fetch_alerts=fetch_alerts,
                fetch_incidents=fetch_incidents,
                alert_severities=alert_severities,
                alert_statuses=alert_statuses,
                alert_verdicts=alert_verdicts,
                incident_severities=incident_severities,
                incident_statuses=incident_statuses,
                incident_verdicts=incident_verdicts,
                first_fetch_time=first_fetch_time,
                backfill_days=backfill_days,
                integration_url=base_url,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(xsoar_incidents)

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
