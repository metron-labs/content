import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
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

BACKFILL_HISTORY_MIN_DAYS = 0
BACKFILL_HISTORY_MAX_DAYS = 365
DEFAULT_BACKFILL_HISTORY_DAYS = 30
GET_ALERTS_FETCH_LIMIT = 200  # Set to None for production (unlimited alert fetch)


def parse_backfill_history(
    backfill_history: str | int | None,
    legacy_first_fetch: str | None = None,
) -> str:
    """Convert a backfill day count to an ISO 8601 UTC timestamp for the first fetch.

    Args:
        backfill_history: Days before today (0 = start of today UTC, max 365).
        legacy_first_fetch: Deprecated relative time string from older instances (e.g. "30 days").

    Returns:
        An ISO 8601 UTC timestamp string, e.g. "2026-01-01T00:00:00Z".
    """
    days: int | None = None
    if backfill_history is not None and str(backfill_history).strip() != "":
        try:
            days = int(backfill_history)
        except (TypeError, ValueError):
            days = None

    if days is None and legacy_first_fetch:
        parsed = arg_to_datetime(legacy_first_fetch, is_utc=True)
        if parsed:
            return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")  # type: ignore[union-attr]

    if days is None:
        days = DEFAULT_BACKFILL_HISTORY_DAYS

    days = max(BACKFILL_HISTORY_MIN_DAYS, min(BACKFILL_HISTORY_MAX_DAYS, days))
    now = datetime.now(UTC)
    start = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_backfill_history_days(backfill_history: str | int | None) -> None:
    """Validate that backfill_history is an integer between 0 and 365 inclusive.

    Args:
        backfill_history: Days before today (0 = start of today UTC, max 365).

    Raises:
        ValueError: If the value is not an integer or is outside the allowed range.
    """
    if backfill_history is None or str(backfill_history).strip() == "":
        return

    try:
        days = int(backfill_history)
    except (TypeError, ValueError):
        raise ValueError("backfill_history must be an integer between 0 and 365.")

    if days < BACKFILL_HISTORY_MIN_DAYS or days > BACKFILL_HISTORY_MAX_DAYS:
        raise ValueError("backfill_history must be between 0 and 365.")


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
            headers={"JWTSessionToken": session_jwt},
            json_data=json_data,
            resp_type="json",
            ok_codes=(200,),
        )

        errors = response.get("errors")
        if errors:
            raise DemistoException(f"GraphQL error: {errors}")

        return response

    def test_connection(self, backfill_history: str | int | None = None) -> dict:
        validate_backfill_history_days(backfill_history)

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
            headers={"JWTSessionToken": session_jwt},
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


def _highlight_values_in_text(text: str, values: set[str]) -> str:
    """Wrap occurrences of known asset/observable values in backticks."""
    if not text or not values:
        return text
    result = text
    for value in sorted(values, key=len, reverse=True):
        if not value or f"`{value}`" in result:
            continue
        result = result.replace(value, f"`{value}`")
    return result


def _format_incident_findings(
    findings: Any,
    assets: Any,
    observables: Any,
) -> Any:
    """Format incident findings as a numbered list with asset/observable highlights."""
    if findings is None or not isinstance(findings, list) or not findings:
        return findings

    highlight_values = set(_normalize_list_items(assets) + _normalize_list_items(observables))
    formatted_findings: list[str] = []
    for index, finding in enumerate(findings, start=1):
        if isinstance(finding, dict):
            text = json.dumps(finding)
        else:
            text = str(finding).strip()
        if not text:
            continue
        text = _highlight_values_in_text(text, highlight_values)
        formatted_findings.append(f"{index}. {text}")

    if not formatted_findings:
        return findings
    return "\n".join(formatted_findings)


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
    if "dataSources" in raw:
        raw["dataSources"] = _format_bullet_list(raw.get("dataSources"))

    assets = raw.get("assets")
    observables = raw.get("observables")

    if "assets" in raw:
        raw["assets"] = _format_bullet_list(assets)
    if "observables" in raw:
        raw["observables"] = _format_bullet_list(observables)
    if "incidentFindings" in raw:
        raw["incidentFindings"] = _format_incident_findings(raw.get("incidentFindings"), assets, observables)
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


def incident_to_xsoar_incident(incident: dict) -> dict:
    """Convert a Vega incident to an XSOAR incident.

    Args:
        incident: A single incident dict from the Vega API.

    Returns:
        An XSOAR incident dict.
    """

    severity = VEGA_SEVERITY_TO_XSOAR.get(incident.get("severity", "").upper(), IncidentSeverity.UNKNOWN)
    created_at = incident.get("createdAt", "")

    # Inject vegaEntityType so the classifier transformer can route correctly
    raw = dict(incident)
    raw["vegaEntityType"] = "Vega Incident"
    _apply_vega_entity_link(raw)
    _format_raw_entity_for_xsoar(raw)

    return {
        "name": f"{raw.get('name', 'Unknown')}",
        "occurred": created_at,
        "severity": severity,
        "type": "Vega Incident",
        "rawJSON": json.dumps(raw),
    }


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

    max_time = max(entity.get(time_key, "") for entity in fetched_entities)
    ids_at_max: list[str] = []
    for entity in fetched_entities:
        if entity.get(time_key) == max_time:
            entity_id = entity.get(id_key)
            if entity_id:
                ids_at_max.append(str(entity_id))

    if max_time > previous_last_fetch:
        return max_time, ids_at_max
    if max_time == previous_last_fetch:
        return max_time, list(set(previous_last_ids + ids_at_max))

    # Edge case: API returned entities older than last_fetch (inclusive from filter).
    return previous_last_fetch, list(set(previous_last_ids + ids_at_max))


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

    Returns:
        A tuple of (next_run, xsoar_incidents).
    """
    xsoar_incidents: list[dict] = []
    next_run: dict = dict(last_run)

    alerts_last_fetch = last_run.get("alerts_last_fetch") or first_fetch_time
    incidents_last_fetch = last_run.get("incidents_last_fetch") or first_fetch_time
    alerts_last_ids: list[str] = last_run.get("alerts_last_ids", [])
    incidents_last_ids: list[str] = last_run.get("incidents_last_ids", [])

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
            demisto.debug(f"Fetched {len(alerts)} alerts from Vega.")

            for alert in alerts:
                alert_id = alert.get("id", "")
                if alert_id in alerts_last_ids:
                    continue
                xsoar_incidents.append(alert_to_incident(alert, integration_url=integration_url))

            next_run["alerts_last_fetch"], next_run["alerts_last_ids"] = _update_fetch_state(
                alerts, alerts_last_fetch, alerts_last_ids
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
            demisto.debug(f"Fetched {len(incidents)} incidents from Vega.")

            for incident in incidents:
                incident_id = incident.get("id", "")
                if incident_id in incidents_last_ids:
                    continue
                xsoar_incidents.append(incident_to_xsoar_incident(incident))

            next_run["incidents_last_fetch"], next_run["incidents_last_ids"] = _update_fetch_state(
                incidents, incidents_last_fetch, incidents_last_ids
            )

        except Exception as e:
            demisto.debug(f"Error fetching Vega incidents: {e}")
            raise

    demisto.debug(f"Total XSOAR incidents to ingest: {len(xsoar_incidents)}")
    return next_run, xsoar_incidents


def test_module(client: Client, backfill_history: str | int | None = None):
    try:
        client.test_connection(backfill_history)
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

        first_fetch_time = parse_backfill_history(
            params.get("backfill_history"),
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
            result = test_module(client, params.get("backfill_history"))
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
