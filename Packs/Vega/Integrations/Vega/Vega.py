import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import re

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

MAX_FETCH = 200

# Fallback start date used only if no first_fetch param is configured.
DEFAULT_FIRST_FETCH = "30 days"


def parse_first_fetch(first_fetch: str | None) -> str:
    """Convert a relative time string (e.g. '30 days', '1 week') to an ISO 8601 UTC timestamp.

    Args:
        first_fetch: A relative time string from demisto.params(), e.g. "30 days" or "7 days".

    Returns:
        An ISO 8601 UTC timestamp string, e.g. "2026-01-01T00:00:00Z".
    """
    first_fetch = first_fetch or DEFAULT_FIRST_FETCH
    parsed = arg_to_datetime(first_fetch, is_utc=True)
    if not parsed:
        parsed = arg_to_datetime(DEFAULT_FIRST_FETCH, is_utc=True)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")  # type: ignore[union-attr]


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

    def test_connection(self) -> dict:
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
        limit: int = MAX_FETCH,
        offset: int = 0,
    ) -> dict:
        """Fetch alerts from the Vega API.

        Args:
            severities: Filter by alert severities.
            statuses: Filter by alert statuses.
            verdicts: Filter by alert verdicts.
            from_time: Fetch alerts created after this time (ISO 8601).
            limit: Maximum number of alerts to fetch.
            offset: Offset for pagination.

        Returns:
            The getAlerts response data.
        """
        variables: dict[str, Any] = {"limit": limit, "offset": offset}
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
        limit: int = MAX_FETCH,
        offset: int = 0,
    ) -> dict:
        """Fetch incidents from the Vega API.

        Args:
            severities: Filter by incident severities.
            statuses: Filter by incident statuses.
            verdicts: Filter by incident verdicts.
            from_time: Fetch incidents created after this time (ISO 8601).
            limit: Maximum number of incidents to fetch.
            offset: Offset for pagination.

        Returns:
            The getIncidents response data.
        """
        variables: dict[str, Any] = {"limit": limit, "offset": offset}
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


def alert_to_incident(alert: dict) -> dict:
    """Convert a Vega alert to an XSOAR incident.

    Args:
        alert: A single alert dict from the Vega API.

    Returns:
        An XSOAR incident dict.
    """
    severity = VEGA_SEVERITY_TO_XSOAR.get(alert.get("severity", "").upper(), IncidentSeverity.UNKNOWN)
    created_at = alert.get("createdAt", "")

    # Inject vegaEntityType so the classifier transformer can route correctly
    raw = dict(alert)
    raw["vegaEntityType"] = "Vega Alert"

    return {
        "name": f"Alert: {raw.get('name', 'Unknown')}",
        "occurred": created_at,
        "severity": severity,
        "type": "Vega Alert",
        "rawJSON": json.dumps(raw),
    }


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

    return {
        "name": f"Incident: {raw.get('name', 'Unknown')}",
        "occurred": created_at,
        "severity": severity,
        "type": "Vega Incident",
        "rawJSON": json.dumps(raw),
    }


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
    max_fetch: int = MAX_FETCH,
) -> tuple[dict, list[dict]]:
    """Fetch alerts and/or incidents from Vega and return them as XSOAR incidents.

    Args:
        client: The Vega API client.
        last_run: The last run dict from demisto.getLastRun().
        fetch_alerts: Whether to fetch alerts.
        fetch_incidents: Whether to fetch incidents.
        alert_severities: Filter alerts by severity.
        alert_statuses: Filter alerts by status.
        alert_verdicts: Filter alerts by verdict.
        incident_severities: Filter incidents by severity.
        incident_statuses: Filter incidents by status.
        incident_verdicts: Filter incidents by verdict.
        first_fetch_time: ISO 8601 timestamp to use as the start time on the first run.
        max_fetch: Maximum total incidents to return.

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
            alerts_response = client.get_alerts(
                severities=alert_severities,
                statuses=alert_statuses,
                verdicts=alert_verdicts,
                from_time=alerts_last_fetch,
                limit=max_fetch,
            )

            api_error = alerts_response.get("error")
            if api_error and api_error.get("message"):
                demisto.debug(f"Vega alerts API error: {api_error.get('message')}")

            alerts = alerts_response.get("alerts") or []
            demisto.debug(f"Fetched {len(alerts)} alerts from Vega.")

            latest_alert_time = alerts_last_fetch
            new_alert_ids: list[str] = []

            for alert in alerts:
                alert_id = alert.get("id", "")
                alert_created = alert.get("createdAt", "")

                # Deduplicate: skip alerts already seen in the last run
                if alert_id in alerts_last_ids:
                    continue

                xsoar_incidents.append(alert_to_incident(alert))

                # Track the latest timestamp
                if not latest_alert_time or alert_created > latest_alert_time:
                    latest_alert_time = alert_created
                    new_alert_ids = [alert_id]
                elif alert_created == latest_alert_time:
                    new_alert_ids.append(alert_id)

            next_run["alerts_last_fetch"] = latest_alert_time
            next_run["alerts_last_ids"] = new_alert_ids

        except Exception as e:
            demisto.debug(f"Error fetching Vega alerts: {e}")
            raise

    if fetch_incidents:
        demisto.debug("Fetching Vega incidents...")
        try:
            incidents_response = client.get_incidents(
                severities=incident_severities,
                statuses=incident_statuses,
                verdicts=incident_verdicts,
                from_time=incidents_last_fetch,
                limit=max_fetch,
            )

            api_error = incidents_response.get("error")
            if api_error and api_error.get("message"):
                demisto.debug(f"Vega incidents API error: {api_error.get('message')}")

            incidents = incidents_response.get("incidents") or []
            demisto.debug(f"Fetched {len(incidents)} incidents from Vega.")

            latest_incident_time = incidents_last_fetch
            new_incident_ids: list[str] = []

            for incident in incidents:
                incident_id = incident.get("id", "")
                incident_created = incident.get("createdAt", "")

                # Deduplicate: skip incidents already seen in the last run
                if incident_id in incidents_last_ids:
                    continue

                xsoar_incidents.append(incident_to_xsoar_incident(incident))

                # Track the latest timestamp
                if not latest_incident_time or incident_created > latest_incident_time:
                    latest_incident_time = incident_created
                    new_incident_ids = [incident_id]
                elif incident_created == latest_incident_time:
                    new_incident_ids.append(incident_id)

            next_run["incidents_last_fetch"] = latest_incident_time
            next_run["incidents_last_ids"] = new_incident_ids

        except Exception as e:
            demisto.debug(f"Error fetching Vega incidents: {e}")
            raise

    demisto.debug(f"Total XSOAR incidents to ingest: {len(xsoar_incidents)}")
    return next_run, xsoar_incidents


def test_module(client: Client):
    try:
        client.test_connection()
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

        # Parse first_fetch param (default: "30 days")
        first_fetch_time = parse_first_fetch(params.get("first_fetch"))

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            access_key=access_key,
            access_key_id=access_key_id,
        )

        if command == "test-module":
            result = test_module(client)
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
                max_fetch=MAX_FETCH,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(xsoar_incidents)

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
