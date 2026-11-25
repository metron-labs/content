import json
from datetime import datetime, timedelta, timezone
from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *

urllib3.disable_warnings()

VENDOR = "flare"
PRODUCT = "exposure"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
PAGE_SIZE = 10
MAX_PAGES = 50
DEFAULT_MAX_EVENTS = 50
MAX_EVENTS_CAP = 500
MAX_BACKFILL_DAYS = 180
DEFAULT_BACKFILL = "30 days"
DEFAULT_TENANT = "default"
SECRET_KEYS = {"password", "passwords"}
RETRY_STATUSES = [429, 500, 502, 503, 504]
ALERT_LIST_PAGES = 20
SEEN_UID_LIMIT = 2000
RISK_SEVERITY = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}
# Flare Events page groups. Each selection expands to the type values tenant search accepts.
CATEGORY_TYPES = {
    "Illicit Networks": ["illicit_networks"],
    "Open Web": ["open_web"],
    "Intelligence Objects": ["intelligence_object"],
    "Leaked Credentials": ["leak", "valid_credential", "invalid_credential", "mitigated_credential"],
    "Look-alike Domains": [
        "lookalike_discovery",
        "lookalike_title",
        "lookalike_ip_address",
        "lookalike_favicon",
        "lookalike_screenshot",
        "lookalike_dns",
        "lookalike_whois_rdap",
        "lookalike_ssl_certificate",
    ],
    "Emerging Source": ["experimental"],
}


class Client(BaseClient):
    """Flare API client. One token is generated per tenant for the life of the process."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.api_key = api_key
        self._tokens: dict[str, str] = {}

    def token_for(self, tenant_key: str) -> str:
        cached = self._tokens.get(tenant_key)
        if cached:
            return cached
        body = None
        if tenant_key != DEFAULT_TENANT:
            body = {"tenant_id": tenant_id(tenant_key)}
        response = self._request("POST", "/tokens/generate", json_data=body, headers={"Authorization": self.api_key})
        token = response.get("token") if isinstance(response, dict) else None
        if not token:
            raise DemistoException(f"Flare did not return a token for tenant {tenant_key}.")
        self._tokens[tenant_key] = str(token)
        return str(token)

    def search_events(
        self,
        tenant_key: str,
        from_cursor: str | None,
        matched_at_gte: str,
        severities: list[str],
        event_types: list[str],
    ) -> dict[str, Any]:
        filters: dict[str, Any] = {"matched_at": {"gte": matched_at_gte}}
        if severities:
            filters["severity"] = severities
        if event_types:
            filters["type"] = event_types
        body: dict[str, Any] = {"size": PAGE_SIZE, "sort": "matched_at", "order": "asc", "filters": filters}
        if from_cursor:
            body["from"] = from_cursor
        response = self._request(
            "POST",
            "/firework/v4/events/tenant/_search",
            json_data=body,
            headers={"Authorization": f"Bearer {self.token_for(tenant_key)}"},
        )
        return response if isinstance(response, dict) else {}

    def get_event(self, tenant_key: str, uid: str) -> dict[str, Any]:
        """GET /firework/v4/events/?uid= returns the full event, including the data block."""
        try:
            response = self._request(
                "GET",
                "/firework/v4/events/",
                params={"uid": uid},
                headers={"Authorization": f"Bearer {self.token_for(tenant_key)}"},
            )
        except DemistoException:
            demisto.debug(f"Flare full event lookup failed for event {uid}.")
            return {}
        return response if isinstance(response, dict) else {}

    def list_alerts(self, tenant_key: str, from_cursor: str | None) -> dict[str, Any]:
        """GET /firework/v4/alerts/ returns saved alerts. Each alert already carries its filters."""
        params = {"size": PAGE_SIZE}
        if from_cursor:
            params["from"] = from_cursor
        response = self._request(
            "GET",
            "/firework/v4/alerts/",
            params=params,
            headers={"Authorization": f"Bearer {self.token_for(tenant_key)}"},
        )
        return response if isinstance(response, dict) else {}

    def search_alert_events(
        self,
        tenant_key: str,
        alert: dict[str, Any],
        from_cursor: str | None,
        matched_at_gte: str,
    ) -> dict[str, Any]:
        """Read one alert's events from the tenant feed using that alert's categories, severities, and the backfill."""
        body: dict[str, Any] = {
            "size": PAGE_SIZE,
            "sort": "matched_at",
            "order": "asc",
            "filters": alert_search_filters(alert, matched_at_gte),
        }
        if from_cursor:
            body["from"] = from_cursor
        response = self._request(
            "POST",
            "/firework/v4/events/tenant/_search",
            json_data=body,
            headers={"Authorization": f"Bearer {self.token_for(tenant_key)}"},
        )
        return response if isinstance(response, dict) else {}

    def _request(
        self,
        method: str,
        url_suffix: str,
        json_data: dict | None = None,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> Any:
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            json_data=json_data,
            params=params,
            headers=headers,
            retries=4,
            status_list_to_retry=RETRY_STATUSES,
            backoff_factor=2,
            timeout=60,
        )


def strip_secrets(value: Any) -> Any:
    """Drop credential fields before an event is stored."""
    if isinstance(value, dict):
        return {key: strip_secrets(item) for key, item in value.items() if key.lower() not in SECRET_KEYS}
    if isinstance(value, list):
        return [strip_secrets(item) for item in value]
    return value


def string_list(value: Any) -> list[str]:
    if isinstance(value, str) and value:
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int)) and str(item)]
    return []


def first_or_blank(values: list[str]) -> str:
    return values[0] if values else ""


def split_ips(values: list[str]) -> tuple[str, str]:
    ipv4 = [value for value in values if ":" not in value]
    ipv6 = [value for value in values if ":" in value]
    return first_or_blank(ipv4), first_or_blank(ipv6)


def tenant_id(tenant_key: str) -> int:
    try:
        return int(tenant_key)
    except ValueError as error:
        raise DemistoException(f"Flare tenant id {tenant_key} must be a number.") from error


def parse_tenants(value: Any) -> list[str]:
    tenants = argToList(value)
    return tenants or [DEFAULT_TENANT]


def parse_choices(value: Any) -> list[str]:
    return [str(item).strip() for item in argToList(value) if str(item).strip()]


def category_types(selected: list[str]) -> list[str]:
    """Turn Flare category labels into the type values sent to tenant search."""
    types: list[str] = []
    for name in selected:
        for value in CATEGORY_TYPES.get(name, [name]):
            if value not in types:
                types.append(value)
    return types


def remember_uids(seen: list[str], new_uids: list[str]) -> list[str]:
    """Keep a bounded cache of event IDs already stored. XSIAM cannot be queried for duplicates."""
    merged = [uid for uid in seen if uid]
    known = set(merged)
    for uid in new_uids:
        if uid and uid not in known:
            merged.append(uid)
            known.add(uid)
    if len(merged) > SEEN_UID_LIMIT:
        return merged[-SEEN_UID_LIMIT:]
    return merged


def latest_matched_at(current: str, events: list[dict[str, Any]]) -> str:
    """Return the newest matched_at among the stored checkpoint and this cycle."""
    latest = current
    for event in events:
        matched_at = str(event.get("matched_at") or "")
        if matched_at > latest:
            latest = matched_at
    return latest


def filter_fingerprint(severities: list[str], event_types: list[str]) -> str:
    return json.dumps({"severity": sorted(severities), "type": sorted(event_types)})


def alert_severities(alert: dict[str, Any]) -> list[str]:
    """Map a Flare alert's numeric risks onto the event-search severity names."""
    risks = alert.get("risks") if isinstance(alert.get("risks"), list) else []
    severities: list[str] = []
    for risk in risks:
        try:
            severity = RISK_SEVERITY.get(int(risk))
        except (TypeError, ValueError):
            severity = None
        if severity and severity not in severities:
            severities.append(severity)
    return severities


def alert_types(alert: dict[str, Any]) -> list[str]:
    values = alert.get("search_types") if isinstance(alert.get("search_types"), list) else []
    return [str(item) for item in values if str(item).strip()]


def alert_is_disabled(alert: dict[str, Any]) -> bool:
    scope = alert.get("identifier_scope") if isinstance(alert.get("identifier_scope"), dict) else {}
    return bool(scope.get("is_disabled"))


def alert_search_filters(alert: dict[str, Any], matched_at_gte: str) -> dict[str, Any]:
    """Use the filters saved on the alert. Add only the backfill window."""
    filters: dict[str, Any] = {"matched_at": {"gte": matched_at_gte}}
    types = alert_types(alert)
    severities = alert_severities(alert)
    if types:
        filters["type"] = types
    if severities and len(severities) < len(RISK_SEVERITY):
        filters["severity"] = severities
    return filters


def alert_fingerprint(alert: dict[str, Any]) -> str:
    return json.dumps({"severity": alert_severities(alert), "type": sorted(alert_types(alert))})


def backfill_start(backfill: str) -> str:
    """Return the UTC start timestamp for the first fetch. Reject ranges over 180 days."""
    start, _end = parse_date_range(backfill or DEFAULT_BACKFILL, date_format=DATE_FORMAT)
    start_time = arg_to_datetime(start)
    if start_time is None:
        raise DemistoException(f"Could not parse the initial backfill value {backfill!r}.")
    oldest = datetime.now(timezone.utc) - timedelta(days=MAX_BACKFILL_DAYS)
    if start_time < oldest:
        raise DemistoException(f"Initial backfill cannot exceed {MAX_BACKFILL_DAYS} days.")
    return start


def event_limit(value: Any, default: int = DEFAULT_MAX_EVENTS) -> int:
    limit = arg_to_number(value, arg_name="limit")
    if limit is None:
        return default
    if limit < 1 or limit > MAX_EVENTS_CAP:
        raise DemistoException(f"Maximum events per fetch must be between 1 and {MAX_EVENTS_CAP}.")
    return limit


def event_data_block(full_event: dict[str, Any]) -> dict[str, Any]:
    """The v4 event response carries the payload under data. Passwords are removed."""
    data = full_event.get("data") if isinstance(full_event.get("data"), dict) else {}
    cleaned = strip_secrets(data)
    return cleaned if isinstance(cleaned, dict) else {}


def build_event(
    tenant_key: str,
    feed_item: dict[str, Any],
    full_event: dict[str, Any] | None = None,
    alert: dict[str, Any] | None = None,
    instance_tag: str = "",
) -> dict[str, Any]:
    """Flatten one feed record. The full-event data block is attached only when it was fetched."""
    metadata = feed_item.get("metadata") if isinstance(feed_item.get("metadata"), dict) else {}
    tenant_metadata = feed_item.get("tenant_metadata") if isinstance(feed_item.get("tenant_metadata"), dict) else {}
    severity_block = tenant_metadata.get("severity") if isinstance(tenant_metadata.get("severity"), dict) else {}
    identifiers = feed_item.get("identifiers") if isinstance(feed_item.get("identifiers"), list) else []
    full_event = full_event or {}
    full_metadata = full_event.get("metadata") if isinstance(full_event.get("metadata"), dict) else {}
    data = event_data_block(full_event)
    features = data.get("features") if isinstance(data.get("features"), dict) else {}

    identifier_ids = [
        str(item.get("id")) for item in identifiers if isinstance(item, dict) and item.get("id") is not None
    ]
    identifier_names = [str(item.get("name")) for item in identifiers if isinstance(item, dict) and item.get("name")]
    emails = string_list(features.get("emails"))
    usernames = string_list(features.get("usernames"))
    domains = string_list(features.get("domains"))
    ip_addresses = string_list(features.get("ip_addresses"))
    ipv4, ipv6 = split_ips(ip_addresses)
    event_id = str(metadata.get("uid") or full_metadata.get("uid") or "")
    identity_name = str(data.get("identity_name") or "")
    severity = str(severity_block.get("override") or metadata.get("severity") or full_metadata.get("severity") or "")
    event_type = str(metadata.get("type") or "")
    grouping_id = first_or_blank(identifier_ids) or event_id
    grouping_name = first_or_blank(identifier_names) or identity_name or event_id
    matched_at = str(metadata.get("matched_at") or full_metadata.get("matched_at") or "")

    return {
        "flare_event_id": event_id,
        "flare_tenant_id": "" if tenant_key == DEFAULT_TENANT else tenant_key,
        "matched_at": matched_at,
        "estimated_created_at": str(metadata.get("estimated_created_at") or ""),
        "event_type": event_type,
        "severity": severity.lower(),
        "flare_url": str(metadata.get("flare_url") or full_metadata.get("flare_url") or ""),
        "full_event_type": str(full_event.get("event_type") or ""),
        "source_url": str(data.get("url") or ""),
        "event_data": json.dumps(data) if data else "",
        "event_description": f"{event_type} {severity} for {grouping_name}".strip(),
        "identity_name": identity_name,
        "email": first_or_blank(emails),
        "username": first_or_blank(usernames),
        "domain": first_or_blank(domains),
        "ipv4": ipv4,
        "ipv6": ipv6,
        "grouping_id": grouping_id,
        "grouping_name": grouping_name,
        "flare_alert_id": "" if not alert else str(alert.get("id") or ""),
        "flare_alert_name": "" if not alert else str(alert.get("name") or "").strip(),
        "flare_instance_tag": instance_tag,
        "identifier_ids": identifier_ids,
        "identifier_names": identifier_names,
        "emails": emails,
        "usernames": usernames,
        "domains": domains,
        "ip_addresses": ip_addresses,
        "raw_feed": json.dumps(strip_secrets(feed_item)),
        "_time": matched_at or None,
    }


def feed_uid(item: dict[str, Any]) -> str:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    return str(metadata.get("uid") or "")


def advance_cursor(
    request_cursor: str | None,
    response_next: str | None,
    handled_uids: list[str],
    truncated: bool,
) -> dict[str, Any]:
    """Stay on the current page when it was not fully consumed or when Flare reports no further page."""
    if truncated or not response_next:
        return {"from": request_cursor, "page_uids": handled_uids}
    return {"from": response_next, "page_uids": []}


def resume_cursor(
    tenant_key: str,
    saved_state: dict[str, Any],
    backfill: str,
    fingerprint: str,
    watermark: str = "",
) -> tuple[str | None, set[str], str]:
    """Keep the saved page unless the filters changed. A new stream continues from the last stored event."""
    cursor = saved_state.get("from")
    handled = set(saved_state.get("page_uids") or [])
    matched_at_gte = str(saved_state.get("matched_at_gte") or "")
    filters_changed = bool(saved_state) and saved_state.get("fingerprint") != fingerprint
    if filters_changed:
        demisto.debug(f"Flare filters changed for {tenant_key}. Resuming from now.")
        return None, set(), datetime.now(timezone.utc).strftime(DATE_FORMAT)
    if not matched_at_gte:
        matched_at_gte = watermark or backfill_start(backfill)
    return cursor if isinstance(cursor, str) else None, handled, matched_at_gte


def collect_events(
    client: Client,
    tenant_key: str,
    saved_state: dict[str, Any],
    backfill: str,
    fingerprint: str,
    max_events: int,
    fetch_full_event: bool,
    search_page: Any,
    alert: dict[str, Any] | None = None,
    instance_tag: str = "",
    watermark: str = "",
    seen_uids: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Pull one feed until the cycle limit, the feed is caught up, or the page cap is reached."""
    already_seen = seen_uids or set()
    cursor, handled, matched_at_gte = resume_cursor(tenant_key, saved_state, backfill, fingerprint, watermark)
    collected: list[dict[str, Any]] = []
    pages = 0
    while len(collected) < max_events and pages < MAX_PAGES:
        pages += 1
        request_cursor = cursor
        page = search_page(request_cursor, matched_at_gte)
        items = page.get("items") if isinstance(page.get("items"), list) else []
        response_next = page.get("next") if isinstance(page.get("next"), str) else None
        fresh = []
        for item in items:
            uid = feed_uid(item) if isinstance(item, dict) else ""
            if uid and uid not in handled and uid not in already_seen:
                fresh.append(item)
        room = max_events - len(collected)
        chosen = fresh[:room]
        for item in chosen:
            uid = feed_uid(item)
            full_event = client.get_event(tenant_key, uid) if uid and fetch_full_event else {}
            collected.append(build_event(tenant_key, item, full_event, alert, instance_tag))
            if uid:
                handled.add(uid)
                already_seen.add(uid)
        truncated = len(chosen) < len(fresh)
        moved = advance_cursor(request_cursor, response_next, list(handled), truncated)
        cursor = moved["from"]
        handled = set(moved["page_uids"])
        if truncated or not response_next:
            break
    state = {
        "from": cursor,
        "page_uids": list(handled),
        "matched_at_gte": matched_at_gte,
        "fingerprint": fingerprint,
    }
    return collected, state


def fetch_tenant_events(
    client: Client,
    tenant_key: str,
    tenant_state: dict[str, Any],
    backfill: str,
    severities: list[str],
    event_types: list[str],
    max_events: int,
    fetch_full_event: bool = False,
    instance_tag: str = "",
    watermark: str = "",
    seen_uids: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Pull one tenant feed until the cycle limit, the feed is caught up, or the page cap is reached."""

    def search_page(from_cursor: str | None, matched_at_gte: str) -> dict[str, Any]:
        return client.search_events(tenant_key, from_cursor, matched_at_gte, severities, event_types)

    return collect_events(
        client,
        tenant_key,
        tenant_state,
        backfill,
        filter_fingerprint(severities, event_types),
        max_events,
        fetch_full_event,
        search_page,
        instance_tag=instance_tag,
        watermark=watermark,
        seen_uids=seen_uids,
    )


def list_alert_definitions(client: Client, tenant_key: str) -> list[dict[str, Any]]:
    """Page through saved Flare alerts. Stop when the next page is empty or repeats."""
    alerts: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    cursor = None
    seen_cursors: set[str] = set()
    for _page in range(ALERT_LIST_PAGES):
        page = client.list_alerts(tenant_key, cursor)
        items = page.get("items") if isinstance(page.get("items"), list) else []
        for item in items:
            if not isinstance(item, dict) or item.get("id") is None:
                continue
            alert_id = str(item.get("id"))
            if alert_id in seen_ids:
                continue
            seen_ids.add(alert_id)
            alerts.append(item)
        response_next = page.get("next") if isinstance(page.get("next"), str) else None
        if not items or not response_next or response_next in seen_cursors:
            break
        seen_cursors.add(response_next)
        cursor = response_next
    return alerts


def fetch_one_alert(
    client: Client,
    tenant_key: str,
    alert: dict[str, Any],
    saved_state: dict[str, Any],
    backfill: str,
    max_events: int,
    fetch_full_event: bool,
    instance_tag: str = "",
    watermark: str = "",
    seen_uids: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    def search_page(from_cursor: str | None, matched_at_gte: str) -> dict[str, Any]:
        return client.search_alert_events(tenant_key, alert, from_cursor, matched_at_gte)

    return collect_events(
        client,
        f"{tenant_key}:{alert.get('id')}",
        saved_state,
        backfill,
        alert_fingerprint(alert),
        max_events,
        fetch_full_event,
        search_page,
        alert,
        instance_tag,
        watermark,
        seen_uids,
    )


def fetch_saved_alerts(
    client: Client,
    last_run: dict[str, Any],
    params: dict[str, Any],
    max_events: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch each saved Flare alert. Instance severity and category are not applied."""
    fetch_full_event = argToBoolean(params.get("fetch_full_event") or False)
    backfill = str(params.get("first_fetch") or DEFAULT_BACKFILL)
    instance_tag = str(params.get("instance_tag") or "").strip()
    watermark = str(last_run.get("last_matched_at") or "")
    seen_uids = set(last_run.get("seen_uids") or [])
    stored = last_run.get("alerts") if isinstance(last_run.get("alerts"), dict) else {}
    events: list[dict[str, Any]] = []
    next_alerts: dict[str, Any] = {}
    for tenant_key in parse_tenants(params.get("tenants")):
        for alert in list_alert_definitions(client, tenant_key):
            if alert_is_disabled(alert):
                continue
            state_key = f"{tenant_key}:{alert.get('id')}"
            if len(events) >= max_events:
                next_alerts[state_key] = stored.get(state_key) or {}
                continue
            alert_events, alert_state = fetch_one_alert(
                client,
                tenant_key,
                alert,
                stored.get(state_key) or {},
                backfill,
                max_events - len(events),
                fetch_full_event,
                instance_tag,
                watermark,
                seen_uids,
            )
            events.extend(alert_events)
            next_alerts[state_key] = alert_state
    tenants = last_run.get("tenants") if isinstance(last_run.get("tenants"), dict) else {}
    return {"tenants": tenants, "alerts": next_alerts}, events


def fetch_events(
    client: Client,
    last_run: dict[str, Any],
    params: dict[str, Any],
    max_events: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if argToBoolean(params.get("fetch_alerts") or False):
        next_run, events = fetch_saved_alerts(client, last_run, params, max_events)
        return stamp_checkpoint(last_run, next_run, events), events
    tenants = parse_tenants(params.get("tenants"))
    severities = parse_choices(params.get("severity"))
    event_types = category_types(parse_choices(params.get("event_types")))
    fetch_full_event = argToBoolean(params.get("fetch_full_event") or False)
    backfill = str(params.get("first_fetch") or DEFAULT_BACKFILL)
    instance_tag = str(params.get("instance_tag") or "").strip()
    watermark = str(last_run.get("last_matched_at") or "")
    seen_uids = set(last_run.get("seen_uids") or [])
    stored = last_run.get("tenants") if isinstance(last_run.get("tenants"), dict) else {}
    events: list[dict[str, Any]] = []
    next_tenants: dict[str, Any] = {}
    for tenant_key in tenants:
        if len(events) >= max_events:
            next_tenants[tenant_key] = stored.get(tenant_key) or {}
            continue
        tenant_events, tenant_state = fetch_tenant_events(
            client,
            tenant_key,
            stored.get(tenant_key) or {},
            backfill,
            severities,
            event_types,
            max_events - len(events),
            fetch_full_event,
            instance_tag,
            watermark,
            seen_uids,
        )
        events.extend(tenant_events)
        next_tenants[tenant_key] = tenant_state
    alerts = last_run.get("alerts") if isinstance(last_run.get("alerts"), dict) else {}
    return stamp_checkpoint(last_run, {"tenants": next_tenants, "alerts": alerts}, events), events


ISSUE_SEVERITY = {
    "info": IncidentSeverity.INFO,
    "low": IncidentSeverity.LOW,
    "medium": IncidentSeverity.MEDIUM,
    "high": IncidentSeverity.HIGH,
    "critical": IncidentSeverity.CRITICAL,
}


def direct_promotion_enabled(params: dict[str, Any]) -> bool:
    return argToBoolean(params.get("enable_direct_alert_promotion") or False)


def events_to_incidents(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn each stored Flare event into one XSIAM issue. Correlation rules are not involved."""
    incidents: list[dict[str, Any]] = []
    for event in events:
        severity_name = str(event.get("severity") or "info").lower()
        instance_tag = str(event.get("flare_instance_tag") or "").strip()
        event_id = str(event.get("flare_event_id") or "")
        name = f"Flare Exposure - {severity_name.title()}"
        if instance_tag:
            name = f"{name}. Instance {instance_tag}"
        incidents.append(
            {
                "name": name,
                "occurred": str(event.get("matched_at") or ""),
                "severity": ISSUE_SEVERITY.get(severity_name, IncidentSeverity.UNKNOWN),
                "details": (
                    f"Direct alert promotion. Flare {severity_name} event {event_id} "
                    f"({event.get('event_type')}) matched identifier {event.get('grouping_name')}. "
                    f"Instance {instance_tag}."
                ),
                "rawJSON": json.dumps(event),
            }
        )
    return incidents


def stamp_checkpoint(
    last_run: dict[str, Any],
    next_run: dict[str, Any],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Save the newest matched time and the event IDs already stored."""
    stored = [str(event.get("flare_event_id") or "") for event in events]
    next_run["seen_uids"] = remember_uids(list(last_run.get("seen_uids") or []), stored)
    next_run["last_matched_at"] = latest_matched_at(str(last_run.get("last_matched_at") or ""), events)
    return next_run


def test_module(client: Client, params: dict[str, Any]) -> str:
    tenant_key = parse_tenants(params.get("tenants"))[0]
    backfill = backfill_start(str(params.get("first_fetch") or DEFAULT_BACKFILL))
    if argToBoolean(params.get("fetch_alerts") or False):
        alerts = list_alert_definitions(client, tenant_key)
        if alerts:
            client.search_alert_events(tenant_key, alerts[0], None, backfill)
        return "ok"
    client.search_events(
        tenant_key,
        None,
        backfill,
        parse_choices(params.get("severity")),
        category_types(parse_choices(params.get("event_types"))),
    )
    return "ok"


def get_events_command(
    client: Client,
    params: dict[str, Any],
    args: dict[str, Any],
) -> tuple[list[dict[str, Any]], CommandResults]:
    """On-demand fetch. Does not read or move the scheduled cursor."""
    command_params = params | {"first_fetch": args.get("from") or params.get("first_fetch")}
    _next_run, events = fetch_events(client, {}, command_params, event_limit(args.get("limit"), 10))
    readable = tableToMarkdown(
        "Flare exposure events",
        events,
        headers=[
            "flare_event_id",
            "flare_tenant_id",
            "flare_instance_tag",
            "event_type",
            "severity",
            "grouping_name",
            "matched_at",
        ],
        removeNull=True,
    )
    return events, CommandResults(readable_output=readable, raw_response=events)


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = str(params.get("api_key") or "").strip()
    if not api_key:
        return_error("Flare API key is required.")
    client = Client(
        base_url=params.get("url") or "https://api.flare.io",
        api_key=api_key,
        verify=not params.get("insecure"),
        proxy=bool(params.get("proxy")),
    )
    try:
        if command == "test-module":
            return_results(test_module(client, params))
        elif command == "flare-exposure-get-events":
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, params, args)
            return_results(results)
            if should_push:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            limit = event_limit(params.get("max_fetch"), DEFAULT_MAX_EVENTS)
            next_run, events = fetch_events(client, last_run, params, limit)
            if events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                if direct_promotion_enabled(params):
                    demisto.createIncidents(events_to_incidents(events))
            demisto.setLastRun(next_run)
        else:
            return_error(f"Command {command} is not implemented.")
    except Exception as error:
        return_error(f"Failed to execute {command}. Error: {error}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
