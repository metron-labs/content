import json
import re
from datetime import datetime, timedelta, UTC
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
ACTION_BATCH = 10
WRITEBACK_LOOKBACK_MS = 60 * 60 * 1000
WRITEBACK_CASE_LIMIT = 2000
EVENT_ID_PATTERN = re.compile(r"event\s+(\S+?)\s+\(")
RESOLVED_CASE_STATUSES = [
    "resolved_threat_handled",
    "resolved_known_issue",
    "resolved_duplicate",
    "resolved_false_positive",
    "resolved_true_positive",
    "resolved_other",
    "resolved_auto",
    "resolved_security_testing",
]
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
        params: dict[str, Any] = {"size": PAGE_SIZE}
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

    def remediate_events(self, tenant_key: str, uids: list[str]) -> None:
        """POST /firework/v4/events/actions marks each event remediated. Flare accepts 10 targets per call."""
        token = self.token_for(tenant_key)
        for body in remediate_batches(uids):
            self._request(
                "POST",
                "/firework/v4/events/actions",
                json_data=body,
                headers={"Authorization": f"Bearer {token}"},
            )

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


def as_dict(value: Any) -> dict[str, Any]:
    """Return value when it is a dictionary."""
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    """Return value when it is a list."""
    return value if isinstance(value, list) else []


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
    """Keep a bounded list of case ids already sent back to Flare."""
    merged = [uid for uid in seen if uid]
    known = set(merged)
    for uid in new_uids:
        if uid and uid not in known:
            merged.append(uid)
            known.add(uid)
    if len(merged) > WRITEBACK_CASE_LIMIT:
        return merged[-WRITEBACK_CASE_LIMIT:]
    return merged


def integration_context() -> dict[str, Any]:
    context = demisto.getIntegrationContext() or {}
    return context if isinstance(context, dict) else {}


def remediate_batches(uids: list[str]) -> list[dict[str, Any]]:
    """Build Flare remediate calls. Each call carries at most 10 event ids."""
    unique: list[str] = []
    seen: set[str] = set()
    for uid in uids:
        event_id = str(uid).strip()
        if event_id and event_id not in seen:
            unique.append(event_id)
            seen.add(event_id)
    batches = []
    for start in range(0, len(unique), ACTION_BATCH):
        targets = [{"uid": event_id} for event_id in unique[start : start + ACTION_BATCH]]
        batches.append({"action": {"type": "remediate"}, "targets": targets})
    return batches


def event_ids_from_alerts(alerts: list[dict[str, Any]]) -> list[str]:
    """Read the Flare event id from an alert description. Correlation and direct promotion both write it there."""
    found: list[str] = []
    seen: set[str] = set()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        for key in ("description", "alert_description", "name", "alert_name"):
            text = alert.get(key)
            if not isinstance(text, str):
                continue
            for event_id in EVENT_ID_PATTERN.findall(text):
                if event_id not in seen:
                    found.append(event_id)
                    seen.add(event_id)
    return found


def writeback_enabled(params: dict[str, Any]) -> bool:
    return argToBoolean(params.get("enable_status_writeback") or False)


def load_writeback_state() -> tuple[int | None, list[str]]:
    context = integration_context()
    raw_since = context.get("writeback_since_ms")
    since_ms = int(raw_since) if isinstance(raw_since, (int, float)) else None
    raw_ids = context.get("writeback_case_ids")
    case_ids = [str(case_id) for case_id in raw_ids] if isinstance(raw_ids, list) else []
    return since_ms, case_ids


def save_writeback_state(since_ms: int, case_ids: list[str]) -> None:
    context = integration_context()
    context["writeback_since_ms"] = since_ms
    context["writeback_case_ids"] = remember_uids([], case_ids)[-WRITEBACK_CASE_LIMIT:]
    demisto.setIntegrationContext(context)


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
    risks = as_list(alert.get("risks"))
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
    values = as_list(alert.get("search_types"))
    return [str(item) for item in values if str(item).strip()]


def category_names(alert: dict[str, Any]) -> list[str]:
    """Each search type on a Flare alert is one category. An alert with no types is one open feed."""
    return alert_types(alert) or ["*"]


def alert_for_category(alert: dict[str, Any], category: str) -> dict[str, Any]:
    if category == "*":
        return alert
    narrowed = dict(alert)
    narrowed["search_types"] = [category]
    return narrowed


def alert_is_disabled(alert: dict[str, Any]) -> bool:
    scope = as_dict(alert.get("identifier_scope"))
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
    oldest = datetime.now(UTC) - timedelta(days=MAX_BACKFILL_DAYS)
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
    data = as_dict(full_event.get("data"))
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
    metadata = as_dict(feed_item.get("metadata"))
    tenant_metadata = as_dict(feed_item.get("tenant_metadata"))
    severity_block = as_dict(tenant_metadata.get("severity"))
    identifiers = as_list(feed_item.get("identifiers"))
    full_event = full_event or {}
    full_metadata = as_dict(full_event.get("metadata"))
    data = event_data_block(full_event)
    features = as_dict(data.get("features"))

    identifier_ids = [str(item.get("id")) for item in identifiers if isinstance(item, dict) and item.get("id") is not None]
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
    metadata = as_dict(item.get("metadata"))
    return str(metadata.get("uid") or "")


def feed_matched_at(item: dict[str, Any]) -> str:
    metadata = as_dict(item.get("metadata"))
    return str(metadata.get("matched_at") or "")


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


def resume_window(
    tenant_key: str,
    saved_state: dict[str, Any],
    backfill: str,
    fingerprint: str,
) -> tuple[str, bool]:
    """Return the search start and whether events at that exact time were already stored."""
    saved = str(saved_state.get("matched_at_gte") or "")
    filters_changed = "fingerprint" in saved_state and saved_state.get("fingerprint") != fingerprint
    if filters_changed:
        demisto.debug(f"Flare filters changed for {tenant_key}. Resuming from now.")
        return datetime.now(UTC).strftime(DATE_FORMAT), False
    if saved:
        return saved, True
    return backfill_start(backfill), False


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
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Pull one feed from the saved timestamp. The next cycle starts at the last event stored here."""
    matched_at_gte, already_stored = resume_window(tenant_key, saved_state, backfill, fingerprint)
    cursor = None
    collected: list[dict[str, Any]] = []
    pages = 0
    while len(collected) < max_events and pages < MAX_PAGES:
        pages += 1
        page = search_page(cursor, matched_at_gte)
        items = as_list(page.get("items"))
        response_next = page.get("next") if isinstance(page.get("next"), str) else None
        fresh = []
        for item in items:
            if not isinstance(item, dict) or not feed_uid(item):
                continue
            if already_stored and feed_matched_at(item) <= matched_at_gte:
                continue
            fresh.append(item)
        room = max_events - len(collected)
        chosen = fresh[:room]
        for item in chosen:
            uid = feed_uid(item)
            full_event = client.get_event(tenant_key, uid) if fetch_full_event else {}
            collected.append(build_event(tenant_key, item, full_event, alert, instance_tag))
        if len(chosen) < len(fresh) or not response_next:
            break
        cursor = response_next
    if collected:
        matched_at_gte = str(collected[-1].get("matched_at") or matched_at_gte)
    return collected, {"matched_at_gte": matched_at_gte, "fingerprint": fingerprint}


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
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Pull one tenant feed from its saved timestamp until the cycle limit or the feed is caught up."""

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
    )


def list_alert_definitions(client: Client, tenant_key: str) -> list[dict[str, Any]]:
    """Page through saved Flare alerts. Stop when the next page is empty or repeats."""
    alerts: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    cursor = None
    seen_cursors: set[str] = set()
    for _page in range(ALERT_LIST_PAGES):
        page = client.list_alerts(tenant_key, cursor)
        items = as_list(page.get("items"))
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
    )


def category_start(saved_categories: dict[str, Any], category: str, global_time: str) -> dict[str, Any]:
    """A category seen before continues from its own timestamp. A new one starts at the global timestamp."""
    saved = str(saved_categories.get(category) or "")
    if saved:
        return {"matched_at_gte": saved}
    if global_time:
        return {"matched_at_gte": global_time}
    return {}


def fetch_saved_alerts(
    client: Client,
    last_run: dict[str, Any],
    params: dict[str, Any],
    max_events: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch each category on each Flare alert. A category added after the first run starts at the global timestamp."""
    fetch_full_event = argToBoolean(params.get("fetch_full_event") or False)
    backfill = str(params.get("first_fetch") or DEFAULT_BACKFILL)
    instance_tag = str(params.get("instance_tag") or "").strip()
    global_time = str(last_run.get("global_time") or "")
    stored = as_dict(last_run.get("alerts"))
    events: list[dict[str, Any]] = []
    next_alerts: dict[str, Any] = {}
    for tenant_key in parse_tenants(params.get("tenants")):
        for alert in list_alert_definitions(client, tenant_key):
            if alert_is_disabled(alert):
                continue
            state_key = f"{tenant_key}:{alert.get('id')}"
            previous = as_dict(stored.get(state_key))
            saved_categories = as_dict(previous.get("categories"))
            if len(events) >= max_events:
                if previous:
                    next_alerts[state_key] = previous
                continue
            next_categories = {str(name): str(stamp) for name, stamp in saved_categories.items()}
            for category in category_names(alert):
                if len(events) >= max_events:
                    break
                alert_events, alert_state = fetch_one_alert(
                    client,
                    tenant_key,
                    alert_for_category(alert, category),
                    category_start(saved_categories, category, global_time),
                    backfill,
                    max_events - len(events),
                    fetch_full_event,
                    instance_tag,
                )
                events.extend(alert_events)
                next_categories[category] = str(alert_state.get("matched_at_gte") or "")
            next_alerts[state_key] = {"categories": next_categories}
    tenants = as_dict(last_run.get("tenants"))
    return {"tenants": tenants, "alerts": next_alerts, "global_time": latest_matched_at(global_time, events)}, events


def fetch_events(
    client: Client,
    last_run: dict[str, Any],
    params: dict[str, Any],
    max_events: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if argToBoolean(params.get("fetch_alerts") or False):
        next_run, alert_events = fetch_saved_alerts(client, last_run, params, max_events)
        return stamp_checkpoint(last_run, next_run, alert_events), alert_events
    tenants = parse_tenants(params.get("tenants"))
    severities = parse_choices(params.get("severity"))
    event_types = category_types(parse_choices(params.get("event_types")))
    fetch_full_event = argToBoolean(params.get("fetch_full_event") or False)
    backfill = str(params.get("first_fetch") or DEFAULT_BACKFILL)
    instance_tag = str(params.get("instance_tag") or "").strip()
    stored = as_dict(last_run.get("tenants"))
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
        )
        events.extend(tenant_events)
        next_tenants[tenant_key] = tenant_state
    alerts = as_dict(last_run.get("alerts"))
    return stamp_checkpoint(last_run, {"tenants": next_tenants, "alerts": alerts}, events), events


ALERT_SEVERITY = {
    "info": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}


class XsiamClient(BaseClient):
    """Opens one XSIAM alert per Flare event. This is separate from the Flare API client."""

    def __init__(self, base_url: str, api_key: str, api_key_id: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": api_key,
            "x-xdr-auth-id": api_key_id,
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def create_alerts(self, alerts: list[dict[str, Any]]) -> None:
        """Open one alert per call. insert_parsed_alerts drops host and user, so cases never group."""
        for alert in alerts:
            response = self._http_request(
                method="POST",
                url_suffix="/public_api/v1/alerts/create_alert",
                json_data={"request_data": {"alert": alert}},
            )
            reply = response.get("reply") if isinstance(response, dict) else None
            if isinstance(reply, dict) and reply.get("err_code"):
                message = reply.get("err_msg") or reply.get("err_code")
                raise DemistoException(f"Direct alert promotion failed to open an issue. {message}")

    def xdr_request(self, url_suffix: str, request_data: dict[str, Any]) -> dict[str, Any]:
        response = self._http_request(method="POST", url_suffix=url_suffix, json_data={"request_data": request_data})
        if not isinstance(response, dict):
            raise DemistoException("XSIAM returned an empty response.")
        reply = response.get("reply")
        if isinstance(reply, dict) and reply.get("err_code"):
            message = reply.get("err_msg") or reply.get("err_code")
            raise DemistoException(f"XSIAM case lookup failed. {message}")
        return reply if isinstance(reply, dict) else {}

    def closed_flare_cases(self, since_ms: int) -> list[dict[str, Any]]:
        """Closed cases whose name contains Flare Exposure and that changed since the last check."""
        reply = self.xdr_request(
            "/public_api/v1/incidents/get_incidents",
            {
                "filters": [
                    {"field": "status", "operator": "in", "value": RESOLVED_CASE_STATUSES},
                    {"field": "modification_time", "operator": "gte", "value": since_ms},
                ],
                "search_from": 0,
                "search_to": 100,
            },
        )
        incidents = reply.get("incidents")
        if not isinstance(incidents, list):
            return []
        cases = []
        for incident in incidents:
            if not isinstance(incident, dict):
                continue
            name = str(incident.get("incident_name") or incident.get("name") or "")
            if "Flare Exposure" in name:
                cases.append(incident)
        return cases

    def case_alerts(self, incident_id: str) -> list[dict[str, Any]]:
        reply = self.xdr_request(
            "/public_api/v1/incidents/get_incident_extra_data",
            {"incident_id": str(incident_id), "alerts_limit": 100},
        )
        alerts = reply.get("alerts")
        if isinstance(alerts, list):
            return [alert for alert in alerts if isinstance(alert, dict)]
        if isinstance(alerts, dict) and isinstance(alerts.get("data"), list):
            return [alert for alert in alerts["data"] if isinstance(alert, dict)]
        return []


def direct_promotion_enabled(params: dict[str, Any]) -> bool:
    return argToBoolean(params.get("enable_direct_alert_promotion") or False)


def xsiam_settings(params: dict[str, Any], feature: str) -> tuple[str, str, str]:
    """XSIAM credentials used by direct alert promotion and status write-back."""
    base_url = str(params.get("xsiam_url") or "").strip().rstrip("/")
    api_key = str(params.get("xsiam_api_key") or "").strip()
    api_key_id = str(params.get("xsiam_api_key_id") or "").strip()
    missing = []
    if not base_url:
        missing.append("XSIAM server URL")
    if not api_key:
        missing.append("XSIAM API key")
    if not api_key_id:
        missing.append("XSIAM API key ID")
    if missing:
        raise DemistoException(f"{feature} needs {', '.join(missing)}.")
    return base_url, api_key, api_key_id


def promotion_settings(params: dict[str, Any]) -> tuple[str, str, str]:
    """XSIAM credentials used only when direct alert promotion is checked."""
    return xsiam_settings(params, "Enable Direct Alert Promotion")


def require_xsiam_settings(params: dict[str, Any]) -> None:
    if direct_promotion_enabled(params):
        xsiam_settings(params, "Enable Direct Alert Promotion")


def xsiam_client_from_params(params: dict[str, Any], feature: str = "Enable Direct Alert Promotion") -> XsiamClient:
    base_url, api_key, api_key_id = xsiam_settings(params, feature)
    return XsiamClient(
        base_url=base_url,
        api_key=api_key,
        api_key_id=api_key_id,
        verify=not params.get("insecure"),
        proxy=bool(params.get("proxy")),
    )


def matched_at_millis(matched_at: str) -> int:
    parsed = arg_to_datetime(matched_at) if matched_at else None
    moment = parsed or datetime.now(UTC)
    return int(moment.timestamp() * 1000)


def events_to_parsed_alerts(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn each stored Flare event into one custom XSIAM alert.

    create_alert keeps alert-table fields. host_name and the actor are the
    same values the correlation rules set, so Medium and higher issues for
    one identifier can share a case.
    """
    alerts: list[dict[str, Any]] = []
    for event in events:
        severity_name = str(event.get("severity") or "info").lower()
        instance_tag = str(event.get("flare_instance_tag") or "").strip()
        event_id = str(event.get("flare_event_id") or "")
        name = f"Flare Exposure - {severity_name.title()}"
        identifier = str(event.get("grouping_name") or "").strip()
        if identifier:
            name = f"{name}. {identifier}"
        if instance_tag:
            name = f"{name}. Instance {instance_tag}"
        alert: dict[str, Any] = {
            "vendor": VENDOR,
            "product": PRODUCT,
            "severity": ALERT_SEVERITY.get(severity_name, "Informational"),
            "category": "Other",
            "alert_name": name,
            "alert_domain": "DOMAIN_SECURITY",
            "description": (
                f"Direct alert promotion. Flare {severity_name} event {event_id} "
                f"({event.get('event_type')}) matched identifier {identifier}. "
                f"Instance {instance_tag}."
            ),
            "event_timestamp": matched_at_millis(str(event.get("matched_at") or "")),
        }
        ipv4 = str(event.get("ipv4") or "").strip()
        if ipv4 and ipv4 != "0.0.0.0":
            alert["remote_ip"] = ipv4
        if identifier:
            alert["host_name"] = identifier
            alert["agent_hostname"] = identifier
            alert["os_parent_user_name"] = identifier
            alert["actor_effective_username"] = identifier
        alerts.append(alert)
    return alerts


def store_and_promote(
    params: dict[str, Any],
    last_run: dict[str, Any],
    next_run: dict[str, Any],
    events: list[dict[str, Any]],
) -> None:
    """Store the dataset first. A failed alert insert is retried on the next fetch without a reset."""
    promoting = direct_promotion_enabled(params)
    pending = [item for item in list(last_run.get("pending_alerts") or []) if isinstance(item, dict)] if promoting else []
    if events:
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        if promoting:
            pending.extend(events_to_parsed_alerts(events))
    if pending:
        next_run["pending_alerts"] = pending
        demisto.setLastRun(next_run)
        xsiam_client_from_params(params).create_alerts(pending)
    next_run.pop("pending_alerts", None)
    demisto.setLastRun(next_run)


def stamp_checkpoint(
    last_run: dict[str, Any],
    next_run: dict[str, Any],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Save the timestamp of the newest event stored in this cycle."""
    next_run["last_matched_at"] = latest_matched_at(str(last_run.get("last_matched_at") or ""), events)
    return next_run


def sync_closed_cases(client: Client, params: dict[str, Any], xsiam: XsiamClient) -> list[str]:
    """Mark Flare events remediated for Flare Exposure cases closed since the last check."""
    now_ms = int(datetime.now(UTC).timestamp() * 1000)
    since_ms, done_ids = load_writeback_state()
    if since_ms is None:
        since_ms = now_ms - WRITEBACK_LOOKBACK_MS
    done = set(done_ids)
    tenant_key = parse_tenants(params.get("tenants"))[0]
    remediated: list[str] = []
    for case in xsiam.closed_flare_cases(since_ms):
        case_id = str(case.get("incident_id") or "")
        if not case_id or case_id in done:
            continue
        alerts = xsiam.case_alerts(case_id)
        event_ids = event_ids_from_alerts(alerts)
        if not alerts or not event_ids:
            raise DemistoException(f"Case {case_id} has no Flare event id on its alerts.")
        client.remediate_events(tenant_key, event_ids)
        remediated.extend(event_ids)
        done_ids.append(case_id)
        done.add(case_id)
    save_writeback_state(now_ms, done_ids)
    if remediated:
        demisto.info(f"Marked {len(remediated)} Flare events remediated from closed cases.")
    return remediated


def update_event_status_command(client: Client, params: dict[str, Any], args: dict[str, Any]) -> CommandResults:
    """On-demand remediate. A case id reads that case's alerts. The checkbox does not gate this command."""
    event_ids = [str(event_id).strip() for event_id in argToList(args.get("event_id")) if str(event_id).strip()]
    case_id = str(args.get("case_id") or "").strip()
    if case_id:
        xsiam = xsiam_client_from_params(params, "flare-update-event-status")
        alerts = xsiam.case_alerts(case_id)
        event_ids.extend(event_ids_from_alerts(alerts))
        if not event_ids:
            raise DemistoException(f"Case {case_id} has no Flare event id on its alerts.")
    if not event_ids:
        raise DemistoException("Provide a Flare event id or a case id.")
    tenant_key = parse_tenants(params.get("tenants"))[0]
    client.remediate_events(tenant_key, event_ids)
    rows = [{"EventID": event_id, "Status": "remediated"} for event_id in event_ids]
    return CommandResults(
        readable_output=tableToMarkdown("Flare events marked remediated", rows, headers=["EventID", "Status"]),
        outputs_prefix="FlareExposure.Remediation",
        outputs={"EventIDs": event_ids, "Status": "remediated", "CaseID": case_id},
    )


def test_module(client: Client, params: dict[str, Any]) -> str:
    require_xsiam_settings(params)
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
        elif command == "flare-update-event-status":
            return_results(update_event_status_command(client, params, args))
        elif command == "fetch-events":
            require_xsiam_settings(params)
            last_run = demisto.getLastRun() or {}
            limit = event_limit(params.get("max_fetch"), DEFAULT_MAX_EVENTS)
            next_run, events = fetch_events(client, last_run, params, limit)
            store_and_promote(params, last_run, next_run, events)
        else:
            return_error(f"Command {command} is not implemented.")
    except Exception as error:
        return_error(f"Failed to execute {command}. Error: {error}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
