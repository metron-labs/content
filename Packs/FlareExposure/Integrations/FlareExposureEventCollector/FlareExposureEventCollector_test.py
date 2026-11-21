import json

import demistomock as demisto
import pytest
from FlareExposureEventCollector import (
    advance_cursor,
    alert_for_create,
    alert_search_filters,
    backfill_start,
    build_event,
    category_types,
    Client,
    event_ids_from_alerts,
    events_to_parsed_alerts,
    XsiamClient,
    promotion_settings,
    remediate_batches,
    sync_closed_cases,
    fetch_events,
    fetch_saved_alerts,
    fetch_tenant_events,
    filter_fingerprint,
    strip_secrets,
    tenant_id,
    writeback_enabled,
)


FEED_ITEM = {
    "metadata": {
        "uid": "driller/driller_github/testbench_source_code_2026-11-05",
        "type": "driller",
        "severity": "high",
        "matched_at": "2026-11-05T05:03:37.534993Z",
        "estimated_created_at": "2026-11-05T05:00:00Z",
        "flare_url": "https://app.flare.io/#/driller/driller_github/testbench_source_code_2026-11-05",
    },
    "tenant_metadata": {"severity": None, "notes": None, "tags": []},
    "identifiers": [{"id": 23077811, "name": "testbench.qa.flared.io"}],
}

FULL_EVENT = {
    "event_type": "driller_source_code",
    "metadata": {"uid": "driller/driller_github/testbench_source_code_2026-11-05", "severity": "high"},
    "data": {
        "actor": {"id": "magicsword-io", "name": "magicsword-io"},
        "title": "Secret File yaml/secret_secrets.yaml",
        "url": "https://github.com/magic-repo-iodummy_url",
        "password": "secret-value",
        "features": {"emails": ["user@example.com"], "ip_addresses": ["203.0.113.10", "2001:db8::1"]},
    },
}


def test_strip_secrets_removes_nested_passwords():
    cleaned = strip_secrets(FULL_EVENT)
    assert "password" not in json.dumps(cleaned)


def test_build_event_uses_feed_fields_without_full_event():
    event = build_event("17", FEED_ITEM)
    assert event["flare_event_id"] == "driller/driller_github/testbench_source_code_2026-11-05"
    assert event["event_type"] == "driller"
    assert event["severity"] == "high"
    assert event["grouping_id"] == "23077811"
    assert event["grouping_name"] == "testbench.qa.flared.io"
    assert event["flare_url"].startswith("https://app.flare.io/#/driller/")
    assert event["event_data"] == ""
    assert event["full_event_type"] == ""


def test_build_event_attaches_data_block_and_drops_password():
    event = build_event("17", FEED_ITEM, FULL_EVENT)
    assert event["full_event_type"] == "driller_source_code"
    assert event["source_url"] == "https://github.com/magic-repo-iodummy_url"
    assert event["email"] == "user@example.com"
    assert event["ipv4"] == "203.0.113.10"
    assert "secret-value" not in event["event_data"]
    assert "secret-value" not in json.dumps(event)


def test_build_event_without_identifier_groups_by_event_id():
    feed = {"metadata": {"uid": "event-1", "type": "paste", "severity": "info", "matched_at": "2026-01-01T00:00:00Z"}}
    event = build_event("default", feed, {})
    assert event["grouping_id"] == "event-1"
    assert event["grouping_name"] == "event-1"
    assert event["flare_tenant_id"] == ""


def test_advance_cursor_replays_a_partial_page():
    state = advance_cursor("cursor-a", "cursor-b", ["event-1"], truncated=True)
    assert state == {"from": "cursor-a", "page_uids": ["event-1"]}


def test_advance_cursor_moves_when_the_page_is_finished():
    state = advance_cursor("cursor-a", "cursor-b", ["event-1"], truncated=False)
    assert state == {"from": "cursor-b", "page_uids": []}


def test_advance_cursor_keeps_the_last_page_for_dedup():
    state = advance_cursor("cursor-a", None, ["event-1"], truncated=False)
    assert state == {"from": "cursor-a", "page_uids": ["event-1"]}


def test_tenant_id_rejects_a_name():
    with pytest.raises(Exception, match="must be a number"):
        tenant_id("acme")


def test_backfill_rejects_more_than_180_days():
    with pytest.raises(Exception, match="180 days"):
        backfill_start("181 days")


class FakeClient:
    def __init__(self, pages: list[dict]):
        self.pages = pages
        self.calls: list[str | None] = []
        self.activity_uids: list[str] = []

    def search_events(self, tenant_key, from_cursor, matched_at_gte, severities, event_types):
        self.calls.append(from_cursor)
        return self.pages[len(self.calls) - 1]

    def get_event(self, tenant_key, uid):
        self.activity_uids.append(uid)
        return {"event_type": "driller_source_code", "data": {"url": "https://example.invalid/item"}}


def test_fetch_stops_inside_a_page_and_replays_the_remainder():
    page = {
        "items": [
            {"metadata": {"uid": "event-1", "severity": "low", "matched_at": "2026-01-01T00:00:00Z"}},
            {"metadata": {"uid": "event-2", "severity": "low", "matched_at": "2026-01-01T00:01:00Z"}},
        ],
        "next": "cursor-b",
    }
    client = FakeClient([page, page])
    first_events, first_state = fetch_tenant_events(client, "17", {}, "1 day", [], [], 1, fetch_full_event=True)
    assert [event["flare_event_id"] for event in first_events] == ["event-1"]
    assert first_state["matched_at_gte"] == "2026-01-01T00:00:00Z"

    second_events, second_state = fetch_tenant_events(client, "17", first_state, "1 day", [], [], 1, fetch_full_event=True)
    assert [event["flare_event_id"] for event in second_events] == ["event-2"]
    assert second_state["matched_at_gte"] == "2026-01-01T00:01:00Z"
    assert client.activity_uids == ["event-1", "event-2"]
    assert first_events[0]["source_url"] == "https://example.invalid/item"
    assert second_events[0]["source_url"] == "https://example.invalid/item"


def test_build_event_keeps_the_instance_tag():
    event = build_event("17", FEED_ITEM, instance_tag="lab-a")
    assert event["flare_instance_tag"] == "lab-a"


def test_fetch_skips_full_event_unless_enabled():
    page = {
        "items": [{"metadata": {"uid": "event-1", "severity": "low", "matched_at": "2026-01-01T00:00:00Z"}}],
        "next": None,
    }
    client = FakeClient([page])
    events, _state = fetch_tenant_events(client, "17", {}, "1 day", [], [], 1, fetch_full_event=False)
    assert events[0]["event_data"] == ""
    assert events[0]["flare_alert_id"] == ""
    assert client.activity_uids == []


def test_fetch_continues_after_the_saved_timestamp():
    page = {
        "items": [{"metadata": {"uid": "event-1", "severity": "low", "matched_at": "2026-01-01T00:00:00Z"}}],
        "next": None,
    }
    client = FakeClient([page])
    events, state = fetch_tenant_events(
        client,
        "17",
        {"matched_at_gte": "2026-01-01T00:00:00Z", "fingerprint": filter_fingerprint([], [])},
        "7 days",
        [],
        [],
        5,
    )
    assert events == []
    assert state["matched_at_gte"] == "2026-01-01T00:00:00Z"


def test_direct_promotion_creates_one_alert_per_event():
    event = build_event("17", FEED_ITEM, instance_tag="Custom-Index-1")
    alerts = events_to_parsed_alerts([event])
    assert len(alerts) == 1
    assert alerts[0]["alert_name"] == "Flare Exposure - High. testbench.qa.flared.io. Instance Custom-Index-1"
    assert alerts[0]["severity"] == "High"
    assert alerts[0]["vendor"] == "flare"
    assert alerts[0]["product"] == "exposure"
    assert "Direct alert promotion" in alerts[0]["description"]
    assert event["flare_event_id"] in alerts[0]["description"]
    assert alerts[0]["host_name"] == "testbench.qa.flared.io"
    assert alerts[0]["os_parent_user_name"] == ["testbench.qa.flared.io"]
    assert "os_actor_effective_username" not in alerts[0]
    assert "actor_effective_username" not in alerts[0]
    assert "agent_hostname" not in alerts[0]
    assert "event_timestamp" not in alerts[0]
    assert alerts[0]["category"] == "Other"
    assert alerts[0]["alert_domain"] == "DOMAIN_SECURITY"
    assert "local_ip" not in alerts[0]


def test_direct_promotion_uses_the_event_ipv4_and_info_severity():
    event = build_event("17", FEED_ITEM, FULL_EVENT, instance_tag="Custom-Index-1")
    event["severity"] = "info"
    alerts = events_to_parsed_alerts([event])
    assert alerts[0]["remote_ip"] == "203.0.113.10"
    assert alerts[0]["severity"] == "Informational"
    assert alerts[0]["alert_name"] == "Flare Exposure - Info. testbench.qa.flared.io. Instance Custom-Index-1"


def test_token_request_uses_the_flare_api_key_header():
    client = Client("https://api.flare.io", "flare-key", True, False)
    captured: dict = {}

    def fake_http(**kwargs):
        captured.update(kwargs)
        return {"token": "issued"}

    client._http_request = fake_http  # type: ignore[method-assign]
    assert client.token_for("747671") == "issued"
    assert captured["headers"]["Authorization"] == "flare-key"
    assert captured["headers"]["User-Agent"]
    assert captured["headers"]["Accept"] == "application/json"
    assert captured["json_data"] == {"tenant_id": 747671}


def test_create_alert_drops_fields_the_api_rejects():
    cleaned = alert_for_create(
        {
            "alert_name": "Flare Exposure - High",
            "host_name": "testbench.qa.flared.io",
            "os_actor_effective_username": ["testbench.qa.flared.io"],
            "event_timestamp": 1793855017534,
            "agent_hostname": "testbench.qa.flared.io",
            "actor_effective_username": "testbench.qa.flared.io",
        }
    )
    assert cleaned == {
        "alert_name": "Flare Exposure - High",
        "host_name": "testbench.qa.flared.io",
        "os_parent_user_name": ["testbench.qa.flared.io"],
    }


def test_create_alerts_wraps_each_alert():
    client = XsiamClient("https://example.test", "key", "1", True, False)
    captured: dict = {}

    def fake_http(**kwargs):
        captured.update(kwargs)
        return {"reply": True}

    client._http_request = fake_http  # type: ignore[method-assign]
    client.create_alerts([{"alert_name": "Flare Exposure - High", "vendor": "flare"}])
    assert captured["url_suffix"] == "/public_api/v1/alerts/create_alert"
    assert captured["json_data"] == {"request_data": {"alert": {"alert_name": "Flare Exposure - High", "vendor": "flare"}}}


def test_direct_promotion_requires_xsiam_credentials():
    with pytest.raises(Exception, match="XSIAM server URL"):
        promotion_settings({"enable_direct_alert_promotion": True})


def test_reset_fetches_the_backfill_again():
    page = {
        "items": [
            {"metadata": {"uid": "event-1", "severity": "low", "matched_at": "2026-11-16T05:00:00Z"}},
            {"metadata": {"uid": "event-2", "severity": "high", "matched_at": "2026-11-16T06:00:00Z"}},
        ],
        "next": None,
    }
    client = FakeClient([page, page, page])
    params = {"tenants": "17", "first_fetch": "7 days"}
    first_state, first_events = fetch_events(client, {}, params, 5)
    assert [event["flare_event_id"] for event in first_events] == ["event-1", "event-2"]

    continued_state, continued_events = fetch_events(client, first_state, params, 5)
    assert continued_events == []
    assert continued_state["last_matched_at"] == "2026-11-16T06:00:00Z"

    reset_state, reset_events = fetch_events(client, {}, params, 5)
    assert [event["flare_event_id"] for event in reset_events] == ["event-1", "event-2"]
    assert reset_state["last_matched_at"] == "2026-11-16T06:00:00Z"


def test_fetch_events_records_the_checkpoint_and_instance_tag():
    page = {
        "items": [{"metadata": {"uid": "event-9", "severity": "low", "matched_at": "2026-11-08T00:00:00Z"}}],
        "next": None,
    }
    client = FakeClient([page])
    state, events = fetch_events(client, {}, {"tenants": "17", "first_fetch": "7 days", "instance_tag": "lab-a"}, 5)
    assert events[0]["flare_instance_tag"] == "lab-a"
    assert state["last_matched_at"] == "2026-11-08T00:00:00Z"
    assert state["tenants"]["17"]["matched_at_gte"] == "2026-11-08T00:00:00Z"
    assert "seen_uids" not in state


SAVED_ALERT = {
    "id": 436059,
    "name": "test ",
    "feed_definition": {"type": "identifier", "id": 23077811},
    "search_types": ["service", "leak"],
    "risks": [5],
}


def test_category_labels_expand_to_search_types():
    illicit = category_types(["Illicit Networks"])
    assert illicit[0] == "illicit_networks"
    assert "chat_message" in illicit
    assert "service" in category_types(["Open Web"])
    assert category_types(["Leaked Credentials"]) == [
        "leaks",
        "leak",
        "valid_credential",
        "invalid_credential",
        "mitigated_credential",
    ]
    assert category_types(["Look-alike Domains"])[0] == "lookalike_discovery"
    assert "bot" in category_types(["Infected Devices"])
    source_code = category_types(["Source Code"])
    assert source_code == ["source_code", "stack_exchange", "source_code_files"]
    assert "source_code_secret" not in source_code
    assert category_types(["Intelligence Objects", "Emerging Source"]) == ["intelligence_object", "experimental"]
    assert category_types([]) == []


def test_alert_search_uses_saved_categories_severities_and_backfill():
    filters = alert_search_filters(SAVED_ALERT, "2026-11-03T00:00:00Z")
    assert filters == {
        "matched_at": {"gte": "2026-11-03T00:00:00Z"},
        "type": ["service", "leak"],
        "severity": ["critical"],
    }


def test_alert_search_omits_severity_when_the_alert_includes_every_risk():
    alert = {**SAVED_ALERT, "risks": [1, 2, 3, 4, 5], "search_types": []}
    filters = alert_search_filters(alert, "2026-11-03T00:00:00Z")
    assert filters == {"matched_at": {"gte": "2026-11-03T00:00:00Z"}}


class AlertClient:
    def __init__(self):
        self.alert_calls: list[dict] = []

    def list_alerts(self, tenant_key, from_cursor):
        if from_cursor:
            return {"items": [], "next": None}
        return {"items": [SAVED_ALERT], "next": "page-2"}

    def search_alert_events(self, tenant_key, alert, from_cursor, matched_at_gte):
        self.alert_calls.append(
            {
                "alert_id": alert["id"],
                "from": from_cursor,
                "matched_at_gte": matched_at_gte,
                "types": list(alert.get("search_types") or []),
            }
        )
        return {
            "items": [{"metadata": {"uid": "alert-event-1", "severity": "critical", "matched_at": "2026-11-05T00:00:00Z"}}],
            "next": None,
        }

    def get_event(self, tenant_key, uid):
        raise AssertionError(uid)


def test_fetch_alerts_ignores_instance_filters_and_tags_the_alert():
    client = AlertClient()
    _state, events = fetch_saved_alerts(
        client,
        {},
        {"tenants": "747671", "severity": ["info"], "event_types": ["paste"], "first_fetch": "3 days"},
        10,
    )
    assert len(client.alert_calls) == 2
    assert {tuple(call["types"]) for call in client.alert_calls} == {("service",), ("leak",)}
    assert events[0]["flare_alert_id"] == "436059"
    assert events[0]["flare_alert_name"] == "test"
    assert events[0]["grouping_name"] == "alert-event-1"


def test_fetch_alerts_skips_a_disabled_alert():
    disabled = {**SAVED_ALERT, "id": 437914, "identifier_scope": {"name": "scatterholt.com", "is_disabled": True}}

    class DisabledAlertClient(AlertClient):
        def list_alerts(self, tenant_key, from_cursor):
            if from_cursor:
                return {"items": [], "next": None}
            return {"items": [SAVED_ALERT, disabled], "next": None}

    client = DisabledAlertClient()
    _state, events = fetch_saved_alerts(client, {}, {"tenants": "747671", "first_fetch": "3 days"}, 10)
    assert [call["alert_id"] for call in client.alert_calls] == [436059, 436059]
    assert [event["flare_alert_id"] for event in events] == ["436059", "436059"]


def test_writeback_checkbox_defaults_off():
    assert writeback_enabled({}) is False
    assert writeback_enabled({"enable_status_writeback": True}) is True


def test_event_ids_come_from_direct_and_correlation_descriptions():
    event_id = "document/cactus_blog/testbench_ransomware_2026-11-14"
    alerts = [
        {"description": f"Direct alert promotion. Flare critical event {event_id} (document) matched identifier x."},
        {"description": "Flare high event listing/alphabet_market/testbench_listing_2026-11-14 (listing) matched identifier y."},
    ]
    assert event_ids_from_alerts(alerts) == [
        event_id,
        "listing/alphabet_market/testbench_listing_2026-11-14",
    ]


def test_remediate_batches_hold_ten_event_ids():
    uids = [f"event-{index}" for index in range(11)]
    batches = remediate_batches(uids)
    assert len(batches) == 2
    assert batches[0]["action"] == {"type": "remediate"}
    assert len(batches[0]["targets"]) == 10
    assert batches[1]["targets"] == [{"uid": "event-10"}]


class WritebackFlare:
    def __init__(self):
        self.calls: list[tuple[str, list[str]]] = []

    def remediate_events(self, tenant_key, uids):
        self.calls.append((tenant_key, list(uids)))


class WritebackXsiam:
    def __init__(self, cases, alerts):
        self.cases = cases
        self.alerts = alerts

    def closed_flare_cases(self, since_ms):
        return self.cases

    def case_alerts(self, incident_id):
        return self.alerts[incident_id]


def test_closed_case_remediates_its_events_once():
    demisto.setIntegrationContext({})
    event_id = "service/driller_shodan/testbench.qa.flared.io/2026-11-14"
    flare = WritebackFlare()
    xsiam = WritebackXsiam(
        [{"incident_id": "223880", "incident_name": "Flare Exposure - High. Instance Custom-Index-1"}],
        {"223880": [{"description": f"Direct alert promotion. Flare high event {event_id} (service) matched identifier x."}]},
    )
    try:
        first = sync_closed_cases(flare, {"tenants": "747671"}, xsiam)
        assert first == [event_id]
        assert flare.calls == [("747671", [event_id])]
        second = sync_closed_cases(flare, {"tenants": "747671"}, xsiam)
        assert second == []
        assert len(flare.calls) == 1
        assert demisto.getIntegrationContext()["writeback_case_ids"] == ["223880"]
    finally:
        demisto.setIntegrationContext({})


def test_alert_fetch_continues_from_the_category_timestamp():
    client = AlertClient()
    state_key = "747671:436059"
    _state, events = fetch_saved_alerts(
        client,
        {
            "global_time": "2026-11-01T00:00:00Z",
            "alerts": {state_key: {"categories": {"service": "2026-11-05T00:00:00Z", "leak": "2026-11-05T00:00:00Z"}}},
        },
        {"tenants": "747671", "first_fetch": "7 days", "instance_tag": "lab-a"},
        10,
    )
    assert {tuple(call["types"]): call["matched_at_gte"] for call in client.alert_calls} == {
        ("service",): "2026-11-05T00:00:00Z",
        ("leak",): "2026-11-05T00:00:00Z",
    }
    assert events == []


def test_new_alert_starts_at_the_global_timestamp():
    client = AlertClient()
    state, events = fetch_saved_alerts(
        client,
        {"global_time": "2026-11-01T00:00:00Z", "alerts": {}},
        {"tenants": "747671", "first_fetch": "7 days"},
        10,
    )
    assert {call["matched_at_gte"] for call in client.alert_calls} == {"2026-11-01T00:00:00Z"}
    assert [event["flare_event_id"] for event in events] == ["alert-event-1", "alert-event-1"]
    assert state["global_time"] == "2026-11-05T00:00:00Z"
    assert state["alerts"]["747671:436059"]["categories"] == {
        "service": "2026-11-05T00:00:00Z",
        "leak": "2026-11-05T00:00:00Z",
    }


def test_new_category_on_a_saved_alert_starts_at_the_global_timestamp():
    client = AlertClient()
    saved_alert = {**SAVED_ALERT, "search_types": ["service", "leak", "open_web"]}

    class ExpandedAlertClient(AlertClient):
        def list_alerts(self, tenant_key, from_cursor):
            if from_cursor:
                return {"items": [], "next": None}
            return {"items": [saved_alert], "next": None}

    client = ExpandedAlertClient()
    state, events = fetch_saved_alerts(
        client,
        {
            "global_time": "2026-11-04T00:00:00Z",
            "alerts": {"747671:436059": {"categories": {"service": "2026-11-05T00:00:00Z", "leak": "2026-11-05T00:00:00Z"}}},
        },
        {"tenants": "747671", "first_fetch": "7 days"},
        10,
    )
    by_type = {tuple(call["types"]): call["matched_at_gte"] for call in client.alert_calls}
    assert by_type[("service",)] == "2026-11-05T00:00:00Z"
    assert by_type[("leak",)] == "2026-11-05T00:00:00Z"
    assert by_type[("open_web",)] == "2026-11-04T00:00:00Z"
    assert [event["flare_event_id"] for event in events] == ["alert-event-1"]
    assert state["alerts"]["747671:436059"]["categories"]["open_web"] == "2026-11-05T00:00:00Z"
    assert state["global_time"] == "2026-11-05T00:00:00Z"
