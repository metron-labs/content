import json

import pytest
from FlareExposureEventCollector import (
    advance_cursor,
    alert_search_filters,
    backfill_start,
    build_event,
    fetch_saved_alerts,
    fetch_tenant_events,
    strip_secrets,
    tenant_id,
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
    assert first_state["from"] is None
    assert first_state["page_uids"] == ["event-1"]

    second_events, second_state = fetch_tenant_events(
        client, "17", first_state, "1 day", [], [], 1, fetch_full_event=True
    )
    assert [event["flare_event_id"] for event in second_events] == ["event-2"]
    assert second_state["from"] == "cursor-b"
    assert client.activity_uids == ["event-1", "event-2"]
    assert first_events[0]["source_url"] == "https://example.invalid/item"
    assert second_events[0]["source_url"] == "https://example.invalid/item"


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


SAVED_ALERT = {
    "id": 436059,
    "name": "test ",
    "feed_definition": {"type": "identifier", "id": 23077811},
    "search_types": ["service", "leak"],
    "risks": [5],
}


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
        self.alert_calls.append({"alert_id": alert["id"], "from": from_cursor, "matched_at_gte": matched_at_gte})
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
    assert len(client.alert_calls) == 1
    assert client.alert_calls[0]["alert_id"] == 436059
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
    assert [call["alert_id"] for call in client.alert_calls] == [436059]
    assert [event["flare_alert_id"] for event in events] == ["436059"]
