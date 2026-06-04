from datetime import datetime, UTC

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import pytest

from Vega import (
    _format_mitre_attack,
    Client,
    _fetch_paginated_entities,
    _format_bullet_list,
    _format_key_findings_html,
    _format_raw_entity_for_xsoar,
    _format_timeline_events_html,
    _load_seen_ids,
    _normalize_entity_id,
    _resolve_fetch_from_time,
    _update_fetch_state,
    alert_to_incident,
    fetch_incidents_command,
    incident_to_xsoar_incident,
    parse_backfill_days,
    validate_backfill_days,
    test_module as vega_test_module,
    main as vega_main,
)

BASE_URL = "https://api.vega.com"

MOCK_JWT_RESPONSE = {
    "session_jwt": "mock-jwt-token",
    "session_max_age": 1999999999,  # Far in the future
    "error": "",
}


def test_test_module(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(
        f"{BASE_URL}/api/v1/query", json={"data": {"getAccessKey": {"id": "mock-key-id", "roles": ["security admin"]}}}
    )

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == "ok"


def test_test_module_unauthorized(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(f"{BASE_URL}/api/v1/query", json={"data": {"getAccessKey": {"id": "mock-key-id", "roles": ["Viewer"]}}})

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == "You do not have required access to fetch incidents."


def test_test_module_incorrect_access_key_id(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(
        f"{BASE_URL}/api/v1/query",
        json={
            "errors": [
                {
                    "message": "Internal Server Error",
                    "extensions": {
                        "error_code": "E000000000",
                        "error_code_name": "INTERNAL_SERVER_ERROR",
                        "extra_args": None,
                        "trace_id": 8786647935177050492,
                    },
                }
            ],
            "data": {"getAccessKey": None},
        },
    )

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == "Incorrect Access Key ID. Please Check your Credentials"


def test_test_module_incorrect_access_key(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", status_code=500)

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="wrong-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == "Incorrect Access Key. Please Check your Credentials."


def test_main_invalid_entities(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "access_key": "key",
            "access_key_id": "id",
            "url": "url",
            "vega_entities": "",
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_return_error = mocker.patch("Vega.return_error")

    vega_main()

    mock_return_error.assert_called_once_with(
        "Failed to execute test-module command.\nError:\nAt least one of 'Fetch Alerts' or 'Fetch Incidents' must be checked."
    )


def test_url_normalization():
    # Test cases for URL normalization: (input_url, expected_normalized_url)
    test_cases = [
        ("https://api.vega.com", "https://api.vega.com/api/v1/"),
        ("https://api.vega.com/", "https://api.vega.com/api/v1/"),
        ("https://api.vega.com/api/v1", "https://api.vega.com/api/v1/"),
        ("https://api.vega.com/api/v1/", "https://api.vega.com/api/v1/"),
        ("https://api.vega.com/API/V1", "https://api.vega.com/API/V1/"),
        ("https://api.vega.com/API/v1/", "https://api.vega.com/API/v1/"),
    ]

    for input_url, expected in test_cases:
        client = Client(
            base_url=input_url,
            verify=False,
            proxy=False,
            access_key="test-key",
            access_key_id="test-key-id",
        )
        assert client._base_url == expected


FIRST_FETCH_TIME = "2026-01-01T00:00:00Z"
BACKFILL_DAYS = "30"
TIMESTAMP_T1 = "2026-06-01T10:00:00Z"
TIMESTAMP_T2 = "2026-06-01T11:00:00Z"
CURRENT_TIME_CURSOR = "2026-06-04T17:00:00Z"


def test_update_fetch_state_preserves_ids_when_all_dupes():
    previous_ids = ["alert-a", "alert-b"]
    fetched = [
        {"id": "alert-a", "createdAt": TIMESTAMP_T1},
        {"id": "alert-b", "createdAt": TIMESTAMP_T1},
    ]

    last_fetch, last_ids = _update_fetch_state(fetched, TIMESTAMP_T1, previous_ids)

    assert last_fetch == TIMESTAMP_T1
    assert set(last_ids) == set(previous_ids)


def test_update_fetch_state_preserves_state_when_empty():
    previous_ids = ["alert-a", "alert-b"]

    last_fetch, last_ids = _update_fetch_state([], TIMESTAMP_T1, previous_ids)

    assert last_fetch == TIMESTAMP_T1
    assert last_ids == previous_ids


def test_update_fetch_state_merges_ids_at_same_timestamp():
    previous_ids = ["alert-a"]
    fetched = [
        {"id": "alert-a", "createdAt": TIMESTAMP_T1},
        {"id": "alert-c", "createdAt": TIMESTAMP_T1},
    ]

    last_fetch, last_ids = _update_fetch_state(fetched, TIMESTAMP_T1, previous_ids)

    assert last_fetch == TIMESTAMP_T1
    assert set(last_ids) == {"alert-a", "alert-c"}


def test_update_fetch_state_handles_mixed_timestamp_formats():
    """Alerts with the same instant but different string formats share one boundary."""
    previous_ids = ["alert-a"]
    fetched = [
        {"id": "alert-a", "createdAt": "2026-06-01T10:00:00Z"},
        {"id": "alert-b", "createdAt": "2026-06-01T10:00:00.000Z"},
    ]

    last_fetch, last_ids = _update_fetch_state(fetched, "2026-06-01T10:00:00Z", previous_ids)

    assert last_fetch == TIMESTAMP_T1
    assert set(last_ids) == {"alert-a", "alert-b"}


def test_normalize_entity_id_coerces_numeric_ids():
    assert _normalize_entity_id({"id": 12345}) == "12345"
    assert _normalize_entity_id({"id": "12345"}) == "12345"


def test_load_seen_ids_merges_legacy_last_ids():
    last_run = {
        "alerts_seen_ids": ["alert-1"],
        "alerts_last_ids": ["alert-2", 12345],
    }
    seen = _load_seen_ids(last_run, "alerts_seen_ids", "alerts_last_ids")
    assert seen == {"alert-1", "alert-2", "12345"}


def test_fetch_incidents_command_dedup_numeric_id_with_seen_ids(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    numeric_id = 987654321
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": numeric_id, "name": "Numeric ID Alert", "severity": "LOW", "createdAt": TIMESTAMP_T1},
        ],
        "total": 1,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_incidents.return_value = {"incidents": [], "total": 0, "limit": 200, "offset": 0}

    last_run = {"alerts_seen_ids": [str(numeric_id)]}

    next_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run=last_run,
        fetch_alerts=True,
        fetch_incidents=False,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        backfill_days=BACKFILL_DAYS,
    )

    assert incidents == []
    assert str(numeric_id) in next_run["alerts_seen_ids"]


def test_resolve_fetch_from_time_uses_backfill_when_cursor_not_anchored():
    last_run = {"incidents_last_fetch": CURRENT_TIME_CURSOR}

    assert (
        _resolve_fetch_from_time(
            last_run,
            "incidents_last_fetch",
            FIRST_FETCH_TIME,
            BACKFILL_DAYS,
        )
        == FIRST_FETCH_TIME
    )


def test_resolve_fetch_from_time_uses_stored_cursor_when_backfill_matches():
    last_run = {
        "vega_backfill_days": BACKFILL_DAYS,
        "incidents_last_fetch": CURRENT_TIME_CURSOR,
    }

    assert (
        _resolve_fetch_from_time(
            last_run,
            "incidents_last_fetch",
            FIRST_FETCH_TIME,
            BACKFILL_DAYS,
        )
        == CURRENT_TIME_CURSOR
    )


def test_update_fetch_state_advances_to_newer_timestamp():
    previous_ids = ["alert-a"]
    fetched = [
        {"id": "alert-a", "createdAt": TIMESTAMP_T1},
        {"id": "alert-d", "createdAt": TIMESTAMP_T2},
    ]

    last_fetch, last_ids = _update_fetch_state(fetched, TIMESTAMP_T1, previous_ids)

    assert last_fetch == TIMESTAMP_T2
    assert last_ids == ["alert-d"]


def test_fetch_paginated_entities_multiple_pages(mocker):
    page_one = {
        "alerts": [{"id": "1", "createdAt": TIMESTAMP_T1}],
        "total": 2,
        "limit": 1,
        "offset": 0,
    }
    page_two = {
        "alerts": [{"id": "2", "createdAt": TIMESTAMP_T2}],
        "total": 2,
        "limit": 1,
        "offset": 1,
    }
    mock_get_alerts = mocker.Mock(side_effect=[page_one, page_two])

    results = _fetch_paginated_entities(
        mock_get_alerts,
        entities_key="alerts",
        from_time=FIRST_FETCH_TIME,
    )

    assert len(results) == 2
    assert results[0]["id"] == "1"
    assert results[1]["id"] == "2"
    assert mock_get_alerts.call_count == 2
    assert mock_get_alerts.call_args_list[0].kwargs["offset"] == 0
    assert mock_get_alerts.call_args_list[1].kwargs["offset"] == 1


def test_fetch_paginated_entities_fetches_beyond_single_page(mocker):
    """Verify pagination continues until total is reached when the API returns multiple pages."""
    page_one = {
        "alerts": [{"id": str(i), "createdAt": TIMESTAMP_T1} for i in range(200)],
        "total": 250,
        "limit": 200,
        "offset": 0,
    }
    page_two = {
        "alerts": [{"id": str(i), "createdAt": TIMESTAMP_T2} for i in range(200, 250)],
        "total": 250,
        "limit": 200,
        "offset": 200,
    }
    mock_get_alerts = mocker.Mock(side_effect=[page_one, page_two])

    results = _fetch_paginated_entities(
        mock_get_alerts,
        entities_key="alerts",
        from_time=FIRST_FETCH_TIME,
    )

    assert len(results) == 250
    assert mock_get_alerts.call_count == 2
    assert mock_get_alerts.call_args_list[0].kwargs.get("limit") is None
    assert mock_get_alerts.call_args_list[0].kwargs["offset"] == 0
    assert mock_get_alerts.call_args_list[1].kwargs["offset"] == 200


def test_fetch_incidents_command_no_duplicate_reingest(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": "alert-1", "name": "Test Alert", "severity": "HIGH", "createdAt": TIMESTAMP_T1},
        ],
        "total": 1,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_incidents.return_value = {"incidents": [], "total": 0, "limit": 200, "offset": 0}

    last_run = {
        "vega_backfill_days": BACKFILL_DAYS,
        "alerts_last_fetch": TIMESTAMP_T1,
        "alerts_last_ids": ["alert-1"],
    }

    next_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run=last_run,
        fetch_alerts=True,
        fetch_incidents=False,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        backfill_days=BACKFILL_DAYS,
    )

    assert incidents == []
    assert next_run["alerts_last_fetch"] == TIMESTAMP_T1
    assert set(next_run["alerts_last_ids"]) == {"alert-1"}
    assert "alert-1" in next_run["alerts_seen_ids"]


def test_fetch_incidents_command_pagination(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incidents.side_effect = [
        {
            "incidents": [{"id": "inc-1", "name": "Inc 1", "severity": "LOW", "createdAt": TIMESTAMP_T1}],
            "total": 2,
            "limit": 1,
            "offset": 0,
        },
        {
            "incidents": [{"id": "inc-2", "name": "Inc 2", "severity": "MEDIUM", "createdAt": TIMESTAMP_T2}],
            "total": 2,
            "limit": 1,
            "offset": 1,
        },
    ]
    mock_client.get_incident_details.return_value = {"timelineEvents": []}
    mock_client.get_alerts.return_value = {"alerts": [], "total": 0, "limit": 200, "offset": 0}

    next_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run={},
        fetch_alerts=False,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        backfill_days=BACKFILL_DAYS,
    )

    assert len(incidents) == 2
    assert mock_client.get_incidents.call_count == 2
    assert mock_client.get_incidents.call_args_list[0].kwargs["from_time"] == FIRST_FETCH_TIME
    assert next_run["incidents_last_fetch"] == TIMESTAMP_T2
    assert next_run["incidents_last_ids"] == ["inc-2"]


def test_fetch_incidents_command_uses_backfill_when_last_run_cursor_not_anchored(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incidents.return_value = {"incidents": [], "total": 0, "limit": 200, "offset": 0}
    mock_client.get_alerts.return_value = {"alerts": [], "total": 0, "limit": 200, "offset": 0}

    last_run = {"incidents_last_fetch": CURRENT_TIME_CURSOR}

    fetch_incidents_command(
        client=mock_client,
        last_run=last_run,
        fetch_alerts=False,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        backfill_days=BACKFILL_DAYS,
    )

    assert mock_client.get_incidents.call_args.kwargs["from_time"] == FIRST_FETCH_TIME


def test_parse_backfill_days_today(mocker):
    fixed_now = datetime(2026, 6, 2, 15, 30, 0, tzinfo=UTC)
    mocker.patch("Vega.datetime", wraps=datetime)
    mocker.patch("Vega.datetime.now", return_value=fixed_now)

    assert parse_backfill_days(0) == "2026-06-02T00:00:00Z"


def test_parse_backfill_days_days(mocker):
    fixed_now = datetime(2026, 6, 2, 15, 30, 0, tzinfo=UTC)
    mocker.patch("Vega.datetime", wraps=datetime)
    mocker.patch("Vega.datetime.now", return_value=fixed_now)

    assert parse_backfill_days(7) == "2026-05-26T00:00:00Z"


def test_parse_backfill_days_defaults(mocker):
    fixed_now = datetime(2026, 6, 2, 15, 30, 0, tzinfo=UTC)
    mocker.patch("Vega.datetime", wraps=datetime)
    mocker.patch("Vega.datetime.now", return_value=fixed_now)

    assert parse_backfill_days(None) == "2026-05-03T00:00:00Z"


def test_validate_backfill_days_rejects_out_of_range():
    with pytest.raises(ValueError, match="between 0 and 365"):
        validate_backfill_days(500)
    with pytest.raises(ValueError, match="between 0 and 365"):
        validate_backfill_days(-5)
    with pytest.raises(ValueError, match="must be an integer"):
        validate_backfill_days("not-a-number")


def test_parse_backfill_days_parses_decimal_string():
    assert parse_backfill_days("30.0") == parse_backfill_days(30)


def test_parse_backfill_days_legacy_first_fetch():
    result = parse_backfill_days(None, legacy_first_fetch="7 days")
    assert result.endswith("T00:00:00Z")
    parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    today_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    assert (today_start - parsed).days == 7


def test_format_bullet_list():
    assert _format_bullet_list(["CloudTrail", "VPC Flow Logs"]) == "• CloudTrail\n• VPC Flow Logs"
    assert _format_bullet_list([]) == []
    assert _format_bullet_list(None) is None
    assert _format_bullet_list("already formatted") == "already formatted"


def test_format_key_findings_html_dark_theme_layout():
    findings = [
        "Suspicious activity from 10.0.0.1",
        "Domain evil.com contacted by host",
    ]
    assets = ["10.0.0.1"]
    observables = ["evil.com"]

    result = _format_key_findings_html(findings, assets, observables)

    assert "background:#000000" in result
    assert "Key findings</div>" in result
    assert "See Investigation" not in result
    assert "border-radius:999px" in result
    assert "10.0.0.1" in result
    assert "evil.com" in result
    assert ">1</div>" in result
    assert ">2</div>" in result
    assert "border-bottom:1px solid #333333" in result


def test_format_key_findings_html_empty_state():
    result = _format_key_findings_html([], [], [])

    assert "No key findings are available" in result
    assert "background:#000000" in result


def test_format_raw_entity_for_xsoar_alert():
    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "vegaEntityType": "Vega Alert",
        "dataSources": ["CloudTrail", "GuardDuty"],
    }
    _format_raw_entity_for_xsoar(alert)

    assert alert["dataSources"] == "• CloudTrail\n• GuardDuty"
    assert alert["detectionDescription"] == "N/A"
    assert alert["detectionQuery"] == "N/A"
    assert set(alert.keys()) == {
        "id",
        "name",
        "vegaEntityType",
        "dataSources",
        "detectionDescription",
        "detectionQuery",
    }


def test_format_raw_entity_for_xsoar_alert_detection_fields():
    alert = {
        "id": "alert-1",
        "vegaEntityType": "Vega Alert",
        "detectionDescription": "  ",
        "detectionQuery": "SELECT * FROM events",
    }
    _format_raw_entity_for_xsoar(alert)

    assert alert["detectionDescription"] == "N/A"
    assert alert["detectionQuery"] == "```sql\nSELECT * FROM events\n```"


def test_format_raw_entity_for_xsoar_alert_empty_detection_fields():
    alert = {
        "id": "alert-1",
        "vegaEntityType": "Vega Alert",
        "detectionDescription": None,
        "detectionQuery": "",
    }
    _format_raw_entity_for_xsoar(alert)

    assert alert["detectionDescription"] == "N/A"
    assert alert["detectionQuery"] == "N/A"


def test_format_mitre_attack():
    assert _format_mitre_attack(None) is None
    assert _format_mitre_attack({}) is None
    assert (
        _format_mitre_attack({"mitreTactics": ["Discovery"], "mitreTechniques": ["Cloud Infrastructure Discovery"]})
        == "• Discovery\n• Cloud Infrastructure Discovery"
    )
    assert _format_mitre_attack({"mitreTactics": "Discovery", "mitreTechniques": "T1526"}) == "• Discovery\n• T1526"


def test_format_raw_entity_for_xsoar_mitre_attack():
    alert = {
        "id": "alert-1",
        "mitre": {"mitreTactics": ["Discovery"], "mitreTechniques": ["T1526"]},
    }
    _format_raw_entity_for_xsoar(alert)

    assert alert["vegaMitreAttack"] == "• Discovery\n• T1526"


def test_format_mitre_attack_object_items():
    mitre = {
        "mitreTactics": [{"name": "Discovery", "id": "TA0007"}],
        "mitreTechniques": [{"techniqueName": "Cloud Infrastructure Discovery", "techniqueId": "T1526"}],
    }
    assert _format_mitre_attack(mitre) == "• Discovery\n• Cloud Infrastructure Discovery"


def test_alert_to_incident_sets_vega_mitre_attack():
    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "severity": "HIGH",
        "createdAt": TIMESTAMP_T1,
        "mitre": {"mitreTactics": ["Discovery"], "mitreTechniques": ["T1526"]},
    }
    xsoar_incident = alert_to_incident(alert)
    raw = json.loads(xsoar_incident["rawJSON"])

    assert raw["vegaMitreAttack"] == "• Discovery\n• T1526"
    assert xsoar_incident["CustomFields"]["vegamitreattack"] == "• Discovery\n• T1526"
    assert xsoar_incident["CustomFields"]["vegacreatedat"] == TIMESTAMP_T1


def test_format_raw_entity_for_xsoar_incident():
    incident = {
        "id": "inc-1",
        "dataSources": ["CloudTrail"],
        "assets": ["i-12345"],
        "observables": ["10.0.0.1"],
        "incidentFindings": ["Instance i-12345 connected to 10.0.0.1"],
    }
    _format_raw_entity_for_xsoar(incident)

    assert incident["dataSources"] == "• CloudTrail"
    assert incident["assets"] == "• i-12345"
    assert incident["observables"] == "• 10.0.0.1"
    assert "vegaIncidentFindings" in incident
    assert "background:#000000" in incident["vegaIncidentFindings"]
    assert "i-12345" in incident["vegaIncidentFindings"]
    assert "10.0.0.1" in incident["vegaIncidentFindings"]


def test_alert_to_incident_formats_raw_json():
    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "severity": "HIGH",
        "createdAt": TIMESTAMP_T1,
        "dataSources": ["CloudTrail"],
    }
    xsoar_incident = alert_to_incident(alert, integration_url="https://api.vega.io")
    raw = json.loads(xsoar_incident["rawJSON"])

    assert raw["dataSources"] == "• CloudTrail"
    assert raw["vegaEntityType"] == "Vega Alert"
    assert raw["link"] == "https://app.vega.io/incidents/alerts/investigation/alert-1"
    assert raw["detectionDescription"] == "N/A"
    assert raw["detectionQuery"] == "N/A"
    assert set(raw.keys()) == {
        "id",
        "name",
        "severity",
        "createdAt",
        "dataSources",
        "vegaEntityType",
        "link",
        "detectionDescription",
        "detectionQuery",
    }


def test_incident_to_xsoar_incident_formats_raw_json():
    incident = {
        "id": "inc-1",
        "name": "Test Incident",
        "severity": "LOW",
        "createdAt": TIMESTAMP_T1,
        "assets": ["host-1"],
        "observables": ["host-1"],
        "incidentFindings": ["Activity detected on host-1"],
    }
    xsoar_incident = incident_to_xsoar_incident(incident)
    raw = json.loads(xsoar_incident["rawJSON"])

    assert raw["assets"] == "• host-1"
    assert raw["observables"] == "• host-1"
    assert "vegaIncidentFindings" in raw
    assert "Activity detected on" in raw["vegaIncidentFindings"]
    assert "host-1" in raw["vegaIncidentFindings"]
    assert xsoar_incident["CustomFields"]["vegaincidentfindings"]
    assert "link" not in raw


def test_format_timeline_events_html_dark_theme_layout():
    timeline = [
        {
            "id": "evt-1",
            "timestamp": "2026-04-28T01:30:00Z",
            "summary": "SSM enumeration detected.",
            "entities": [],
            "dataSources": [{"vendor": "AWS", "displayName": "CloudTrail"}],
            "alert": {"id": "alert-1", "displayName": "AWS SSM Enumeration", "severity": 3},
        },
        {
            "id": "evt-2",
            "timestamp": "2026-04-28T02:00:00Z",
            "summary": "Authorized scanner context.",
            "entities": [
                {
                    "type": "ASSET",
                    "category": "USERNAME",
                    "value": "arn:aws:sts::890123456789:assumed-role/WizAccess-Role/wiz-scanner-session",
                }
            ],
            "dataSources": [{"vendor": "Wiz", "displayName": "Wiz Issues"}],
            "alert": None,
        },
    ]
    formatted = _format_timeline_events_html(timeline)

    assert "background:#000000" in formatted
    assert "color:#ffffff" in formatted
    assert "Timeline</div>" in formatted
    assert "2026-04-28 01:30:00" in formatted
    assert "AWS SSM Enumeration" in formatted
    assert "AWS · CloudTrail" in formatted
    assert "Wiz · Wiz Issues" in formatted
    assert "Severity: High" in formatted
    assert "SSM enumeration detected." in formatted
    assert "arn:aws:sts::890123456789:assumed-role/WizAccess-Role/wiz-scanner-session" in formatted
    assert formatted.count("align-items:stretch") == 2
    assert "border-radius:50%" not in formatted


def test_incident_to_xsoar_incident_includes_timeline_events():
    timeline = [
        {
            "id": "evt-1",
            "timestamp": "2026-04-28T01:30:00Z",
            "summary": "Test event.",
            "entities": [],
            "dataSources": [],
            "alert": None,
        }
    ]
    incident = {
        "id": "inc-1",
        "name": "Test Incident",
        "severity": "LOW",
        "createdAt": TIMESTAMP_T1,
    }
    xsoar_incident = incident_to_xsoar_incident(incident, timeline_events=timeline)
    raw = json.loads(xsoar_incident["rawJSON"])

    assert raw["timelineEvents"] == timeline
    assert "vegaTimelineEvents" in raw
    assert xsoar_incident["CustomFields"]["vegatimelineevents"]
    assert "Test event." in xsoar_incident["CustomFields"]["vegatimelineevents"]


def test_fetch_incidents_command_fetches_timeline_details(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incidents.return_value = {
        "incidents": [{"id": "inc-1", "name": "Inc 1", "severity": "LOW", "createdAt": TIMESTAMP_T2}],
        "total": 1,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_incident_details.return_value = {
        "timelineEvents": [
            {
                "id": "evt-1",
                "timestamp": TIMESTAMP_T2,
                "summary": "Timeline summary.",
                "entities": [],
                "dataSources": [],
                "alert": None,
            }
        ],
        "keyFindings": ["Detail finding from Vega."],
    }
    mock_client.get_alerts.return_value = {"alerts": [], "total": 0, "limit": 200, "offset": 0}

    _, incidents = fetch_incidents_command(
        client=mock_client,
        last_run={},
        fetch_alerts=False,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        backfill_days=BACKFILL_DAYS,
    )

    assert len(incidents) == 1
    mock_client.get_incident_details.assert_called_once_with("inc-1")
    raw = json.loads(incidents[0]["rawJSON"])
    assert raw["timelineEvents"][0]["summary"] == "Timeline summary."
    assert raw["keyFindings"] == ["Detail finding from Vega."]
    assert "Detail finding from Vega." in raw["vegaIncidentFindings"]


def test_format_raw_entity_for_xsoar_prefers_key_findings():
    incident = {
        "incidentFindings": ["List finding"],
        "keyFindings": ["Detail finding"],
        "assets": [],
        "observables": [],
    }
    _format_raw_entity_for_xsoar(incident)

    assert "Detail finding" in incident["vegaIncidentFindings"]
    assert "List finding" not in incident["vegaIncidentFindings"]


def test_alert_to_incident_normalizes_api_link():
    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "severity": "HIGH",
        "createdAt": TIMESTAMP_T1,
        "link": "https://api.vega.io/incidents/alerts/alert-1",
    }
    raw = json.loads(alert_to_incident(alert)["rawJSON"])

    assert raw["link"] == "https://app.vega.io/incidents/alerts/alert-1"


def test_incident_to_xsoar_incident_normalizes_api_link():
    incident_id = "019e1b27-6d49-7ea1-a9d2-f2fe9227738f"
    incident = {
        "id": incident_id,
        "name": "Test Incident",
        "severity": "LOW",
        "createdAt": TIMESTAMP_T1,
        "link": f"https://api.vega.io/incidents/list/{incident_id}",
    }
    raw = json.loads(incident_to_xsoar_incident(incident)["rawJSON"])

    assert raw["link"] == f"https://app.vega.io/incidents/list/{incident_id}"
