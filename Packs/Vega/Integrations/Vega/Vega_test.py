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
    _format_incident_findings,
    _format_raw_entity_for_xsoar,
    _update_fetch_state,
    alert_to_incident,
    fetch_incidents_command,
    incident_to_xsoar_incident,
    parse_backfill_history,
    validate_backfill_history_days,
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
TIMESTAMP_T1 = "2026-06-01T10:00:00Z"
TIMESTAMP_T2 = "2026-06-01T11:00:00Z"


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
    )

    assert incidents == []
    assert next_run["alerts_last_fetch"] == TIMESTAMP_T1
    assert set(next_run["alerts_last_ids"]) == {"alert-1"}


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
    )

    assert len(incidents) == 2
    assert mock_client.get_incidents.call_count == 2
    assert next_run["incidents_last_fetch"] == TIMESTAMP_T2
    assert next_run["incidents_last_ids"] == ["inc-2"]


def test_parse_backfill_history_today(mocker):
    fixed_now = datetime(2026, 6, 2, 15, 30, 0, tzinfo=UTC)
    mocker.patch("Vega.datetime", wraps=datetime)
    mocker.patch("Vega.datetime.now", return_value=fixed_now)

    assert parse_backfill_history(0) == "2026-06-02T00:00:00Z"


def test_parse_backfill_history_days(mocker):
    fixed_now = datetime(2026, 6, 2, 15, 30, 0, tzinfo=UTC)
    mocker.patch("Vega.datetime", wraps=datetime)
    mocker.patch("Vega.datetime.now", return_value=fixed_now)

    assert parse_backfill_history(7) == "2026-05-26T00:00:00Z"


def test_parse_backfill_history_defaults(mocker):
    fixed_now = datetime(2026, 6, 2, 15, 30, 0, tzinfo=UTC)
    mocker.patch("Vega.datetime", wraps=datetime)
    mocker.patch("Vega.datetime.now", return_value=fixed_now)

    assert parse_backfill_history(None) == "2026-05-03T00:00:00Z"


def test_validate_backfill_history_days_rejects_out_of_range():
    with pytest.raises(ValueError, match="between 0 and 365"):
        validate_backfill_history_days(500)
    with pytest.raises(ValueError, match="between 0 and 365"):
        validate_backfill_history_days(-5)
    with pytest.raises(ValueError, match="must be an integer"):
        validate_backfill_history_days("not-a-number")


def test_parse_backfill_history_legacy_first_fetch():
    result = parse_backfill_history(None, legacy_first_fetch="7 days")
    parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert (datetime.now(UTC) - parsed).days >= 6


def test_format_bullet_list():
    assert _format_bullet_list(["CloudTrail", "VPC Flow Logs"]) == "• CloudTrail\n• VPC Flow Logs"
    assert _format_bullet_list([]) == []
    assert _format_bullet_list(None) is None
    assert _format_bullet_list("already formatted") == "already formatted"


def test_format_incident_findings_numbered_and_highlighted():
    findings = [
        "Suspicious activity from 10.0.0.1",
        "Domain evil.com contacted by host",
    ]
    assets = ["10.0.0.1"]
    observables = ["evil.com"]

    result = _format_incident_findings(findings, assets, observables)

    assert result == ("1. Suspicious activity from `10.0.0.1`\n" "2. Domain `evil.com` contacted by host")


def test_format_raw_entity_for_xsoar_alert():
    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "dataSources": ["CloudTrail", "GuardDuty"],
    }
    _format_raw_entity_for_xsoar(alert)

    assert alert["dataSources"] == "• CloudTrail\n• GuardDuty"
    assert set(alert.keys()) == {"id", "name", "dataSources"}


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
    assert incident["incidentFindings"] == "1. Instance `i-12345` connected to `10.0.0.1`"


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
    assert set(raw.keys()) == {
        "id",
        "name",
        "severity",
        "createdAt",
        "dataSources",
        "vegaEntityType",
        "link",
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
    assert raw["incidentFindings"] == "1. Activity detected on `host-1`"
    assert "link" not in raw


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
