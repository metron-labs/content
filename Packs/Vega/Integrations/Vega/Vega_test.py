import json
import time

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from Vega import (
    Client,
    alert_to_incident,
    convert_severity_to_xsoar,
    fetch_incidents,
    incident_to_xsoar_incident,
    test_module as vega_test_module,
)

MOCK_JWT_RESPONSE = {
    "session_jwt": "mock-jwt-token",
    "session_max_age": 1999999999,  # Far in the future
    "error": "",
}


def test_convert_severity_to_xsoar():
    assert convert_severity_to_xsoar("low") == 1
    assert convert_severity_to_xsoar("MEDIUM") == 2
    assert convert_severity_to_xsoar("high") == 3
    assert convert_severity_to_xsoar("CRITICAL") == 4
    assert convert_severity_to_xsoar("UNKNOWN") == 0


def test_alert_to_incident():
    alert = {
        "id": "alert-1",
        "name": "Test Alert Name",
        "severity": "HIGH",
        "createdAt": "2026-05-21T15:00:00Z",
    }
    incident = alert_to_incident(alert)
    assert incident["name"] == "Test Alert Name"
    assert incident["occurred"] == "2026-05-21T15:00:00Z"
    assert incident["severity"] == 3
    assert incident["type"] == "Vega Alert"
    assert json.loads(incident["rawJSON"]) == alert


def test_incident_to_xsoar_incident():
    inc = {
        "id": "inc-1",
        "name": "Test Incident Name",
        "severity": "CRITICAL",
        "createdAt": "2026-05-21T16:00:00Z",
    }
    xsoar_inc = incident_to_xsoar_incident(inc)
    assert xsoar_inc["name"] == "Test Incident Name"
    assert xsoar_inc["occurred"] == "2026-05-21T16:00:00Z"
    assert xsoar_inc["severity"] == 4
    assert xsoar_inc["type"] == "Vega Incident"
    assert json.loads(xsoar_inc["rawJSON"]) == inc


def test_test_module(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(f"{BASE_URL}/query", json={"data": {"getAccessKey": {"id": "mock-key-id", "roles": ["security admin"]}}})

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

    requests_mock.post(f"{BASE_URL}/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(f"{BASE_URL}/query", json={"data": {"getAccessKey": {"id": "mock-key-id", "roles": ["Viewer"]}}})

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == "you do not have required access to fetch incidents"


def test_test_module_incorrect_access_key_id(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(
        f"{BASE_URL}/query",
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
    assert vega_test_module(client) == "incorrect access key id"


def test_test_module_incorrect_access_key(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/login_machine", status_code=500)

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="wrong-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == "Incorrect Access Key. Please Check your Credentials."


def test_get_session_jwt_caching(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    login_mock = requests_mock.post(f"{BASE_URL}/login_machine", json=MOCK_JWT_RESPONSE)

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
    )

    # First call - logins
    jwt1 = client._get_session_jwt()
    assert jwt1 == "mock-jwt-token"
    assert login_mock.call_count == 1

    # Second call - returns cached JWT from instance variables
    jwt2 = client._get_session_jwt()
    assert jwt2 == "mock-jwt-token"
    assert login_mock.call_count == 1


def test_get_session_jwt_expired(requests_mock, mocker):
    mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={"session_jwt": "old-token", "session_expiry": int(time.time()) - 10},
    )
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    login_mock = requests_mock.post(f"{BASE_URL}/login_machine", json=MOCK_JWT_RESPONSE)

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
    )

    jwt = client._get_session_jwt()
    assert jwt == "mock-jwt-token"
    assert login_mock.call_count == 1


def test_fetch_incidents_alerts(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/login_machine", json=MOCK_JWT_RESPONSE)

    alerts_response = {
        "data": {
            "getAlerts": {
                "alerts": [
                    {
                        "id": "alert-1",
                        "name": "Alert 1",
                        "severity": "LOW",
                        "createdAt": "2026-05-21T15:00:00Z",
                    },
                    {
                        "id": "alert-2",
                        "name": "Alert 2",
                        "severity": "MEDIUM",
                        "createdAt": "2026-05-21T15:10:00Z",
                    },
                ],
                "error": None,
            }
        }
    }

    requests_mock.post(f"{BASE_URL}/query", json=alerts_response)

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
    )

    params = {
        "fetch_alerts": True,
        "fetch_incidents_flag": False,
        "max_fetch": 50,
        "first_fetch": "3 days",
    }

    last_run = {}

    incidents, next_run = fetch_incidents(client, params, last_run)

    assert len(incidents) == 2
    assert incidents[0]["name"] == "Alert 1"
    assert incidents[1]["name"] == "Alert 2"

    assert next_run["alerts_last_fetch"] == "2026-05-21T15:10:00Z"
    assert next_run["alerts_processed_ids"] == ["alert-2"]


def test_fetch_incidents_items(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/login_machine", json=MOCK_JWT_RESPONSE)

    incidents_response = {
        "data": {
            "getIncidents": {
                "incidents": [
                    {
                        "id": "inc-1",
                        "name": "Incident 1",
                        "severity": "HIGH",
                        "createdAt": "2026-05-21T15:00:00Z",
                    }
                ],
                "error": None,
            }
        }
    }

    requests_mock.post(f"{BASE_URL}/query", json=incidents_response)

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
    )

    params = {
        "fetch_alerts": False,
        "fetch_incidents_flag": True,
        "max_fetch": 50,
        "first_fetch": "3 days",
    }

    last_run = {}

    incidents, next_run = fetch_incidents(client, params, last_run)

    assert len(incidents) == 1
    assert incidents[0]["name"] == "Incident 1"
    assert next_run["incidents_last_fetch"] == "2026-05-21T15:00:00Z"
    assert next_run["incidents_processed_ids"] == ["inc-1"]


def test_fetch_incidents_deduplication(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/login_machine", json=MOCK_JWT_RESPONSE)

    # Mock response containing two alerts, one has the same createdAt as the last fetch and is in the processed list
    alerts_response = {
        "data": {
            "getAlerts": {
                "alerts": [
                    {
                        "id": "alert-1",
                        "name": "Alert 1 (Old)",
                        "severity": "LOW",
                        "createdAt": "2026-05-21T15:00:00Z",
                    },
                    {
                        "id": "alert-2",
                        "name": "Alert 2 (New)",
                        "severity": "MEDIUM",
                        "createdAt": "2026-05-21T15:00:00Z",
                    },
                    {
                        "id": "alert-3",
                        "name": "Alert 3 (Newer)",
                        "severity": "HIGH",
                        "createdAt": "2026-05-21T15:10:00Z",
                    },
                ],
                "error": None,
            }
        }
    }

    requests_mock.post(f"{BASE_URL}/query", json=alerts_response)

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
    )

    params = {
        "fetch_alerts": True,
        "fetch_incidents_flag": False,
        "max_fetch": 50,
        "first_fetch": "3 days",
    }

    # last run says we fetched up to 15:00:00Z, and processed "alert-1" already
    last_run = {
        "alerts_last_fetch": "2026-05-21T15:00:00Z",
        "alerts_processed_ids": ["alert-1"],
    }

    incidents, next_run = fetch_incidents(client, params, last_run)

    # Should only process alert-2 and alert-3 (alert-1 is filtered out because it is in processed_ids)
    assert len(incidents) == 2
    assert incidents[0]["name"] == "Alert 2 (New)"
    assert incidents[1]["name"] == "Alert 3 (Newer)"

    assert next_run["alerts_last_fetch"] == "2026-05-21T15:10:00Z"
    assert next_run["alerts_processed_ids"] == ["alert-3"]
