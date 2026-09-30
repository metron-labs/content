import pytest

import demistomock as demisto
from CommonServerPython import DemistoException

import VegaReconcileIncidents as reconcile


def _ok_entry(contents=None, entry_context=None):
    return {
        "Type": 1,
        "Contents": contents,
        "EntryContext": entry_context or {},
    }


def test_require_time_arg_rejects_empty():
    with pytest.raises(DemistoException, match="start_time is required"):
        reconcile._require_time_arg({}, "start_time")


def test_parse_object_type_default_and_invalid():
    assert reconcile._parse_object_type({}) == "both"
    assert reconcile._parse_object_type({"object_type": "ALERTS"}) == "alerts"
    with pytest.raises(DemistoException, match="object_type must be one of"):
        reconcile._parse_object_type({"object_type": "tickets"})


def test_collect_vega_ids_dedupes_and_tracks_invalid():
    entities = [
        {"id": "a-1", "name": "one"},
        {"id": "a-1", "name": "dup"},
        {"id": "", "name": "bad"},
        {"name": "missing"},
        {"id": "a-2"},
    ]
    ids, invalid = reconcile._collect_vega_ids(entities)
    assert ids == {"a-1", "a-2"}
    assert len(invalid) == 2


def test_reconcile_all_alerts_present(mocker):
    mocker.patch.object(
        reconcile,
        "_fetch_vega_alerts",
        return_value=[{"id": "a-1", "createdAt": "2026-09-01T00:00:00Z"}, {"id": "a-2", "createdAt": "2026-09-02T00:00:00Z"}],
    )
    mocker.patch.object(reconcile, "_fetch_vega_incidents", return_value=[])
    mocker.patch.object(reconcile, "_query_xsoar_ids_for_vega_ids", side_effect=[{"a-1", "a-2"}, set()])

    result = reconcile.reconcile_incidents(
        {
            "start_time": "2026-09-01T00:00:00Z",
            "end_time": "2026-09-30T23:59:59Z",
            "object_type": "both",
            "create_missing": "false",
        }
    )
    outputs = result.outputs
    assert outputs["Alerts"]["TotalInVega"] == 2
    assert outputs["Alerts"]["TotalInXSOAR"] == 2
    assert outputs["Alerts"]["MissingCount"] == 0
    assert outputs["Alerts"]["MissingIDs"] == []
    assert outputs["Incidents"]["TotalInVega"] == 0


def test_reconcile_missing_alerts_report_only(mocker):
    mocker.patch.object(
        reconcile,
        "_fetch_vega_alerts",
        return_value=[{"id": "a-1"}, {"id": "a-2"}, {"id": "a-3"}],
    )
    mocker.patch.object(reconcile, "_query_xsoar_ids_for_vega_ids", return_value={"a-1"})
    recover = mocker.patch.object(reconcile, "_recover_missing_alerts")

    result = reconcile.reconcile_incidents(
        {
            "start_time": "2026-09-01T00:00:00Z",
            "end_time": "2026-09-30T23:59:59Z",
            "object_type": "alerts",
            "create_missing": "false",
        }
    )
    assert result.outputs["Alerts"]["MissingCount"] == 2
    assert result.outputs["Alerts"]["MissingIDs"] == ["a-2", "a-3"]
    assert result.outputs["Alerts"]["RecoveredCount"] == 0
    recover.assert_not_called()
    assert "Incidents" not in result.outputs


def test_reconcile_missing_alerts_create_true(mocker):
    mocker.patch.object(
        reconcile,
        "_fetch_vega_alerts",
        return_value=[{"id": "a-1"}, {"id": "a-2"}],
    )
    mocker.patch.object(reconcile, "_query_xsoar_ids_for_vega_ids", return_value={"a-1"})
    mocker.patch.object(reconcile, "_recover_missing_alerts", return_value=(["a-2"], []))

    result = reconcile.reconcile_incidents(
        {
            "start_time": "2026-09-01T00:00:00Z",
            "end_time": "2026-09-30T23:59:59Z",
            "object_type": "alerts",
            "create_missing": "true",
        }
    )
    assert result.outputs["Alerts"]["RecoveredCount"] == 1
    assert result.outputs["Alerts"]["RecoveredIDs"] == ["a-2"]
    assert result.outputs["Alerts"]["FailedCount"] == 0


def test_reconcile_incidents_object_type(mocker):
    mocker.patch.object(
        reconcile,
        "_fetch_vega_incidents",
        return_value=[{"id": "i-1"}, {"id": "i-2"}],
    )
    mocker.patch.object(reconcile, "_query_xsoar_ids_for_vega_ids", return_value={"i-1"})
    mocker.patch.object(reconcile, "_recover_missing_incidents", return_value=(["i-2"], []))

    result = reconcile.reconcile_incidents(
        {
            "start_time": "2026-09-01T00:00:00Z",
            "end_time": "2026-09-15T00:00:00Z",
            "object_type": "incidents",
            "create_missing": "true",
        }
    )
    assert result.outputs["Incidents"]["MissingIDs"] == ["i-2"]
    assert result.outputs["Incidents"]["RecoveredCount"] == 1
    assert "Alerts" not in result.outputs


def test_reconcile_empty_vega_results(mocker):
    mocker.patch.object(reconcile, "_fetch_vega_alerts", return_value=[])
    mocker.patch.object(reconcile, "_fetch_vega_incidents", return_value=[])
    query = mocker.patch.object(reconcile, "_query_xsoar_ids_for_vega_ids", return_value=set())

    result = reconcile.reconcile_incidents(
        {
            "start_time": "2026-09-01T00:00:00Z",
            "end_time": "2026-09-30T23:59:59Z",
            "object_type": "both",
        }
    )
    assert result.outputs["Alerts"]["TotalInVega"] == 0
    assert result.outputs["Incidents"]["TotalInVega"] == 0
    assert query.call_count == 2


def test_reconcile_empty_xsoar_results(mocker):
    mocker.patch.object(reconcile, "_fetch_vega_alerts", return_value=[{"id": "a-1"}])
    mocker.patch.object(reconcile, "_query_xsoar_ids_for_vega_ids", return_value=set())

    result = reconcile.reconcile_incidents(
        {
            "start_time": "2026-09-01T00:00:00Z",
            "end_time": "2026-09-30T23:59:59Z",
            "object_type": "alerts",
            "create_missing": "false",
        }
    )
    assert result.outputs["Alerts"]["TotalInXSOAR"] == 0
    assert result.outputs["Alerts"]["MissingIDs"] == ["a-1"]


def test_query_xsoar_ids_batches_and_extracts(mocker):
    ids = [f"id-{index}" for index in range(55)]
    responses = [
        [_ok_entry(entry_context={"foundIncidents": [{"id": "1", "CustomFields": {"alertid": "id-0"}}]})],
        [_ok_entry(entry_context={"foundIncidents": [{"CustomFields": {"alertid": "id-50"}}]})],
    ]
    execute = mocker.patch.object(reconcile, "_execute_command", side_effect=responses)
    found = reconcile._query_xsoar_ids_for_vega_ids("Vega Alert", "alertid", set(ids))
    assert found == {"id-0", "id-50"}
    assert execute.call_count == 2


def test_execute_command_raises_on_error(mocker):
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Type": 4, "Contents": "boom", "HumanReadable": "boom"}],
    )
    mocker.patch.object(reconcile, "is_error", return_value=True)
    mocker.patch.object(reconcile, "get_error", return_value="boom")
    with pytest.raises(DemistoException, match="failed"):
        reconcile._execute_command("vega-get-alerts", {})


def test_recover_missing_alerts_creates_once(mocker):
    mocker.patch.object(reconcile, "_query_xsoar_ids_for_vega_ids", side_effect=[set(), set()])
    mocker.patch.object(
        reconcile,
        "_execute_command",
        return_value=[
            _ok_entry(
                entry_context={
                    "Vega.Alert": [
                        {
                            "id": "a-missing",
                            "xsoarIncident": {
                                "name": "Alert",
                                "type": "Vega Alert",
                                "rawJSON": "{}",
                                "CustomFields": {"alertid": "a-missing"},
                            },
                        }
                    ]
                }
            )
        ],
    )
    create = mocker.patch.object(reconcile, "_create_xsoar_incident", return_value="100")
    recovered, failed = reconcile._recover_missing_alerts(["a-missing"], "2026-09-01T00:00:00Z")
    assert recovered == ["a-missing"]
    assert failed == []
    create.assert_called_once()


def test_recover_missing_alerts_partial_failure(mocker):
    mocker.patch.object(reconcile, "_query_xsoar_ids_for_vega_ids", return_value=set())
    mocker.patch.object(
        reconcile,
        "_execute_command",
        return_value=[
            _ok_entry(
                entry_context={
                    "Vega.Alert": [
                        {
                            "id": "a-ok",
                            "xsoarIncident": {"name": "ok", "type": "Vega Alert", "rawJSON": "{}"},
                        }
                    ]
                }
            )
        ],
    )

    def create_side_effect(prepared):
        if prepared.get("name") == "ok":
            return "1"
        raise DemistoException("create failed")

    mocker.patch.object(reconcile, "_create_xsoar_incident", side_effect=create_side_effect)
    # Second ID missing from Vega response -> failed
    recovered, failed = reconcile._recover_missing_alerts(["a-ok", "a-missing"], None)
    assert recovered == ["a-ok"]
    assert failed == ["a-missing"]


def test_recover_skips_duplicate_when_present_before_create(mocker):
    # First batch presence check: empty. Final per-id check: already present.
    mocker.patch.object(reconcile, "_query_xsoar_ids_for_vega_ids", side_effect=[set(), {"a-1"}])
    mocker.patch.object(
        reconcile,
        "_execute_command",
        return_value=[
            _ok_entry(
                entry_context={
                    "Vega.Alert": [{"id": "a-1", "xsoarIncident": {"name": "Alert", "type": "Vega Alert", "rawJSON": "{}"}}]
                }
            )
        ],
    )
    create = mocker.patch.object(reconcile, "_create_xsoar_incident")
    recovered, failed = reconcile._recover_missing_alerts(["a-1"], None)
    assert recovered == ["a-1"]
    assert failed == []
    create.assert_not_called()


def test_main_returns_error(mocker):
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(reconcile, "reconcile_incidents", side_effect=DemistoException("bad"))
    return_error = mocker.patch.object(reconcile, "return_error")
    reconcile.main()
    return_error.assert_called_once()
