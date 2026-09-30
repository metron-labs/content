import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any

OBJECT_TYPE_ALERTS = "alerts"
OBJECT_TYPE_INCIDENTS = "incidents"
OBJECT_TYPE_BOTH = "both"
VALID_OBJECT_TYPES = frozenset({OBJECT_TYPE_ALERTS, OBJECT_TYPE_INCIDENTS, OBJECT_TYPE_BOTH})

XSOAR_TYPE_ALERT = "Vega Alert"
XSOAR_TYPE_INCIDENT = "Vega Incident"

ALERT_ID_FIELD = "alertid"
INCIDENT_ID_FIELD = "vegaincidentid"

# Wide fromdate so incidents created later in XSOAR are still found by Vega ID.
XSOAR_SEARCH_FROMDATE = "50 years ago"
XSOAR_ID_QUERY_BATCH_SIZE = 50
DEFAULT_SEARCH_LIMIT = 10000


def _require_time_arg(args: dict[str, Any], key: str) -> str:
    """Return a required non-empty time argument."""
    value = args.get(key)
    if value is None or not str(value).strip():
        raise DemistoException(f"{key} is required and must be a non-empty ISO-8601 timestamp.")
    return str(value).strip()


def _parse_object_type(args: dict[str, Any]) -> str:
    """Validate and normalize object_type."""
    raw = str(args.get("object_type") or OBJECT_TYPE_BOTH).strip().lower()
    if raw not in VALID_OBJECT_TYPES:
        raise DemistoException(f"object_type must be one of: {', '.join(sorted(VALID_OBJECT_TYPES))}. Got: {raw}")
    return raw


def _execute_command(command: str, args: dict[str, Any]) -> list[dict[str, Any]]:
    """Execute an XSOAR command and raise on error entries."""
    results = demisto.executeCommand(command, args)
    if not results:
        raise DemistoException(f"Command {command} returned no results.")
    if not isinstance(results, list):
        results = [results]
    for entry in results:
        if is_error(entry):
            raise DemistoException(f"Command {command} failed: {get_error(entry)}")
    return results


def _context_values(results: list[dict[str, Any]], path: str) -> list[Any]:
    """Collect context values for a path from command result entries."""
    values: list[Any] = []
    for entry in results:
        entry_context = entry.get("EntryContext") or {}
        if not isinstance(entry_context, dict):
            continue

        matched = entry_context.get(path)
        if matched is None:
            # Integration outputs may be stored under indicator-style keys.
            for key, value in entry_context.items():
                if key == path or str(key).startswith(f"{path}("):
                    matched = value
                    break
        if matched is None:
            try:
                matched = demisto.dt(entry_context, path)
            except Exception:
                matched = demisto.get(entry_context, path)

        if matched is None:
            continue
        if isinstance(matched, list):
            values.extend(matched)
        else:
            values.append(matched)
    return values


def _extract_vega_entities_from_get_command(results: list[dict[str, Any]], outputs_prefix: str) -> list[dict[str, Any]]:
    """Extract Vega entity dicts from vega-get-* command results."""
    entities = _context_values(results, outputs_prefix)
    if entities:
        return [entity for entity in entities if isinstance(entity, dict)]

    # Fallback: Contents may hold the raw entity list when context is empty.
    for entry in results:
        contents = entry.get("Contents")
        if isinstance(contents, list):
            return [entity for entity in contents if isinstance(entity, dict)]
        if isinstance(contents, dict):
            nested = contents.get("alerts") or contents.get("incidents")
            if isinstance(nested, list):
                return [entity for entity in nested if isinstance(entity, dict)]
    return []


def _normalize_id(value: Any) -> str:
    """Normalize a Vega object id to a comparable string."""
    if value is None:
        return ""
    return str(value).strip()


def _collect_vega_ids(entities: list[dict[str, Any]]) -> tuple[set[str], list[str]]:
    """Return unique Vega IDs and a list of malformed/missing ID warnings."""
    ids: set[str] = set()
    invalid: list[str] = []
    for entity in entities:
        entity_id = _normalize_id(entity.get("id"))
        if not entity_id:
            invalid.append(str(entity.get("name") or entity))
            continue
        ids.add(entity_id)
    return ids, invalid


def _incident_custom_fields(incident: dict[str, Any]) -> dict[str, Any]:
    """Return CustomFields for an XSOAR incident search hit."""
    custom_fields = incident.get("CustomFields") or incident.get("customFields") or {}
    return custom_fields if isinstance(custom_fields, dict) else {}


def _extract_xsoar_vega_id(incident: dict[str, Any], id_field: str) -> str:
    """Extract the immutable Vega object ID from an XSOAR incident."""
    custom_fields = _incident_custom_fields(incident)
    value = custom_fields.get(id_field)
    if value is None:
        value = incident.get(id_field)
    return _normalize_id(value)


def _extract_found_incidents(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract incidents from SearchIncidentsV2 command results."""
    found = _context_values(results, "foundIncidents")
    incidents = [item for item in found if isinstance(item, dict)]
    if incidents:
        return incidents

    for entry in results:
        contents = entry.get("Contents")
        if isinstance(contents, dict):
            data = contents.get("data")
            if isinstance(data, list):
                return [item for item in data if isinstance(item, dict)]
        if isinstance(contents, list):
            # SearchIncidentsV2 may wrap getIncidents results.
            for item in contents:
                if not isinstance(item, dict):
                    continue
                nested = item.get("Contents")
                if isinstance(nested, dict) and isinstance(nested.get("data"), list):
                    return [row for row in nested["data"] if isinstance(row, dict)]
    return []


def _query_xsoar_ids_for_vega_ids(
    incident_type: str,
    id_field: str,
    vega_ids: set[str],
) -> set[str]:
    """Query XSOAR for existing Vega object IDs among the provided set."""
    if not vega_ids:
        return set()

    found_ids: set[str] = set()
    ordered_ids = sorted(vega_ids)
    for start in range(0, len(ordered_ids), XSOAR_ID_QUERY_BATCH_SIZE):
        chunk = ordered_ids[start : start + XSOAR_ID_QUERY_BATCH_SIZE]
        id_clause = " ".join(f'"{entity_id}"' for entity_id in chunk)
        query = f'type:"{incident_type}" and {id_field}:({id_clause})'
        results = _execute_command(
            "SearchIncidentsV2",
            {
                "query": query,
                "fromdate": XSOAR_SEARCH_FROMDATE,
                "limit": str(max(DEFAULT_SEARCH_LIMIT, len(chunk) * 5)),
            },
        )
        for incident in _extract_found_incidents(results):
            vega_id = _extract_xsoar_vega_id(incident, id_field)
            if not vega_id:
                demisto.info(
                    f"Vega reconciliation: XSOAR incident {incident.get('id')} of type {incident_type} "
                    f"is missing searchable field {id_field}."
                )
                continue
            found_ids.add(vega_id)
    return found_ids


def _fetch_vega_alerts(start_time: str, end_time: str) -> list[dict[str, Any]]:
    """Fetch Vega alerts for the source-system time range."""
    results = _execute_command(
        "vega-get-alerts",
        {"from_time": start_time, "to_time": end_time, "prepare_incident": "false"},
    )
    return _extract_vega_entities_from_get_command(results, "Vega.Alert")


def _fetch_vega_incidents(start_time: str, end_time: str) -> list[dict[str, Any]]:
    """Fetch Vega incidents for the source-system time range."""
    results = _execute_command(
        "vega-get-incidents",
        {"from_time": start_time, "to_time": end_time, "prepare_incident": "false"},
    )
    return _extract_vega_entities_from_get_command(results, "Vega.Incident")


def _reconcile_object_type(
    *,
    object_label: str,
    incident_type: str,
    id_field: str,
    entities: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compare one Vega object type against XSOAR and report missing IDs."""
    vega_ids, invalid = _collect_vega_ids(entities)
    if invalid:
        demisto.info(f"Vega reconciliation: skipped {len(invalid)} {object_label} without a valid id.")

    xsoar_ids = _query_xsoar_ids_for_vega_ids(incident_type, id_field, vega_ids)
    missing_ids = sorted(vega_ids - xsoar_ids)
    missing_ids_csv = ",".join(missing_ids)

    return {
        "TotalInVega": len(vega_ids),
        "TotalInXSOAR": len(xsoar_ids),
        "MissingCount": len(missing_ids),
        "MissingIDs": missing_ids,
        "MissingIDsCSV": missing_ids_csv,
        "InvalidCount": len(invalid),
    }


def _format_missing_ids_block(title: str, missing_ids: list[str]) -> str:
    """Format a copyable missing-ID list for the War Room."""
    if not missing_ids:
        return f"{title}:\n(none)"
    csv_list = ",".join(missing_ids)
    lines = "\n".join(missing_ids)
    return (
        f"{title}:\n"
        f"Count: {len(missing_ids)}\n"
        f"Copyable CSV (for command args):\n{csv_list}\n"
        f"One ID per line:\n{lines}"
    )


def _format_section(title: str, stats: dict[str, Any] | None) -> str:
    """Format one object-type section of the reconciliation report."""
    if stats is None:
        return f"{title}:\nSkipped"
    return (
        f"{title}:\n"
        f"Found in Vega:        {stats.get('TotalInVega', 0)}\n"
        f"Found in XSOAR:       {stats.get('TotalInXSOAR', 0)}\n"
        f"Missing:              {stats.get('MissingCount', 0)}"
    )


def reconcile_incidents(args: dict[str, Any]) -> CommandResults:
    """Run Vega alert/incident reconciliation for a source-system time range."""
    start_time = _require_time_arg(args, "start_time")
    end_time = _require_time_arg(args, "end_time")
    object_type = _parse_object_type(args)

    alerts_stats: dict[str, Any] | None = None
    incidents_stats: dict[str, Any] | None = None

    if object_type in (OBJECT_TYPE_ALERTS, OBJECT_TYPE_BOTH):
        alert_entities = _fetch_vega_alerts(start_time, end_time)
        alerts_stats = _reconcile_object_type(
            object_label="alerts",
            incident_type=XSOAR_TYPE_ALERT,
            id_field=ALERT_ID_FIELD,
            entities=alert_entities,
        )

    if object_type in (OBJECT_TYPE_INCIDENTS, OBJECT_TYPE_BOTH):
        incident_entities = _fetch_vega_incidents(start_time, end_time)
        incidents_stats = _reconcile_object_type(
            object_label="incidents",
            incident_type=XSOAR_TYPE_INCIDENT,
            id_field=INCIDENT_ID_FIELD,
            entities=incident_entities,
        )

    missing_alert_ids = list((alerts_stats or {}).get("MissingIDs") or [])
    missing_incident_ids = list((incidents_stats or {}).get("MissingIDs") or [])
    missing_alert_ids_csv = ",".join(missing_alert_ids)
    missing_incident_ids_csv = ",".join(missing_incident_ids)

    outputs: dict[str, Any] = {
        "StartTime": start_time,
        "EndTime": end_time,
        "ObjectType": object_type,
        "MissingAlertIDs": missing_alert_ids,
        "MissingAlertIDsCSV": missing_alert_ids_csv,
        "MissingIncidentIDs": missing_incident_ids,
        "MissingIncidentIDsCSV": missing_incident_ids_csv,
    }
    if alerts_stats is not None:
        outputs["Alerts"] = alerts_stats
    if incidents_stats is not None:
        outputs["Incidents"] = incidents_stats

    readable = (
        "### Vega Reconciliation Results\n\n"
        f"Time Range:\n{start_time} → {end_time}\n\n"
        f"{_format_section('Vega Alerts', alerts_stats)}\n\n"
        f"{_format_section('Vega Incidents', incidents_stats)}\n\n"
        f"{_format_missing_ids_block('Missing Vega Alert IDs', missing_alert_ids)}\n\n"
        f"{_format_missing_ids_block('Missing Vega Incident IDs', missing_incident_ids)}\n\n"
        "Use the copyable CSV lists with follow-up commands, for example:\n"
        "`!vega-get-alerts alert_ids=<MissingAlertIDsCSV> prepare_incident=true`\n"
        "`!vega-get-incidents incident_ids=<MissingIncidentIDsCSV> prepare_incident=true`"
    )
    return CommandResults(
        readable_output=readable,
        outputs_prefix="Vega.Reconciliation",
        outputs_key_field=["StartTime", "EndTime", "ObjectType"],
        outputs=outputs,
    )


def main() -> None:
    try:
        return_results(reconcile_incidents(demisto.args()))
    except Exception as exc:
        return_error(f"Failed to execute VegaReconcileIncidents. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
