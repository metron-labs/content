## VegaReconcileIncidents

Reconcile Vega alerts and/or incidents against Cortex XSOAR for a **Vega source-system** time range.

### Purpose

Verify that every Vega Alert or Vega Incident created in Vega within the selected time range has a corresponding XSOAR incident. The automation reports results only; it does not create incidents.

Missing Vega IDs are returned as copyable lists so another command can create the corresponding XSOAR incidents.

### Inputs

| Argument | Description | Required |
| --- | --- | --- |
| start_time | Inclusive start of the Vega created-at range (ISO-8601 UTC). | True |
| end_time | Inclusive end of the Vega created-at range (ISO-8601 UTC). | True |
| object_type | `alerts`, `incidents`, or `both`. Default is `both`. | False |

### Behavior

- Fetches Vega objects with `vega-get-alerts` / `vega-get-incidents` using Vega created-at filters.
- Compares immutable Vega API IDs against XSOAR:
  - Alerts: `alertid`
  - Incidents: `vegaincidentid`
- Does **not** compare by XSOAR incident name or Vega display id (`vegaalertid`).
- Uses Vega source timestamp (`vegacreatedat` / Vega `createdAt`), not XSOAR `created`, for the selected range.
- Prints a human-readable reconciliation summary.
- Returns missing IDs as lists and as comma-separated CSV strings for follow-up commands.

### Outputs useful for follow-up creation

| Context path | Use |
| --- | --- |
| `Vega.Reconciliation.MissingAlertIDs` | List of missing Vega alert UUIDs |
| `Vega.Reconciliation.MissingAlertIDsCSV` | Copyable CSV for `alert_ids=` |
| `Vega.Reconciliation.MissingIncidentIDs` | List of missing Vega incident UUIDs |
| `Vega.Reconciliation.MissingIncidentIDsCSV` | Copyable CSV for `incident_ids=` |

Example follow-up:

```
!vega-get-alerts alert_ids=${Vega.Reconciliation.MissingAlertIDsCSV} prepare_incident=true
!vega-get-incidents incident_ids=${Vega.Reconciliation.MissingIncidentIDsCSV} prepare_incident=true
```

### Example

```
!VegaReconcileIncidents start_time="2026-09-01T00:00:00Z" end_time="2026-09-30T23:59:59Z" object_type=both
```

### Scheduling

Run manually from the War Room or schedule the automation/playbook through normal XSOAR mechanisms.
