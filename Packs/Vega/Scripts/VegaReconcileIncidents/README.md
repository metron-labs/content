## VegaReconcileIncidents

Reconcile Vega alerts and/or incidents against Cortex XSOAR for a **Vega source-system** time range.

### Purpose

Verify that every Vega Alert or Vega Incident created in Vega within the selected time range has a corresponding XSOAR incident. Optionally recover missing incidents using the same mapping as the Vega integration fetch path.

### Inputs

| Argument | Description | Required |
| --- | --- | --- |
| start_time | Inclusive start of the Vega created-at range (ISO-8601 UTC). | True |
| end_time | Inclusive end of the Vega created-at range (ISO-8601 UTC). | True |
| object_type | `alerts`, `incidents`, or `both`. Default is `both`. | False |
| create_missing | When `false` (default), report only. When `true`, create missing XSOAR incidents. | False |

### Behavior

- Fetches Vega objects with `vega-get-alerts` / `vega-get-incidents` using Vega created-at filters.
- Compares immutable Vega API IDs against XSOAR:
  - Alerts: `alertid`
  - Incidents: `vegaincidentid`
- Does **not** compare by XSOAR incident name or Vega display id (`vegaalertid`).
- Uses Vega source timestamp (`vegacreatedat` / Vega `createdAt`), not XSOAR `created`, for the selected range.
- With `create_missing=true`, re-fetches missing IDs with `prepare_incident=true` and creates incidents via `createNewIncident` using the existing Vega → XSOAR mapping.

### Example

```
!VegaReconcileIncidents start_time="2026-09-01T00:00:00Z" end_time="2026-09-30T23:59:59Z" object_type=both create_missing=false
```

### Scheduling

Run manually from the War Room or schedule the automation/playbook through normal XSOAR mechanisms.
