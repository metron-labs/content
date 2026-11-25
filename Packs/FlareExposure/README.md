# Flare

Collects Flare threat exposure events into Cortex XSIAM.

This version covers ingestion, XDM normalization, and alert creation:

- The event collector polls the Flare API and writes `flare_events_raw`. **Fetch Via Alerts** loads each saved Flare alert and fetches tenant events with that alert's categories and severities. Leave **Fetch events** checked.
- The parsing rule sets `_time` to the time the event arrives. The Flare match time stays in `matched_at`.
- The modeling rule maps the event onto XDM and sets the Flare identifier as the case grouping key.
- Scheduled correlation rules open one alert per event, one rule per Flare severity.

**Enable Status Write-back - Auto Closure/Remediation** is not used by the event fetch. The playbook **Flare - Case Closure Status Write-back** marks the Flare events remediated when the case is resolved.

Vendor is `flare`, product is `events`, and the dataset is `flare_events_raw`. Alert names are `Flare - Critical`, `Flare - High`, `Flare - Medium`, `Flare - Low`, and `Flare - Info`.
