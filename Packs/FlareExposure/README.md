# Flare Exposure

Collects Flare threat exposure events into Cortex XSIAM.

This first version covers ingestion, XDM normalization, and alert creation:

- The event collector polls the Flare API and writes `flare_exposure_events_raw`. **Fetch alerts** loads each saved Flare alert and fetches tenant events with that alert's categories and severities.
- The parsing rule sets `_time` from `matched_at`.
- The modeling rule maps the event onto XDM and sets the Flare identifier as the case grouping key.
- Real-time correlation rules open one alert per event, one rule per Flare severity.

Playbooks, status write-back, and the indicator feed are not part of this version.

These names stay clear of an existing `flare_events_raw` pipeline: vendor `flare`, product `exposure`, dataset `flare_exposure_events_raw`, alert names `Flare Exposure - Critical`, `Flare Exposure - High`, `Flare Exposure - Medium`, `Flare Exposure - Low`, and `Flare Exposure - Info`.
