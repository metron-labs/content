Collects threat exposure events from Flare into Cortex XSIAM.

The instance exchanges the Flare API key for a token, polls the tenant event feed, and stores each event in `flare_exposure_events_raw`. Enable **Fetch full event** to also call the event endpoint and store its `data` block. Passwords are removed before an event is stored.

Enable **Fetch alerts** to read each saved Flare alert and then fetch events from the tenant feed using that alert's categories and severities. The instance severity and category are not sent. Only the initial backfill is applied. Each stored event keeps the alert id and name it came from.

Use a comma-separated list of numeric tenant IDs. Leave the tenant field empty to use the default tenant of the API key. Leave severity and category empty to ingest every event those tenants match.
