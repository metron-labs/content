Collects threat exposure events from Flare into Cortex XSIAM.

The instance exchanges the Flare API key for a token, polls the tenant event feed, and stores each event in `flare_exposure_events_raw`. Enable **Fetch full event** to also call the event endpoint and store its `data` block. Passwords are removed before an event is stored.

Enable **Fetch Via Alerts** to read each saved Flare alert and then fetch events from the tenant feed using that alert's categories and severities. The instance severity and category are not sent. A later switch continues from the last stored event instead of repeating the backfill. Each stored event keeps the alert id and name it came from.

Set **Instance tag** to a short name for this instance. The collector stores it on every event as `flare_instance_tag`, and the correlation rules copy it to the issue as the agent id. Filter events with `flare_instance_tag` and issues with `agent_id`.

Use a comma-separated list of numeric tenant IDs. Leave the tenant field empty to use the default tenant of the API key. Leave severity and category empty to ingest every event those tenants match. **Fetch events** stays selected. **Fetch Via Alerts** is the next option. **Enable Direct Alert Promotion** opens one issue per stored event. Leave it off to let the correlation rules open the issues.
