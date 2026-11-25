Collects threat exposure events from Flare into Cortex XSIAM.

The instance exchanges the Flare API key for a token, polls the tenant event feed, and stores each event in `flare_events_raw`. Enable **Fetch full event** to also call the event endpoint and store its `data` block. Passwords are removed before an event is stored.

**Fetch Via Alerts** is optional. Leave **Fetch events** checked. The severity and category selected on this instance apply to **Fetch events** only. They are not applied to events collected with **Fetch Via Alerts**. For that option, the collector reads each saved Flare alert from the alerts API and uses that alert's own categories and severities. Those filters belong to the alert, including a custom group, and they decide which events are fetched. A disabled alert is skipped. Each stored event keeps the alert id and name it came from. A later switch continues from the last stored event instead of repeating the backfill.

Set **Instance tag** to a short name for this instance. The collector stores it on every event as `flare_instance_tag`, and the correlation rules copy it onto the issue. Filter events with `flare_instance_tag` and issues with `user_agent`.

Use a comma-separated list of numeric tenant IDs. Leave the tenant field empty to use the default tenant of the API key. Leave severity and category empty to ingest every event from **Fetch events**. **Fetch events** stays selected. **Fetch Via Alerts** is the next option.

**Enable Direct Alert Promotion** is optional. Leave it off to let the correlation rules open the issues. When it is checked, fill in the XSIAM server URL, API key, and API key ID first. Each stored event still goes into the dataset, and the collector also opens one XSIAM alert for it. If this checkbox is on while the correlation rules are also enabled, the same Flare event opens two issues and can create duplicate cases.

**Enable Status Write-back - Auto Closure/Remediation** is not used by the event fetch. The playbook **Flare - Case Closure Status Write-back** runs when a Flare case is resolved and marks the Flare events on that case as remediated. The command `flare-update-event-status` does the same update for one event id or one case id.
