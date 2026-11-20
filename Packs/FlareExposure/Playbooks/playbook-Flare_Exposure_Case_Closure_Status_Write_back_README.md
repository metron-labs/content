Marks the Flare events on a resolved Flare Exposure case as remediated.

Run this playbook on the case when its status changes to Resolved. It checks that the status contains `resolved`, then calls `flare-update-event-status` with the case id. The command reads the alerts on that case and sends each Flare event id to Flare as remediated.

The event fetch does not send this update. The playbook does not wait for the next fetch.
