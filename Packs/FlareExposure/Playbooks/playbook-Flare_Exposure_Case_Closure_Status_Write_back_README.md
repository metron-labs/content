Marks the Flare events on the current case as remediated.

Run this playbook on a Flare Exposure case. It calls `flare-update-event-status` with the case id. The command reads the alerts on that case and sends each Flare event id to Flare as remediated.

The instance checkbox **Enable Status Write-back - Auto Closure/Remediation** does the same update on the next fetch after a case is closed. This playbook is the on-demand path and does not require the checkbox.
