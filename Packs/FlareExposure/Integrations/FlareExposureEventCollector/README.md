Flare exposure event collector for Cortex XSIAM.
This collector uses the Flare firework v4 tenant event feed.

The dataset, vendor, and product names are `flare_events_raw`, `flare`, and `events`.

## Configure Flare on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**.
2. Search for Flare.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Instance tag | Text stored on every event. Filter events, issues, and cases by this value. | False |
    | Server URL | Flare API base URL. Default is https://api.flare.io. | False |
    | API Key | Flare API key from the profile page. | True |
    | Flare tenants | Comma-separated numeric tenant IDs. Empty uses the key's default tenant. | False |
    | XSIAM server URL | Cortex API URL. Required for direct alert promotion and for the case-closure playbook. | False |
    | XSIAM API Key | Cortex API key. Required for direct alert promotion and for the case-closure playbook. | False |
    | XSIAM API Key ID | Cortex API key ID. Required for direct alert promotion and for the case-closure playbook. | False |
    | Flare severity | Severities to ingest. Empty ingests all. | False |
    | Flare category | The four Flare categories, plus one entry per subtype such as `open_web.paste`. A category selects every subtype in that group. A dotted entry selects that one subtype. Empty ingests all. | False |
    | Initial backfill | First-fetch window. Default is 30 days. Maximum is 180 days. | False |
    | Maximum number of events per fetch | Events stored in one cycle. Default is 50. Maximum is 500. | False |
    | Events Fetch Interval | Minutes between fetches. Default is 10. | False |
    | Fetch full event | Store the event data block. Off stores the feed record only. | False |
    | Fetch events | Stores every event in the dataset. Leave this checked. First Collect option. | False |
    | Fetch Via Alerts | Read saved Flare alerts, then fetch tenant events with each alert's categories and severities. Shown directly under Fetch events. Leave Fetch events checked. | False |
    | Enable Direct Alert Promotion | Stores each event and opens one XSIAM alert through the Cortex alerts API. Leave this off to use the correlation rules. Do not use both. | False |
    | Enable Status Write-back - Auto Closure/Remediation | Not used by the event fetch. The case-closure playbook updates Flare when the case is resolved. | False |
    | Trust any certificate (not secure) | Skip certificate verification. | False |
    | Use system proxy settings | Use the XSIAM system proxy. | False |

4. Click **Test** to validate the API key and connectivity.

## What gets stored

Each fetch exchanges the API key for a token at `POST /tokens/generate`, then reads `POST /firework/v4/events/tenant/_search`. When **Fetch full event** is enabled, each result is also read from `GET /firework/v4/events/?uid=` and the `data` block is stored on the event. Passwords are removed before the event is stored.

When **Fetch Via Alerts** is enabled, leave **Fetch events** checked. The collector lists `GET /firework/v4/alerts/` and then calls `POST /firework/v4/events/tenant/_search` once per category on each enabled alert. The open tenant feed search is not called. `search_types` is sent as `type`, and `risks` is sent as `severity` (`1` info, `2` low, `3` medium, `4` high, `5` critical). The instance severity and category settings are not sent. Each stored event includes `flare_alert_id` and `flare_alert_name`. Each category on an alert keeps its own timestamp. A category added to an alert after the first run, and an alert that appears after the first run, start at the global timestamp. The global timestamp is the newest event stored by any category. Parsing, modeling, and the correlation rules are unchanged apart from the instance tag.

The next fetch starts at the timestamp of the last event stored for that tenant. Changing severity or category starts that tenant from the current time instead of replaying the backfill.

## Alerts and cases

Five scheduled correlation rules query `flare_events_raw` every 10 minutes. Each rule matches one Flare severity for events stored in the last 24 hours, so one event opens one alert when it arrives, including a backfill of older Flare matches. A repeated event id is suppressed for 24 hours. The Flare match time stays in `matched_at`.

**Enable Direct Alert Promotion** is the other way to open an alert. The fetch still writes `flare_events_raw`, then calls `POST /public_api/v1/alerts/create_alert` once per event. That call uses the XSIAM server URL, API key, and API key ID. The alert name is the Flare identifier. `host_name` and `os_parent_user_name` carry that same identifier so Medium and higher issues can group into one case. Leave the checkbox off when the correlation rules are enabled, or the same event opens two alerts.

**Enable Status Write-back - Auto Closure/Remediation** is not used by the event fetch. When a Flare case is resolved, the playbook **Flare - Case Closure Status Write-back** calls `flare-update-event-status` with the case id. That command reads the alerts on the case and sends `POST /firework/v4/events/actions` with action `remediate`. The fetch interval does not delay this update.

The alert field **Actor Effective Username** is set to the Flare identifier name (`xdm.target.resource.name`). To put multiple alerts for the same identifier into one case, configure XSIAM case grouping on that actor field. The content pack does not create the grouping policy. Alerts with no Flare identifier use the Flare event id, so they are not grouped together under an empty name.

## Commands

### flare-get-events

Retrieves events on demand. This command does not move the scheduled fetch cursor.

#### Base Command

`flare-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set to true to store the events. Default is false. | Required |
| limit | Maximum number of events to return. Default is 10. | Optional |
| from | How far back to read, for example 12 hours or 7 days. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

`!flare-get-events should_push_events=false limit=10 from="7 days"`

### flare-get-event-details

Retrieves one Flare event, including its data block. Password fields are removed.

#### Base Command

`flare-get-event-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | Flare event id. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flare.Event | Unknown | The Flare event with password fields removed. |

#### Command example

`!flare-get-event-details event_id="driller/driller_github/testbench_source_code_2026-11-05"`

### flare-get-profile

Retrieves the Flare account profile for the configured API key.

#### Base Command

`flare-get-profile`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flare.Profile | Unknown | The Flare account profile. |

#### Command example

`!flare-get-profile`

### flare-get-tenants

Lists the Flare tenants the configured API key can access.

#### Base Command

`flare-get-tenants`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flare.Tenant | Unknown | Flare tenants the API key can access. |

#### Command example

`!flare-get-tenants`

### flare-get-credentials

Retrieves one page of leaked credentials for a Flare tenant. Password fields are removed. Pass the `from` value printed as "Next page" to read the following page.

#### Base Command

`flare-get-credentials`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | Flare tenant id. Defaults to the first tenant configured on the instance. | Optional |
| limit | Maximum number of credentials to return. Default is 20. Maximum is 100. | Optional |
| from | Page cursor returned by the previous call. Leave empty to read the first page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flare.Credential | Unknown | Leaked credentials with password fields removed. |

#### Command example

`!flare-get-credentials tenant_id="747671" limit=20`
