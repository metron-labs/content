Flare exposure event collector for Cortex XSIAM.
This collector uses the Flare firework v4 tenant event feed.

The dataset, vendor, and product names are `flare_exposure_events_raw`, `flare`, and `exposure`. They are intentionally different from an existing `flare_events_raw` pipeline so the two can run side by side.

## Configure Flare Exposure Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**.
2. Search for Flare Exposure Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | Flare API base URL. Default is https://api.flare.io. | False |
    | API Key | Flare API key from the profile page. | True |
    | Flare tenants | Comma-separated numeric tenant IDs. Empty uses the key's default tenant. | False |
    | Flare severity | Severities to ingest. Empty ingests all. | False |
    | Flare category | Feed categories to ingest. Empty ingests all. | False |
    | Initial backfill | First-fetch window. Default is 30 days. Maximum is 180 days. | False |
    | Maximum number of events per fetch | Events stored in one cycle. Default is 50. Maximum is 500. | False |
    | Fetch full event | Store the event data block. Off stores the feed record only. | False |
    | Fetch alerts | Read saved Flare alerts, then fetch tenant events with each alert's categories, severities, and the backfill. | False |
    | Fetch events | Enables scheduled collection. | False |
    | Events Fetch Interval | Minutes between fetches. Default is 10. | False |
    | Trust any certificate (not secure) | Skip certificate verification. | False |
    | Use system proxy settings | Use the XSIAM system proxy. | False |

4. Click **Test** to validate the API key and connectivity.

## What gets stored

Each fetch exchanges the API key for a token at `POST /tokens/generate`, then reads `POST /firework/v4/events/tenant/_search`. When **Fetch full event** is enabled, each result is also read from `GET /firework/v4/events/?uid=` and the `data` block is stored on the event. Passwords are removed before the event is stored.

When **Fetch alerts** is enabled, the collector lists `GET /firework/v4/alerts/` and then calls `POST /firework/v4/events/tenant/_search` once per alert. `search_types` is sent as `type`, and `risks` is sent as `severity` (`1` info, `2` low, `3` medium, `4` high, `5` critical). The only extra filter is the initial backfill. The instance severity and category settings are not sent. Each stored event includes `flare_alert_id` and `flare_alert_name`. Parsing, modeling, and the correlation rules are unchanged.

The cursor is the Flare `next` token, saved per tenant after a successful push. The same `matched_at` filter is reused on later fetches, which is what the Flare paging contract requires. Changing severity or category starts that tenant from the current time instead of replaying the backfill.

## Alerts and cases

Five real-time correlation rules query `flare_exposure_events_raw`. Each rule matches one Flare severity, so one event opens one alert and the rules do not overlap. A repeated event id is suppressed for 24 hours.

The alert field **Actor Effective Username** is set to the Flare identifier name (`xdm.target.resource.name`). To put multiple alerts for the same identifier into one case, configure XSIAM case grouping on that actor field. The content pack does not create the grouping policy. Alerts with no Flare identifier use the Flare event id, so they are not grouped together under an empty name.

## Commands

### flare-exposure-get-events

Retrieves events on demand. This command does not move the scheduled fetch cursor.

#### Base Command

`flare-exposure-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set to true to store the events. Default is false. | Required |
| limit | Maximum number of events to return. Default is 10. | Optional |
| from | How far back to read, for example 12 hours or 7 days. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

`!flare-exposure-get-events should_push_events=false limit=10 from="7 days"`
