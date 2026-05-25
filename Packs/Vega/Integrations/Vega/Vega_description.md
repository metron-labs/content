## Vega Integration Setup

The Vega integration allows you to ingest alerts and incidents from the Vega platform using the GraphQL API.

### Authentication

To connect to the Vega platform, you need an **Access Key**.
1. Log in to your Vega console.
2. Navigate to **Settings** > **Machine Users** / **API Keys**.
3. Generate or retrieve an Access Key for your machine user.
4. Copy the Access Key and paste it into the **Access Key** configuration parameter of this integration.

### Session Management

The integration automatically performs authentication using the `login_machine` endpoint. 
It retrieves a JSON Web Token (`session_jwt`) and caches it in integration context. The cached token is reused for all subsequent API requests. The token will only be refreshed once it is close to expiring (within a 5-minute safety margin), ensuring minimal login requests are sent to the Vega API.

### Ingestion Settings

You can configure the integration to fetch alerts, incidents, or both:
- **Fetch Alerts**: Fetches Vega alerts. You can filter the fetched alerts by specific severities (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and statuses (`OPEN`, `IN_PROGRESS`, `CLOSED`).
- **Fetch Incidents**: Fetches Vega incidents. You can filter the fetched incidents by specific severities (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and statuses (`NEW`, `INVESTIGATING`, `CLOSED`).

- **First fetch time**: The relative time window to retrieve alerts and incidents on the very first run (e.g., `3 days`, `1 week`).
- **Maximum items per fetch**: Limits the number of alerts and incidents retrieved per run (default: 50).