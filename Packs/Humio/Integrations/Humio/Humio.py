import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import urllib3
from datetime import datetime

import requests


""" IMPORTS """


# Disable insecure warnings from urllib3
# - this does not disable SSL checking, just the warnings logged from urllib3
urllib3.disable_warnings()

""" CLASS for Humio"""


class Client:
    def __init__(self, base_url, verify, proxies):
        self.base_url = base_url
        self.verify = verify
        self.proxies = proxies

    def http_request(self, method, url_suffix, data=None, headers=None):
        server = self.base_url + url_suffix
        res = requests.request(
            method,
            server,
            json=data,
            verify=self.verify,
            headers=headers,
            proxies=self.proxies,
        )
        return res


def test_module(client, headers=None):
    response = client.http_request("GET", "/api/v1/status")
    headers = {} if headers is None else headers
    if response.status_code == 200:
        try:
            resp = response.json()
        except Exception:
            return f"Could connect to server, but got unexpected response: {response.text}"

        if resp["status"].lower() == "ok":  # noqa: RET503
            incidentquery = demisto.params().get("queryParameter")
            incidentrepo = demisto.params().get("queryRepository")
            if incidentquery is not None and incidentrepo is not None:
                args = {
                    "queryString": incidentquery,
                    "repository": incidentrepo,
                    "start": "1m",
                    "end": "now",
                    "isLive": "false",
                    "timeZoneOffsetMinutes": 0,
                }
                humio_query(client, args, headers)
                return "ok"
            else:
                return "ok"

    else:
        return f"Bad status from server: ({response.status_code}) {response.text}"


def humio_query(client, args, headers):
    data = {}
    data["queryString"] = args.get("queryString")
    try:
        data["start"] = int(args.get("start"))
    except ValueError:
        data["start"] = args.get("start")
    try:
        data["end"] = int(args.get("end"))
    except ValueError:
        data["end"] = args.get("end")
    data["isLive"] = args.get("isLive").lower() in ["true", "1", "t", "y", "yes"]
    data["timeZoneOffsetMinutes"] = int(args.get("timeZoneOffsetMinutes", 0))
    if args.get("arguments"):
        data["arguments"] = args.get("arguments")
    url = "/api/v1/repositories/" + args.get("repository") + "/query"
    headers["Accept"] = "application/json"
    response = client.http_request("POST", url, data, headers)
    if response.status_code == 200:
        result = response.json()
        markdown = tableToMarkdown("Humio Query Results", result, removeNull=True)
        outputs = {"Humio.Query": [result]}
        return markdown, outputs, result
    else:
        raise ValueError("Error:" + " response from server was: " + str(response.text))


def humio_query_job(client, args, headers):
    data = {}
    data["queryString"] = args.get("queryString")
    data["start"] = args.get("start")
    data["end"] = args.get("end")
    data["isLive"] = args.get("isLive").lower() in ["true", "1", "t", "y", "yes"]
    data["timeZoneOffsetMinutes"] = int(args.get("timeZoneOffsetMinutes"))
    if args.get("arguments"):
        data["arguments"] = args.get("arguments")
    url = "/api/v1/repositories/" + args.get("repository") + "/queryjobs"
    headers["Accept"] = "application/json"
    response = client.http_request("POST", url, data, headers)
    if response.status_code == 200:
        result = response.json()
        markdown = tableToMarkdown("Humio Query Job", result, removeNull=True)
        outputs = {"Humio.Job": result}
        return markdown, outputs, result
    else:
        raise ValueError("Error:" + " response from server was: " + str(response.text))


def humio_poll(client, args, headers):
    data: dict[str, str] = {}
    url = "/api/v1/repositories/" + args.get("repository") + "/queryjobs/" + args.get("id")
    headers["Accept"] = "application/json"
    response = client.http_request("GET", url, data, headers)
    if response.status_code == 200:
        result = response.json()
        result["job_id"] = args.get("id")
        markdown = tableToMarkdown("Humio Poll Result", result.get("events", []), removeNull=True)
        outputs = {"Humio.Result(val.job_id == obj.job_id)": result}
        return markdown, outputs, result
    elif response.status_code == 404:
        raise ValueError(response.text)
    else:
        raise ValueError("Error:" + " response from server was: " + str(response.text))


def humio_delete_job(client, args, headers):
    data: dict[str, str] = {}
    url = "/api/v1/repositories/" + args.get("repository") + "/queryjobs/" + args.get("id")
    headers["Accept"] = "application/json"
    response = client.http_request("DELETE", url, data, headers)
    if response.status_code == 204:
        return "Command executed. Status code " + str(response), None, None
    elif response.status_code == 404:
        raise ValueError(response.text)
    else:
        raise ValueError("Error:" + " response from server was: " + str(response.text))


def humio_list_alerts(client, args, headers):
    data: dict[str, str] = {}
    url = "/api/v1/repositories/" + args.get("repository") + "/alerts"
    headers["Accept"] = "application/json"
    response = client.http_request("GET", url, data, headers)
    if response.status_code == 200:
        result = response.json()
        markdown = tableToMarkdown("Humio Alerts", result, removeNull=True)
        outputs = {"Humio.Alert(val.id == obj.id)": result}
        return markdown, outputs, result
    else:
        raise ValueError("Error:" + " response from server was: " + str(response.text))


def humio_get_alert_by_id(client, args, headers):
    data: dict[str, str] = {}
    url = "/api/v1/repositories/" + args.get("repository") + "/alerts/" + args.get("id")
    headers["Accept"] = "application/json"
    response = client.http_request("GET", url, data, headers)
    if response.status_code == 200:
        if not response.text:
            raise ValueError("Alert with id " + str(args.get("id")) + " not found")
        result = response.json()
        markdown = tableToMarkdown("Humio Alerts", result, removeNull=True)
        outputs = {"Humio.Alert(val.id == obj.id)": result}
        return markdown, outputs, result
    else:
        raise ValueError("Error:" + " response from server was: " + str(response.text))


def humio_create_alert(client, args, headers):
    fulldata = {}
    data = {}
    data["queryString"] = args.get("queryString")
    data["start"] = args.get("start")
    data["end"] = "now"
    data["isLive"] = True
    fulldata["name"] = args.get("name")
    fulldata["description"] = args.get("description", "")
    fulldata["throttleTimeMillis"] = int(args.get("throttleTimeMillis"))
    fulldata["silenced"] = args.get("silenced", "false").lower() in [
        "true",
        "1",
        "t",
        "y",
        "yes",
    ]
    fulldata["notifiers"] = [notifier for notifier in args.get("notifiers").split(",") if notifier]
    fulldata["labels"] = [label for label in args.get("labels", "").split(",") if label]
    fulldata["query"] = data
    url = "/api/v1/repositories/" + args.get("repository") + "/alerts"
    headers["Accept"] = "application/json"
    response = client.http_request("POST", url, fulldata, headers)
    if response.status_code == 201:
        result = response.json()
        markdown = tableToMarkdown("Humio Alerts", result, removeNull=True)
        outputs = {"Humio.Alert(val.id == obj.id)": result}
        return markdown, outputs, result
    else:
        raise ValueError("Error:" + " response from server was: " + str(response.text))


def humio_delete_alert(client, args, headers):
    data: dict[str, str] = {}
    url = "/api/v1/repositories/" + args.get("repository") + "/alerts/" + args.get("id")
    headers["Accept"] = "application/json"
    response = client.http_request("DELETE", url, data, headers)
    if response.status_code == 204:
        return "Command executed. Status code " + str(response), None, None
    else:
        raise ValueError("Error:" + " response from server was: " + str(response.text))


def humio_list_notifiers(client, args, headers):
    url = "/graphql"
    headers["Accept"] = "application/json"

    graphql_query = """
    query{{searchDomain(name:"{repoName}"){{actions{{__typename, id , name
        ... on EmailAction{{id, name, recipients, subjectTemplate, emailBodyTemplate: bodyTemplate, useProxy, attachCsv}}
        ... on SlackAction{{url, fields{{fieldName, value}}, useProxy}}
        ... on SlackPostMessageAction{{apiToken, channels, fields{{fieldName, value}}, useProxy}}
        ... on WebhookAction{{method, url, webhookBodyTemplate: bodyTemplate, headers{{header,value}}, ignoreSSL, useProxy}}
        ... on OpsGenieAction{{apiUrl, genieKey, useProxy}}
        ... on VictorOpsAction{{messageType, notifyUrl, useProxy}}
        ... on PagerDutyAction{{severity, routingKey, useProxy}}
        ... on HumioRepoAction{{ingestToken}}
        ... on UploadFileAction{{fileName}}
        }}}}}}
    """.format(repoName=args.get("repository"))

    data = {"query": graphql_query}

    response = client.http_request("POST", url, data, headers)

    if response.status_code == 200:
        result = response.json()
        if not result.get("data"):
            raise ValueError(f"Failed to execute request: {response['errors'][0]['message']}")

        actions = result.get("data", {}).get("searchDomain", {}).get("actions", [])
        markdown = tableToMarkdown("Humio Notifiers", actions, removeNull=True)
        outputs = {"Humio.Notifier(val.id == obj.id)": actions}
        return markdown, outputs, actions
    else:
        raise ValueError("Error:" + " response from server was: " + str(response.text))


def humio_get_notifier_by_id(client, args, headers):
    url = "/graphql"
    graphql_query = """
    query{{searchDomain(name:"{repoName}"){{action(id:"{id}"){{__typename, id, name
        ... on EmailAction{{id, name, recipients, subjectTemplate, emailBodyTemplate: bodyTemplate, useProxy, attachCsv}}
        ... on SlackAction{{url, fields{{fieldName, value}}, useProxy}}
        ... on SlackPostMessageAction{{apiToken, channels, fields{{fieldName, value}}, useProxy}}
        ... on WebhookAction{{method, url, webhookBodyTemplate: bodyTemplate, headers{{header,value}}, ignoreSSL, useProxy}}
        ... on OpsGenieAction{{apiUrl, genieKey, useProxy}}
        ... on VictorOpsAction{{messageType, notifyUrl, useProxy}}
        ... on PagerDutyAction{{severity, routingKey, useProxy}}
        ... on HumioRepoAction{{ingestToken}}
        ... on UploadFileAction{{fileName}}}}}}}}
    """.format(repoName=args.get("repository"), id=args.get("id"))

    headers["Accept"] = "application/json"

    data = {"query": graphql_query}

    response = client.http_request("POST", url, data, headers)
    if response.status_code == 200:
        result = response.json()
        if not result.get("data"):
            raise ValueError(f"Failed to execute request: {response['errors'][0]['message']}")
        actions = result.get("data", {}).get("searchDomain", {}).get("action")
        markdown = tableToMarkdown("Humio Notifiers", actions, removeNull=True)
        outputs = {"Humio.Notifier(val.id == obj.id)": actions}
        return markdown, outputs, actions
    else:
        raise ValueError("Error:" + " response from server was: " + str(response.text))


def fetch_incidents(client, headers):
    incidentquery = demisto.params().get("queryParameter")
    incidentrepo = demisto.params().get("queryRepository")
    timestampfrom = demisto.params().get("queryStartTime")
    chunkSize = demisto.params().get("queryChunkSize", "50")
    lastrun = demisto.getLastRun()
    url = "/api/v1/repositories/" + incidentrepo + "/query"
    headers["Accept"] = "application/json"

    last_event_ts = int(lastrun.get("time", 0))

    # Only query events with an ingesttimestamp greater than the last run and
    # set maximum of 50 returned events (this is idempotent)
    incidentquery = "@ingesttimestamp > " + str(last_event_ts) + " | " + incidentquery + " | head(" + str(chunkSize) + ")"

    demisto.debug("Querying '" + incidentquery + "'")
    data = {
        "queryString": incidentquery,
        "end": "now",
        "isLive": False,
        "timeZoneOffsetMinutes": int(demisto.params().get("queryTimeZoneOffsetMinutes")),
        "start": timestampfrom,
    }

    response = client.http_request("POST", url, data, headers)
    if response.status_code == 200:
        response_data = response.json()
        if response_data:
            for result in response_data:
                ingest_ts = int(result.get("@ingesttimestamp"))
                if ingest_ts > last_event_ts:
                    last_event_ts = ingest_ts

            last_event_ts += 1
            demisto.setLastRun({"time": last_event_ts})
        return form_incindents(response_data)
    else:
        raise ValueError("Error in fetching incidents. Error from server was: " + str(response.text))


def create_incident_from_humioquery(incident):
    occurred = datetime.fromtimestamp(incident["@timestamp"] / 1000.0).strftime("%Y-%m-%dT%H:%M:%SZ")
    keys = incident.keys()
    labels = []
    for key in keys:
        labels.append({"type": key, "value": str(incident[key])})
    return {
        "name": "Humio Incident {id}".format(id=incident["@id"]),
        "labels": labels,
        "rawJSON": json.dumps(incident),
        "occurred": occurred,
    }


def form_incindents(incidents):
    returnableincidents = []
    for item in incidents:
        returnableincidents.append(create_incident_from_humioquery(item))
    return returnableincidents


def main():
    apikey = demisto.params().get("API-key")
    baseserver = (
        demisto.params()["url"][:-1]
        if (demisto.params()["url"] and demisto.params()["url"].endswith("/"))
        else demisto.params()["url"]
    )
    verify_certificate = not demisto.params().get("insecure", False)
    proxies = handle_proxy()

    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Authorization"] = "Bearer " + apikey

    command = demisto.command()
    LOG(f"Command being called is {command}")
    try:
        client = Client(baseserver, verify_certificate, proxies)
        commands = {
            "humio-query": humio_query,
            "humio-query-job": humio_query_job,
            "humio-poll": humio_poll,
            "humio-delete-job": humio_delete_job,
            "humio-list-alerts": humio_list_alerts,
            "humio-get-alert-by-id": humio_get_alert_by_id,
            "humio-create-alert": humio_create_alert,
            "humio-delete-alert": humio_delete_alert,
            "humio-list-notifiers": humio_list_notifiers,
            "humio-get-notifier-by-id": humio_get_notifier_by_id,
        }
        if command == "test-module":
            results = test_module(client, headers)
            return_outputs(results)
        elif demisto.command() == "fetch-incidents":
            demisto.incidents(fetch_incidents(client, headers))
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args(), headers))
    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
