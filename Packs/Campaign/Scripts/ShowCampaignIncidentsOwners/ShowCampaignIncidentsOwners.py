import demistomock as demisto
from CommonServerPython import *

from CommonServerUserPython import *


def get_incident_ids() -> list | None:
    """
    Gets all the campaign incident ids.

    Returns:
        List of all the ids.
    """
    incidents = demisto.get(demisto.context(), "EmailCampaign.incidents")
    return [incident["id"] for incident in incidents] if incidents else None


def get_incident_owners(incident_ids: list[str]) -> list:
    """
    Gets the campaign incident owners by their ids.

    Args:
        incident_ids: All the campaign incident ids.

    Returns:
        List of the incident owners.
    """

    res = demisto.executeCommand("GetIncidentsByQuery", {"query": f"id:({' '.join(incident_ids)})"})

    if isError(res):
        return_error(f"Error occurred while trying to get incidents by query: {get_error(res)}")

    incidents_from_query = json.loads(res[0]["Contents"])

    incident_owners = {incident["owner"] for incident in incidents_from_query}
    incident_owners.add(demisto.incident()["owner"])  # Add the campaign incident owner
    incident_owners_res = list(filter(lambda x: x, incident_owners))

    return incident_owners_res


def main():
    try:
        if incident_ids := get_incident_ids():
            incident_owners = get_incident_owners(incident_ids)

            html_readable_output = (
                f"<div style='font-size:17px; text-align:center; padding: 50px;'> Incident Owners"
                f"</br> <div style='font-size:32px;'> {len(incident_owners)} </div> "
                f"<div style='font-size:17px;'> {', '.join(incident_owners)} </div></div>"
            )

        else:
            html_readable_output = (
                "<div style='font-size:17px; text-align:center; padding: 50px;'> Incident Owners"
                "</br> <div style='font-size:17px;'> No incident owners. </div></div>"
            )

        return_results(CommandResults(content_format="html", raw_response=html_readable_output))
    except Exception as err:
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
