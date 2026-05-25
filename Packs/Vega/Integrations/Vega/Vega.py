import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import re

# requests.packages.urllib3.disable_warnings() # pylint: disable=no-member


class Client(BaseClient):
    """
    Client Class For Vega API Integration
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, access_key: str, access_key_id: str = ""):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.access_key = access_key
        self.access_key_id = access_key_id

    def test_connection(self) -> dict:
        try:
            login_res: dict = self._http_request(
                method="POST",
                url_suffix="login_machine",
                json_data={"access_key": self.access_key},
                resp_type="json",
                ok_codes=(200,),
            )
        except Exception:
            raise ValueError("Incorrect Access Key. Please Check your Credentials.")

        session_jwt: str = login_res.get("session_jwt", "") if login_res else ""
        # if not session_jwt:
        #     raise ValueError("Incorrect Access Key. Please Check your Credentials.")

        query_data: dict = {
            "query": (
                "query GetAccessKey($id: String!) {  getAccessKey(id: $id) {    id    name    description    "
                "status    createdBy    createdAt    expireTime    roles    bindings {      role      "
                "scopeId      scopeName    }    secretValue  }}"
            ),
            "variables": {"id": self.access_key_id},
        }

        query_res = self._http_request(
            method="POST",
            url_suffix="query",
            headers={"JWTSessionToken": session_jwt},
            json_data=query_data,
            resp_type="json",
            ok_codes=(200,),
        )

        errors = query_res.get("errors")
        data = query_res.get("data") or {}
        get_access_key = data.get("getAccessKey")

        if errors or get_access_key is None:
            raise ValueError("Incorrect Access Key ID. Please Check your Credentials")

        roles = get_access_key.get("roles") or []

        if not any(re.search(r"(?i)editor|admin", role) for role in roles):
            raise ValueError("You do not have required access to fetch incidents.")

        return query_res


def test_module(client: Client):
    try:
        client.test_connection()
        return "ok"
    except Exception as e:
        return str(e)


def main() -> None:
    params = demisto.params()
    command = demisto.command()

    access_key = params.get("access_key")
    access_key_id = params.get("access_key_id")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    base_url = params.get("url")

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            access_key=access_key,
            access_key_id=access_key_id,
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
