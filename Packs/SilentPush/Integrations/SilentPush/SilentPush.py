# import demistomock as demisto           # noqa: F401
# from CommonServerPython import *        # noqa: F401
import ipaddress
import re
"""Base Integration for Cortex XSOAR (aka Demisto)

This is an integration to interact with the SilentPush API and provide functionality within XSOAR.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting
"""

import requests
import urllib3
from typing import Any, Optional, Dict, List

urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''

class Client(BaseClient):
    """Client class to interact with the SilentPush API

    This Client implements API calls and does not contain any XSOAR logic.
    It should only perform requests and return data.
    It inherits from BaseClient defined in CommonServerPython.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url: str, api_key: str, verify: bool = True, proxy: bool = False):
        """
        Initializes the client with the necessary parameters.

        Args:
            base_url (str): The base URL for the SilentPush API.
            api_key (str): The API key for authentication.
            verify (bool): Flag to determine whether to verify SSL certificates (default True).
            proxy (bool): Flag to determine whether to use a proxy (default False).
        """
        self.base_url = base_url.rstrip('/') + '/api/v1/merge-api/'
        self.api_key = api_key
        self.verify = verify
        self.proxy = proxy
        self._headers = {
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        }

    def _http_request(self, method: str, url_suffix: str, params: dict = None, data: dict = None) -> Any:
        """
        Perform an HTTP request to the SilentPush API.

        Args:
            method (str): The HTTP method to use (e.g., 'GET', 'POST').
            url_suffix (str): The endpoint suffix to append to the base URL.
            params (dict, optional): Query parameters to include in the request. Defaults to None.
            data (dict, optional): JSON data to send in the request body. Defaults to None.

        Returns:
            Any: The JSON response from the API or text response if not JSON.

        Raises:
            DemistoException: If there's an error during the API call.
        """
        if url_suffix == "/api/v2/iocs/threat-ranking":
            full_url = demisto.params().get('url', 'https://api.silentpush.com') + url_suffix
        else:
            full_url = f'{self.base_url}{url_suffix}'
        try:
            response = requests.request(
                method,
                full_url,
                headers=self._headers,
                verify=self.verify,
                params=params,
                json=data
            )
            if response.headers.get('Content-Type', '').startswith('application/json'):
                return response.json()
            else:
                return response.text
        except Exception as e:
            raise DemistoException(f'Error in API call: {str(e)}')

    def parse_subject(self,subject: Any) -> Dict[str, Any]:
        """
        Parse the subject of a certificate or domain record.

        Args:
            subject (Any): The subject to parse, which can be a dictionary, string, or other type.

        Returns:
            Dict[str, Any]: A dictionary representation of the subject,
            with a fallback to {'CN': subject} or {'CN': 'N/A'} if parsing fails.
        """
        if isinstance(subject, dict):
            return subject
        elif isinstance(subject, str):
            try:
                return json.loads(subject.replace("'", '"'))
            except (json.JSONDecodeError, TypeError):
                return {'CN': subject}
        else:
            return {'CN': 'N/A'}

    def validate_ip_address(self, ip: str, allow_ipv6: bool = True) -> bool:
        """
        Validate an IP address.

        Args:
            self: The instance of the class.
            ip (str): IP address to validate.
            allow_ipv6 (bool, optional): Whether to allow IPv6 addresses. Defaults to True.

        Returns:
            bool: True if valid IP address, False otherwise.
        """
        try:
            ip = ip.strip()
            ip_obj = ipaddress.ip_address(ip)

            return not (not allow_ipv6 and ip_obj.version == 6)
        except ValueError:
            return False

    def validate_ip_inputs(self, ips: List[str], allow_ipv6: bool = True) -> List[str]:
        """
        Validate a list of IP addresses.

        Args:
            ips (List[str]): List of IP addresses to validate.
            allow_ipv6 (bool): Whether to allow IPv6 addresses. Defaults to True.

        Returns:
            List[str]: List of valid IP addresses.

        Raises:
            DemistoException: If no valid IP addresses are found.
        """
        valid_ips = [
            ip.strip() for ip in ips if self.validate_ip_address(ip, allow_ipv6=allow_ipv6)
        ]

        if not valid_ips:
            raise DemistoException(
                f"No valid {'IPv4 and IPv6' if allow_ipv6 else 'IPv4'} addresses found."
            )

        return valid_ips


    ''' Client Methods'''

    def list_domain_information(self, domains: List[str], fetch_risk_score: Optional[bool] = False, fetch_whois_info: Optional[bool] = False) -> Dict:
        """
        Retrieve domain information along with optional risk scores and WHOIS data.

        Args:
            domains (List[str]): List of domains to get information for
            fetch_risk_score (bool, optional): Whether to fetch risk scores. Defaults to False
            fetch_whois_info (bool, optional): Whether to fetch WHOIS information. Defaults to False

        Returns:
            Dict: Dictionary containing domain information with optional risk scores and WHOIS data

        Raises:
            DemistoException: If more than 100 domains are provided
        """
        if len(domains) > 100:
            raise DemistoException("Maximum of 100 domains can be submitted in a single request.")

        domains_data = {'domains': domains}
        bulk_info_response = self._http_request(
            method='POST',
            url_suffix='explore/bulk/domaininfo',
            data=domains_data
        )

        domain_info_list = bulk_info_response.get('response', {}).get('domaininfo', [])
        domain_info_dict = {item['domain']: item for item in domain_info_list}

        risk_score_dict = {}
        if fetch_risk_score:
            risk_response = self._http_request(
                method='POST',
                url_suffix='explore/bulk/domain/riskscore',
                data=domains_data
            )
            risk_score_list = risk_response.get('response', [])
            risk_score_dict = {item['domain']: item for item in risk_score_list}

        whois_info_dict = {}
        if fetch_whois_info:
            for domain in domains:
                try:
                    whois_response = self._http_request(
                        method='GET',
                        url_suffix=f'explore/domain/whois/{domain}'
                    )
                    whois_data = whois_response.get('response', {}).get('whois', [{}])[0]

                    whois_info_dict[domain] = {
                        'Registrant Name': whois_data.get('name', 'N/A'),
                        'Registrant Organization': whois_data.get('org', 'N/A'),
                        'Registrant Address': ', '.join(whois_data.get('address', [])) if isinstance(whois_data.get('address'), list) else whois_data.get('address', 'N/A'),
                        'Registrant City': whois_data.get('city', 'N/A'),
                        'Registrant State': whois_data.get('state', 'N/A'),
                        'Registrant Country': whois_data.get('country', 'N/A'),
                        'Registrant Zipcode': whois_data.get('zipcode', 'N/A'),
                        'Creation Date': whois_data.get('created', 'N/A'),
                        'Updated Date': whois_data.get('updated', 'N/A'),
                        'Expiration Date': whois_data.get('expires', 'N/A'),
                        'Registrar': whois_data.get('registrar', 'N/A'),
                        'WHOIS Server': whois_data.get('whois_server', 'N/A'),
                        'Nameservers': ', '.join(whois_data.get('nameservers', [])),
                        'Emails': ', '.join(whois_data.get('emails', []))
                    }
                except Exception as e:
                    whois_info_dict[domain] = {'error': str(e)}

        results = []
        for domain in domains:
            domain_info = {
                'domain': domain,
                **domain_info_dict.get(domain, {}),
            }

            if fetch_risk_score:
                risk_data = risk_score_dict.get(domain, {})
                domain_info.update({
                    'risk_score': risk_data.get('sp_risk_score', 'N/A'),
                    'risk_score_explanation': risk_data.get('sp_risk_score_explain', 'N/A')
                })

            if fetch_whois_info:
                domain_info['whois_info'] = whois_info_dict.get(domain, {})

            results.append(domain_info)

        return {'domains': results}

    def get_domain_certificates(self, domain: str, **kwargs) -> Dict[str, Any]:
        url_suffix = f"explore/domain/certificates/{domain}"
        params = {k: v for k, v in kwargs.items() if v is not None}
        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params
        )
        return response


    def search_domains(self, query: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None, risk_score_min: Optional[int] = None, risk_score_max: Optional[int] = None, limit: int = 100, domain_regex: Optional[str] = None, name_server: Optional[str] = None, asnum: Optional[int] = None, asname: Optional[str] = None, min_ip_diversity: Optional[int] = None, registrar: Optional[str] = None, min_asn_diversity: Optional[int] = None, certificate_issuer: Optional[str] = None, whois_date_after: Optional[str] = None, skip: Optional[int] = None) -> dict:
        """
            Search for domains based on various filtering criteria.

            Args:
                query (str, optional): Domain search query.
                start_date (str, optional): Start date for domain search.
                end_date (str, optional): End date for domain search.
                risk_score_min (int, optional): Minimum risk score filter.
                risk_score_max (int, optional): Maximum risk score filter.
                limit (int, optional): Maximum number of results to return. Defaults to 100.
                domain_regex (str, optional): Regular expression to filter domains.
                name_server (str, optional): Name server filter.
                asnum (int, optional): Autonomous System Number filter.
                asname (str, optional): Autonomous System Name filter.
                min_ip_diversity (int, optional): Minimum IP diversity filter.
                registrar (str, optional): Domain registrar filter.
                min_asn_diversity (int, optional): Minimum ASN diversity filter.
                certificate_issuer (str, optional): Certificate issuer filter.
                whois_date_after (str, optional): WHOIS date filter.
                skip (int, optional): Number of results to skip.

            Returns:
                dict: Search results matching the specified criteria.
            """
        url_suffix = 'explore/domain/search'
        params = {k: v for k, v in {
            'domain': query,
            'start_date': start_date,
            'end_date': end_date,
            'risk_score_min': risk_score_min,
            'risk_score_max': risk_score_max,
            'limit': limit,
            'domain_regex': domain_regex,
            'name_server': name_server,
            'asnum': asnum,
            'asname': asname,
            'min_ip_diversity': min_ip_diversity,
            'registrar': registrar,
            'min_asn_diversity': min_asn_diversity,
            'certificate_issuer': certificate_issuer,
            'whois_date_after': whois_date_after,
            'skip': skip,
        }.items() if v is not None}
        response = self._http_request('GET', url_suffix, params=params)
        return response

    def list_domain_infratags(
        self,
        domains: list,
        cluster: bool = False,
        mode: str = 'live',
        match: str = 'self',
        as_of: Optional[str] = None,
        origin_uid: Optional[str] = None,
        use_get: bool = False
    ) -> dict:
        """
        Retrieve infrastructure tags for specified domains, supporting both GET and POST methods.

        Args:
            domains (list): List of domains to fetch infrastructure tags for.
            cluster (bool): Whether to include cluster information (default: False).
            mode (str): Tag retrieval mode (default: 'live').
            match (str): Matching criteria (default: 'self').
            as_of (Optional[str]): Specific timestamp for tag retrieval.
            origin_uid (Optional[str]): Unique identifier for the API user.
            use_get (bool): Use GET method instead of POST (default: False).

        Returns:
            dict: API response containing infratags and optional tag clusters.
        """
        url_suffix = 'explore/bulk/domain/infratags'
        params = {
            'mode': mode,
            'match': match,
            'clusters': int(cluster),
        }


        if as_of:
            params['as_of'] = as_of
        if origin_uid:
            params['origin_uid'] = origin_uid

        if use_get:

            response = self._http_request(
                method='GET',
                url_suffix=url_suffix,
                params=params
            )
        else:

            payload = {'domains': domains}
            response = self._http_request(
                method='POST',
                url_suffix=url_suffix,
                params=params,
                data=payload
            )

        return response


    def get_enrichment_data(self, resource: str, value: str, explain: Optional[bool] = False, scan_data: Optional[bool] = False) -> dict:
        """
        Retrieve enrichment data for a specific resource.

        Args:
            resource (str): Type of resource (e.g., 'ip', 'domain').
            value (str): The specific value to enrich.
            explain (bool, optional): Whether to include detailed explanations. Defaults to False.
            scan_data (bool, optional): Whether to include scan data. Defaults to False.

        Returns:
            dict: Enrichment data for the specified resource.
        """
        endpoint = f"explore/enrich/{resource}/{value}"

        query_params = {}
        query_params["explain"] = int(explain) if explain else query_params.get("explain", 0)
        query_params["scan_data"] = int(scan_data) if scan_data else query_params.get("scan_data", 0)

        response = self._http_request(
            method="GET",
            url_suffix=endpoint,
            params=query_params
        )

        if resource in ["ip", "ipv4", "ipv6"]:
            ip2asn_data = response.get("response", {}).get("ip2asn", [])
            return ip2asn_data[0] if isinstance(ip2asn_data, list) and ip2asn_data else {}
        else:
            return response.get("response", {}).get("domaininfo", {})

    def list_ip_information(self, ips: List[str], resource: str) -> Dict:
        """
        Retrieve information for multiple IP addresses.

        Args:
            ips (List[str]): List of IPv4 or IPv6 addresses to fetch information for.
            resource (str): The resource type ('ipv4' or 'ipv6').

        Returns:
            Dict: API response containing IP information.
        """
        if len(ips) > 100:
            raise DemistoException("Maximum of 100 IPs can be submitted in a single request.")

        ip_data = {"ips": ips}
        url_suffix = f"explore/bulk/ip2asn/{resource}"
        bulk_ip_response = self._http_request("POST", url_suffix, data=ip_data)

        return bulk_ip_response




    def get_asn_reputation(self, asn: int, limit: Optional[int] = None, explain: Optional[bool] = False) -> Dict[str, Any]:
        """
        Retrieve reputation history for a specific Autonomous System Number (ASN).

        Args:
            asn (int): The Autonomous System Number to query.
            limit (int, optional): Maximum number of results to return. Defaults to None.
            explain (bool, optional): Whether to include explanation for reputation score. Defaults to False.

        Returns:
            Dict[str, Any]: ASN reputation history information.
        """
        url_suffix = f"explore/ipreputation/history/asn/{asn}"
        query_params = {}

        if limit:
            query_params['limit'] = limit
        if explain:
            query_params['explain'] = 'true'

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=query_params
        )

        return response

    def get_asn_takedown_reputation(self, asn: str, limit: Optional[int] = None, explain: bool = False) -> Dict[str, Any]:
        """
        Retrieve takedown reputation for a specific Autonomous System Number (ASN).

        Args:
            asn (str): The ASN number to query
            limit (Optional[int]): Maximum results to return
            explain (bool): Whether to include explanation for reputation score

        Returns:
            Dict[str, Any]: Takedown reputation information for the specified ASN

        Raises:
            ValueError: If ASN is not provided
            DemistoException: If API call fails
        """
        if not asn:
            raise ValueError('ASN is required.')

        endpoint = f'explore/takedownreputation/asn/{asn}'
        params = {}

        if limit:
            params['limit'] = limit
        if explain:
            params['explain'] = 'true'

        response = self._http_request(
            method='GET',
            url_suffix=endpoint,
            params=params
        )

        return response.get('response', {}).get('takedown_reputation', {})


    def get_ipv4_reputation(self, ipv4: str, explain: bool = False, limit: int = None) -> List[Dict[str, Any]]:
        """
        Retrieve reputation information for an IPv4 address.
        """
        url_suffix = f"explore/ipreputation/history/ipv4/{ipv4}"
        query_params = {}

        if explain:
            query_params['explain'] = 'true'
        if limit:
            query_params['limit'] = limit

        raw_response = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=query_params
        )


        ipv4_reputation = raw_response.get('response', {}).get('ip_reputation_history', [])

        return ipv4_reputation





    def get_job_status(self, job_id: str, max_wait: Optional[int] = None, result_type: Optional[str] = None) -> Dict[str, Any]:
        """
            Retrieve the status of a specific job.

            Args:
                job_id (str): The unique identifier of the job to check.
                max_wait (int, optional): Maximum wait time in seconds. Must be between 0 and 25. Defaults to None.
                result_type (str, optional): Type of result to retrieve. Defaults to None.

            Returns:
                Dict[str, Any]: Job status information.

            Raises:
                ValueError: If max_wait is invalid or result_type is not in allowed values.
            """
        url_suffix = f"explore/job/{job_id}"

        params = {}
        if max_wait is not None:
            if not isinstance(max_wait, int) or max_wait < 0 or max_wait > 25:
                raise ValueError("max_wait must be an integer between 0 and 25")
            params['max_wait'] = max_wait

        if result_type:
            valid_result_types = ['Status', 'Include Metadata', 'Exclude Metadata']
            if result_type not in valid_result_types:
                raise ValueError(f"result_type must be one of {valid_result_types}")
            params['result_type'] = result_type

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params
        )

        return response

    def get_nameserver_reputation(self, nameserver: str, explain: bool = False, limit: int = None):
        """
        Retrieve historical reputation data for the specified name server.

        Args:
            nameserver (str): The nameserver for which the reputation data is to be fetched.
            explain (bool): Whether to include detailed calculation explanations.
            limit (int): Maximum number of reputation entries to return.

        Returns:
            dict: Reputation history for the given nameserver.
        """

        url_suffix = f"explore/nsreputation/nameserver/{nameserver}"

        params = {}

        if explain:
            params['explain'] = explain
        if limit:
            params['limit'] = limit


        response = self._http_request(method="GET", url_suffix=url_suffix, params=params)



        try:

            return response.get('response', {}).get('ns_server_reputation', [])
        except AttributeError:

            return {}



    def get_subnet_reputation(self, subnet: str, explain: Optional[bool] = False, limit: Optional[int] = None) -> Dict[str, Any]:
        """
            Retrieve reputation history for a specific subnet.

            Args:
                subnet (str): The subnet to query.
                explain (bool, optional): Whether to include detailed explanations. Defaults to False.
                limit (int, optional): Maximum number of results to return. Defaults to None.

            Returns:
                Dict[str, Any]: Subnet reputation history information.
            """
        url_suffix = f"explore/ipreputation/history/subnet/{subnet}"

        params = {}
        if explain:
            params['explain'] = str(explain).lower()
        if limit is not None:
            params['limit'] = limit

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params
        )

        return response

    def get_asns_for_domain(self, domain: str) -> Dict[str, Any]:
        """
            Retrieve Autonomous System Numbers (ASNs) associated with a domain.

            Args:
                domain (str): The domain to retrieve ASNs for.

            Returns:
                Dict[str, Any]: Domain ASN information.
            """
        url_suffix = f"explore/padns/lookup/domain/asns/{domain}"

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix
        )

        return response

    def forward_padns_lookup(self, qtype: str, qname: str, **kwargs) -> Dict[str, Any]:
        """
        Perform a forward PADNS lookup using various filtering parameters.

        Args:
            qtype (str): Type of DNS record.
            qname (str): The DNS record name to lookup.
            **kwargs: Optional parameters for filtering and pagination.

        Returns:
            Dict[str, Any]: PADNS lookup results.
        """
        url_suffix = f"explore/padns/lookup/query/{qtype}/{qname}"

        params = {k: v for k, v in kwargs.items() if v is not None}

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params
        )

        return response

    def reverse_padns_lookup(self, qtype: str, qname: str, **kwargs) -> Dict[str, Any]:
        """
        Perform a reverse PADNS lookup using various filtering parameters.

        Args:
            qtype (str): Type of DNS record.
            qname (str): The DNS record name to lookup.
            **kwargs: Optional parameters for filtering and pagination.

        Returns:
            Dict[str, Any]: Reverse PADNS lookup results.
        """
        url_suffix = f"explore/padns/lookup/answer/{qtype}/{qname}"

        params = {k: v for k, v in kwargs.items() if v is not None}

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params
        )

        return response


    def density_lookup(self, qtype: str, query: str, **kwargs) -> Dict[str, Any]:
        """
        Perform a density lookup based on various query types and parameters.

        Args:
            qtype (str): Query type (nssrv, mxsrv, nshash, mxhash, ipv4, ipv6, asn, chv)
            query (str): Value to lookup
            **kwargs: Optional parameters for filtering and scoping

        Returns:
            Dict[str, Any]: Density lookup results
        """
        url_suffix = f"explore/padns/lookup/density/{qtype}/{query}"

        params = {k: v for k, v in kwargs.items() if v is not None}

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params
        )

        return response

    def search_scan_data(self, query: str) -> Dict[str, Any]:
        """
        Search the Silent Push scan data repositories.

        Args:
            query (str): Query in SPQL syntax to scan data (mandatory)

        Returns:
            Dict[str, Any]: Search results from scan data repositories

        Raises:
            DemistoException: If query is not provided or API call fails
        """
        if not query:
            raise DemistoException("Query parameter is required for search scan data.")

        url_suffix = "explore/scandata/search/raw"

        payload = {
            "query": query
        }

        try:
            response = self._http_request(
                method="POST",
                url_suffix=url_suffix,
                data=payload
            )
            return response
        except Exception as e:
            raise DemistoException(f"Failed to search scan data: {str(e)}")


    def live_url_scan(self, url: str, platform: Optional[str] = None, os: Optional[str] = None,
                    browser: Optional[str] = None, region: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform a live scan of a URL to get hosting metadata.

        Args:
            url (str): The URL to scan
            platform (str, optional): Device to perform scan with (Desktop, Mobile, Crawler)
            os (str, optional): OS to perform scan with (Windows, Linux, MacOS, iOS, Android)
            browser (str, optional): Browser to perform scan with (Firefox, Chrome, Edge, Safari)
            region (str, optional): Region from where scan should be performed (US, EU, AS, TOR)

        Returns:
            Dict[str, Any]: The scan results including hosting metadata

        Raises:
            DemistoException: If there's an error during the API call
        """
        url_suffix = "explore/tools/scanondemand"

        params = {
            'url': url,
            'platform': platform,
            'os': os,
            'browser': browser,
            'region': region
        }

        params = {k: v for k, v in params.items() if v is not None}

        try:
            response = self._http_request(
                method='GET',
                url_suffix=url_suffix,
                params=params
            )
            return response
        except Exception as e:
            raise DemistoException(f'Error in live URL scan: {str(e)}')

    def get_future_attack_indicators(self, feed_uuid: str, page_no: int = 1, page_size: int = 10000) -> Dict[str, Any]:
        """
        Retrieve indicators of future attack feed from SilentPush.

        Args:
            feed_uuid (str): Feed unique identifier to fetch records for.
            page_no (int, optional): Page number for pagination. Defaults to 1.
            page_size (int, optional): Number of records per page. Defaults to 10000.

        Returns:
            Dict[str, Any]: Response containing future attack indicators.

        Raises:
            DemistoException: If there's an error during the API call.
        """
        url_suffix = "/api/v2/iocs/threat-ranking"

        params = {
            'page': page_no,
            'size': page_size,
            'source_uuids': feed_uuid
        }

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params
        )

        return response

    def screenshot_url(self, url: str) -> Dict[str, Any]:
        """
        Generate a screenshot for a given URL and store it in the vault using GET request.

        Args:
            url (str): The URL to capture a screenshot of

        Returns:
            Dict[str, Any]: Response containing screenshot information and vault details
        """
        endpoint = "explore/tools/screenshotondemand"
        params = {"url": url}

        try:

            response = self._http_request(
                method="GET",
                url_suffix=endpoint,
                params=params
            )

            if response.get("error"):
                raise DemistoException(f"Failed to get screenshot: {response['error']}")

            screenshot_data = response.get("response", {}).get("screenshot", {})
            if not screenshot_data:
                raise DemistoException("No screenshot data returned from API")

            screenshot_url = screenshot_data.get("message")
            if not screenshot_url:
                raise DemistoException("No screenshot URL returned")


            image_response = requests.get(screenshot_url, verify=self.verify)
            if image_response.status_code != 200:
                raise DemistoException(f"Failed to download screenshot image: HTTP {image_response.status_code}")


            filename = f"{url.split('://')[1].split('/')[0]}_screenshot.jpg"
            return {
                "status_code": screenshot_data.get("response", 200),
                "screenshot_url": screenshot_url,
                "vault_info": fileResult(filename, image_response.content),
                "filename": filename
            }

        except Exception as e:
            raise DemistoException(f"Error capturing screenshot: {str(e)}")

def test_module(client: Client) -> str:
    try:
        resp = client.search_domains()
        if resp.get("status_code") != 200:
            return f"Connection failed :- {resp.get('errors')}"
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        raise e

def list_domain_information_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Handle the list-domain-information command execution.

    Args:
        client (Client): The client object for making API calls
        args (Dict[str, Any]): Command arguments

    Returns:
        CommandResults: Results for XSOAR

    Raises:
        DemistoException: If no domains are provided
    """
    domains_arg = args.get('domains', '')
    if not domains_arg:
        raise DemistoException('No domains provided')

    domains = [domain.strip() for domain in domains_arg.split(',') if domain.strip()]
    fetch_risk_score = argToBoolean(args.get('fetch_risk_score', False))
    fetch_whois_info = argToBoolean(args.get('fetch_whois_info', False))

    response = client.list_domain_information(domains, fetch_risk_score, fetch_whois_info)

    markdown = ['# Domain Information Results\n']

    for domain_data in response.get('domains', []):
        domain = domain_data.get('domain', 'N/A')
        markdown.append(f'## Domain: {domain}')

        basic_info = {
            'Created Date': domain_data.get('whois_created_date', 'N/A'),
            'Updated Date': domain_data.get('whois_updated_date', 'N/A'),
            'Expiration Date': domain_data.get('whois_expiration_date', 'N/A'),
            'Registrar': domain_data.get('registrar', 'N/A'),
            'Status': domain_data.get('status', 'N/A'),
            'Name Servers': domain_data.get('nameservers', 'N/A')
        }
        markdown.append(tableToMarkdown('Domain Information', [basic_info]))

        if fetch_risk_score:
            risk_info = {
                'Risk Score': domain_data.get('risk_score', 'N/A'),
                'Risk Score Explanation': domain_data.get('risk_score_explanation', 'N/A')
            }
            markdown.append(tableToMarkdown('Risk Assessment', [risk_info]))

        if fetch_whois_info:
            whois_info = domain_data.get('whois_info', {})
            if whois_info and isinstance(whois_info, dict):
                if 'error' in whois_info:
                    markdown.append(f'WHOIS Error: {whois_info["error"]}')
                else:
                    markdown.append(tableToMarkdown('WHOIS Information', [whois_info]))

        markdown.append('\n---\n')

    return CommandResults(
        outputs_prefix='SilentPush.Domain',
        outputs_key_field='domain',
        outputs=response.get('domains', []),
        readable_output='\n'.join(markdown),
        raw_response=response
    )

def get_domain_certificates_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    domain = args.get('domain')
    if not domain:
        raise DemistoException("The 'domain' parameter is required.")
    params = {
        'domain_regex': args.get('domain_regex'),
        'certificate_issuer': args.get('certificate_issuer'),
        'date_min': args.get('date_min'),
        'date_max': args.get('date_max'),
        'prefer': args.get('prefer'),
        'max_wait': arg_to_number(args.get('max_wait')) if args.get('max_wait') else None,
        'with_metadata': argToBoolean(args.get('with_metadata')) if 'with_metadata' in args else None,
        'skip': arg_to_number(args.get('skip')) if args.get('skip') else None,
        'limit': arg_to_number(args.get('limit')) if args.get('limit') else None
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        raw_response = client.get_domain_certificates(domain, **params)

        certificates = raw_response.get('response', {}).get('domain_certificates', [])
        metadata = raw_response.get('response', {}).get('metadata', {})

        if not certificates:
            return CommandResults(
                readable_output=f"No certificates found for domain: {domain}",
                outputs_prefix='SilentPush.Certificate',
                outputs_key_field='domain',
                outputs={'domain': domain, 'certificates': [], 'metadata': metadata},
                raw_response=raw_response
            )

        markdown = [f"# SSL/TLS Certificate Information for Domain: {domain}\n"]
        for cert in certificates:
            subject = client.parse_subject(cert.get('subject', {}))
            cert_info = {
                'Issuer': cert.get('issuer', 'N/A'),
                'Issued On': cert.get('not_before', 'N/A'),
                'Expires On': cert.get('not_after', 'N/A'),
                'Common Name': subject.get('CN', 'N/A'),
                'Subject Alternative Names': ', '.join(cert.get('domains', [])),
                'Serial Number': cert.get('serial_number', 'N/A'),
                'Fingerprint SHA256': cert.get('fingerprint_sha256', 'N/A'),
            }
            markdown.append(tableToMarkdown('Certificate Information', [cert_info]))

        return CommandResults(
            outputs_prefix='SilentPush.Certificate',
            outputs_key_field='domain',
            outputs={'domain': domain, 'certificates': certificates, 'metadata': metadata},
            readable_output='\n'.join(markdown),
            raw_response=raw_response
        )

    except Exception as e:
        raise DemistoException(f"Error retrieving certificates for domain '{domain}': {str(e)}")


def search_domains_command(client: Client, args: dict) -> CommandResults:
    query = args.get('query')
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    risk_score_min = arg_to_number(args.get('risk_score_min'))
    risk_score_max = arg_to_number(args.get('risk_score_max'))
    limit = arg_to_number(args.get('limit', 100))
    domain_regex = args.get('domain_regex')
    name_server = args.get('name_server')
    asnum = arg_to_number(args.get('asnum'))
    asname = args.get('asname')
    min_ip_diversity = arg_to_number(args.get('min_ip_diversity'))
    registrar = args.get('registrar')
    min_asn_diversity = arg_to_number(args.get('min_asn_diversity'))
    certificate_issuer = args.get('certificate_issuer')
    whois_date_after = args.get('whois_date_after')
    skip = arg_to_number(args.get('skip'))

    try:
        raw_response = client.search_domains(
            query=query,
            start_date=start_date,
            end_date=end_date,
            risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
            limit=limit,
            domain_regex=domain_regex,
            name_server=name_server,
            asnum=asnum,
            asname=asname,
            min_ip_diversity=min_ip_diversity,
            registrar=registrar,
            min_asn_diversity=min_asn_diversity,
            certificate_issuer=certificate_issuer,
            whois_date_after=whois_date_after,
            skip=skip
        )
    except Exception as e:
        return CommandResults(
            readable_output=f"Error: {str(e)}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error'
        )

    if raw_response.get('error'):
        return CommandResults(
            readable_output=f"Error: {raw_response['error']}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error'
        )

    records = raw_response.get('response', {}).get('records', [])

    if not records:
        return CommandResults(
            readable_output="No domains found.",
            raw_response=raw_response,
            outputs_prefix='SilentPush.SearchResults',
            outputs_key_field='domain',
            outputs=raw_response
        )

    readable_output = tableToMarkdown('Domain Search Results', records)

    return CommandResults(
        outputs_prefix='SilentPush.SearchResults',
        outputs_key_field='domain',
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response
    )

def list_domain_infratags_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to retrieve domain infratags with optional cluster details.

    Args:
        client (Client): SilentPush API client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Formatted results of the infratags lookup.
    """
    domains = argToList(args.get('domains', ''))
    cluster = argToBoolean(args.get('cluster', False))
    mode = args.get('mode', 'live')
    match = args.get('match', 'self')
    as_of = args.get('as_of', None)
    origin_uid = args.get('origin_uid', None)
    use_get = argToBoolean(args.get('use_get', False))

    if not domains and not use_get:
        raise ValueError('"domains" argument is required when using POST.')


    raw_response = client.list_domain_infratags(domains, cluster, mode, match, as_of, origin_uid, use_get)
    infratags = raw_response.get('response', {}).get('infratags', [])
    tag_clusters = raw_response.get('response', {}).get('tag_clusters', [])


    readable_output = tableToMarkdown('Domain Infratags', infratags)

    if cluster and tag_clusters:
        cluster_details = []
        for cluster in tag_clusters:
            for key, value in cluster.items():
                cluster_details.append({'Cluster Level': key, 'Details': value})

        readable_output += tableToMarkdown('Domain Tag Clusters', cluster_details)

    if cluster and not tag_clusters:
        readable_output += "\n\n**No tag cluster data returned by the API.**"

    return CommandResults(
        outputs_prefix='SilentPush.InfraTags',
        outputs_key_field='domain',
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response
    )




def get_enrichment_data_command(client: Client, args: dict) -> CommandResults:
    resource = args.get("resource")
    value = args.get("value")
    explain = argToBoolean(args.get("explain", False))
    scan_data = argToBoolean(args.get("scan_data", False))

    if not resource or not value:
        raise ValueError("Both 'resource' and 'value' arguments are required.")


    if resource in ["ipv4", "ipv6"]:
        is_valid_ip = client.validate_ip_address(value, allow_ipv6=(resource == "ipv6"))
        if not is_valid_ip:
            raise DemistoException(f"Invalid {resource.upper()} address: {value}")


    enrichment_data = client.get_enrichment_data(resource, value, explain, scan_data)

    if not enrichment_data:
        return CommandResults(
            readable_output=f"No enrichment data found for resource: {value}",
            outputs_prefix="SilentPush.Enrichment",
            outputs_key_field="value",
            outputs={"value": value, "data": {}},
            raw_response=enrichment_data
        )

    readable_output = tableToMarkdown(
        f"Enrichment Data for {value}",
        enrichment_data,
        removeNull=True
    )

    return CommandResults(
        outputs_prefix="SilentPush.Enrichment",
        outputs_key_field="value",
        outputs={"value": value, **enrichment_data},
        readable_output=readable_output,
        raw_response=enrichment_data
    )


def list_ip_information_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ips = argToList(args.get("ips", ""))

    if not ips:
        raise ValueError("The 'ips' parameter is required.")


    ipv4_addresses = []
    ipv6_addresses = []

    for ip in ips:
        if client.validate_ip_address(ip, allow_ipv6=False):
            ipv4_addresses.append(ip)
        elif client.validate_ip_address(ip, allow_ipv6=True):
            ipv6_addresses.append(ip)


    results = []
    if ipv4_addresses:
        ipv4_info = client.list_ip_information(ipv4_addresses, resource="ipv4")
        results.extend(ipv4_info.get("response", {}).get("ip2asn", []))

    if ipv6_addresses:
        ipv6_info = client.list_ip_information(ipv6_addresses, resource="ipv6")
        results.extend(ipv6_info.get("response", {}).get("ip2asn", []))

    if not results:
        return CommandResults(
            readable_output=f"No information found for IPs: {', '.join(ips)}",
            outputs_prefix="SilentPush.IPInformation",
            outputs_key_field="ip",
            outputs=[],
            raw_response={"ips": ips, "results": results},
        )


    readable_output = tableToMarkdown(
        "Comprehensive IP Information",
        results,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="SilentPush.IPInformation",
        outputs_key_field="ip",
        outputs=results,
        readable_output=readable_output,
        raw_response={"ips": ips, "results": results},
    )





def get_asn_reputation_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for retrieving ASN reputation data.

    Args:
        client (Client): The API client instance
        args (dict): Command arguments containing:
            - asn: ASN number
            - limit (optional): Maximum results to return
            - explain (optional): Whether to include explanation

    Returns:
        CommandResults: Formatted command results for XSOAR
    """
    asn = args.get("asn")
    limit = arg_to_number(args.get("limit", None))
    explain = argToBoolean(args.get("explain", False))

    if not asn:
        raise ValueError("ASN is required.")

    try:
        raw_response = client.get_asn_reputation(asn, limit, explain)

        response_data = raw_response.get('response', {})
        asn_reputation = response_data.get('asn_reputation') or response_data.get('asn_reputation_history', [])

        asn_reputation = sorted(
            asn_reputation,
            key=lambda x: x.get('date', ''),
            reverse=True
        )

        if not asn_reputation:
            return CommandResults(
                readable_output=f"No reputation data found for ASN {asn}.",
                outputs_prefix="SilentPush.ASNReputation",
                outputs_key_field="asn",
                outputs=[],
                raw_response=raw_response
            )

        data_for_table = []
        for entry in asn_reputation:
            row = {
                'ASN': entry.get('asn'),
                'Reputation': entry.get('asn_reputation'),
                'ASName': entry.get('asname'),
                'Date': entry.get('date')
            }
            if explain and entry.get('explanation'):
                row['Explanation'] = entry.get('explanation')
            data_for_table.append(row)

        headers = ['ASN', 'Reputation', 'ASName', 'Date']
        if explain:
            headers.append('Explanation')

        readable_output = tableToMarkdown(
            f'ASN Reputation for {asn}',
            data_for_table,
            headers=headers,
            removeNull=True
        )

        return CommandResults(
            outputs_prefix="SilentPush.ASNReputation",
            outputs_key_field="asn",
            outputs={
                'asn': asn,
                'reputation_data': asn_reputation
            },
            readable_output=readable_output,
            raw_response=raw_response
        )

    except Exception as e:
        raise DemistoException(f"Error retrieving ASN reputation data: {str(e)}")

def get_asn_takedown_reputation_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for retrieving ASN takedown reputation.

    Args:
        client (Client): The API client instance
        args (dict): Command arguments

    Returns:
        CommandResults: Command results for XSOAR
    """
    asn = args.get('asn')
    if not asn:
        raise ValueError('ASN is a required parameter')

    try:
        limit = int(args.get('limit')) if args.get('limit') else None
    except ValueError:
        raise ValueError('limit must be a valid number')

    explain = argToBoolean(args.get('explain', False))

    try:
        response = client.get_asn_takedown_reputation(asn=asn, limit=limit, explain=explain)

        if not response:
            return CommandResults(
                readable_output=f'No takedown reputation data found for ASN {asn}',
                outputs_prefix='SilentPush.ASNTakedownReputation',
                outputs=None
            )

        reputation_data = {
            'ASN': response.get('asn', asn),
            'AS Name': response.get('asname', 'N/A'),
            'Allocation Date': response.get('asn_allocation_date', 'N/A'),
            'Takedown Reputation': response.get('asn_takedown_reputation', 'N/A'),
            'Allocation Age': response.get('asn_allocation_age', 'N/A')
        }

        headers = ['ASN', 'AS Name', 'Allocation Date', 'Takedown Reputation', 'Allocation Age']

        readable_output = tableToMarkdown(
            f'ASN Takedown Reputation Information for {asn}',
            [reputation_data],
            headers=headers,
            removeNull=True
        )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='SilentPush.ASNTakedownReputation',
            outputs_key_field='asn',
            outputs=reputation_data,
            raw_response=response
        )

    except Exception as e:
        raise DemistoException(f'Error retrieving ASN takedown reputation: {str(e)}')


def get_ipv4_reputation_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ipv4 = args.get('ipv4')
    if not ipv4:
        raise DemistoException("IPv4 address is required")

    explain = argToBoolean(args.get('explain', "false"))
    limit = arg_to_number(args.get('limit'))

    raw_response = client.get_ipv4_reputation(ipv4, explain, limit)


    if not raw_response:

        return CommandResults(
            readable_output=f"No reputation data found for IPv4: {ipv4}",
            outputs_prefix='SilentPush.IPv4Reputation',
            outputs_key_field='ip',
            outputs={'ip': ipv4},
            raw_response=raw_response
        )

    latest_reputation = raw_response[0]



    reputation_data = {
        'IP': latest_reputation.get('ip', ipv4),
        'Date': latest_reputation.get('date'),
        'Reputation Score': latest_reputation.get('ip_reputation')
    }

    readable_output = tableToMarkdown(
        f'IPv4 Reputation Information for {ipv4}',
        [reputation_data]
    )

    return CommandResults(
        outputs_prefix='SilentPush.IPv4Reputation',
        outputs_key_field='ip',
        outputs=reputation_data,
        readable_output=readable_output,
        raw_response=raw_response
    )


def get_job_status_command(client: Client, args: dict) -> CommandResults:
    job_id = args.get('job_id')
    max_wait = arg_to_number(args.get('max_wait'))
    result_type = args.get('result_type')

    if not job_id:
        raise DemistoException("job_id is a required parameter")

    try:
        raw_response = client.get_job_status(job_id, max_wait, result_type)

        job_status = raw_response.get('response', {})

        headers = list(job_status.keys())
        rows = [job_status]

        readable_output = tableToMarkdown(
            f"Job Status for Job ID: {job_id}",
            rows,
            headers=headers,
            removeNull=True
        )

        return CommandResults(
            outputs_prefix='SilentPush.JobStatus',
            outputs_key_field='job_id',
            outputs={'job_id': job_id, **job_status},
            readable_output=readable_output,
            raw_response=raw_response
        )

    except Exception as e:
        return CommandResults(
            readable_output=f"Error retrieving job status: {str(e)}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error',
            outputs={'error': str(e)}
        )

def get_nameserver_reputation_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for retrieving nameserver reputation.

    Args:
        client (Client): The API client instance.
        args (dict): Command arguments.

    Returns:
        CommandResults: The command results containing nameserver reputation data.
    """
    nameserver = args.get("nameserver")
    explain = argToBoolean(args.get("explain", "false"))
    limit = arg_to_number(args.get("limit"))

    if not nameserver:
        raise ValueError("Nameserver is required.")

    try:

        reputation_data = client.get_nameserver_reputation(nameserver, explain, limit)


        if reputation_data:
            readable_output = tableToMarkdown(
                f"Nameserver Reputation for {nameserver}",
                reputation_data,
                headers=["ns_server", "ns_server_reputation", "date"],
                removeNull=True
            )
        else:
            readable_output = f"No reputation history found for nameserver: {nameserver}"

        return CommandResults(
            outputs_prefix="SilentPush.NameserverReputation",
            outputs_key_field="ns_server",
            outputs={"nameserver": nameserver, "reputation_data": reputation_data},
            readable_output=readable_output,
            raw_response=reputation_data
        )

    except Exception as e:
        raise DemistoException(f"Error retrieving nameserver reputation: {e}")

def get_subnet_reputation_command(client: Client, args: dict) -> CommandResults:
    subnet = args.get('subnet')
    explain = argToBoolean(args.get('explain', False))
    limit = arg_to_number(args.get('limit'))

    if not subnet:
        raise DemistoException("Subnet is a required parameter.")

    try:
        raw_response = client.get_subnet_reputation(subnet, explain, limit)

        subnet_reputation = raw_response.get('response', {}).get('subnet_reputation_history', [])

        if not subnet_reputation:
            readable_output = f"No reputation history found for subnet: {subnet}"
        else:
            readable_output = tableToMarkdown(
                f"Subnet Reputation for {subnet}",
                subnet_reputation,
                removeNull=True
            )

        return CommandResults(
            outputs_prefix='SilentPush.SubnetReputation',
            outputs_key_field='subnet',
            outputs={'subnet': subnet, 'reputation_history': subnet_reputation},
            readable_output=readable_output,
            raw_response=raw_response
        )

    except Exception as e:
        return CommandResults(
            readable_output=f"Error retrieving subnet reputation: {str(e)}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error',
            outputs={'error': str(e)}
        )

def get_asns_for_domain_command(client: Client, args: dict) -> CommandResults:
    domain = args.get('domain')

    if not domain:
        raise DemistoException("domain is a required parameter")

    try:
        raw_response = client.get_asns_for_domain(domain)

        records = raw_response.get('response', {}).get('records', [])

        if not records or 'domain_asns' not in records[0]:
            readable_output = f"No ASNs found for domain: {domain}"
            asns = []
        else:
            domain_asns = records[0]['domain_asns']

            asns = [{'ASN': asn, 'Description': description}
                    for asn, description in domain_asns.items()]

            readable_output = tableToMarkdown(
                f"ASNs for Domain: {domain}",
                asns,
                headers=['ASN', 'Description']
            )

        return CommandResults(
            outputs_prefix='SilentPush.DomainASNs',
            outputs_key_field='domain',
            outputs={
                'domain': domain,
                'asns': asns
            },
            readable_output=readable_output,
            raw_response=raw_response
        )

    except Exception as e:
        return CommandResults(
            readable_output=f"Error retrieving domain ASNs: {str(e)}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error',
            outputs={'error': str(e)}
        )

def forward_padns_lookup_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to perform forward PADNS lookup.

    Args:
        client (Client): SilentPush API client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Formatted results of the PADNS lookup.
    """
    qtype = args.get('qtype')
    qname = args.get('qname')

    if not qtype or not qname:
        raise DemistoException("Both 'qtype' and 'qname' are required parameters.")

    netmask = args.get('netmask')
    subdomains = argToBoolean(args.get('subdomains')) if 'subdomains' in args else None
    regex = args.get('regex')
    match = args.get('match')
    first_seen_after = args.get('first_seen_after')
    first_seen_before = args.get('first_seen_before')
    last_seen_after = args.get('last_seen_after')
    last_seen_before = args.get('last_seen_before')
    as_of = args.get('as_of')
    sort = args.get('sort')
    output_format = args.get('output_format')
    prefer = args.get('prefer')
    with_metadata = argToBoolean(args.get('with_metadata')) if 'with_metadata' in args else None
    max_wait = arg_to_number(args.get('max_wait'))
    skip = arg_to_number(args.get('skip'))
    limit = arg_to_number(args.get('limit'))

    try:
        raw_response = client.forward_padns_lookup(
            qtype=qtype,
            qname=qname,
            netmask=netmask,
            subdomains=subdomains,
            regex=regex,
            match=match,
            first_seen_after=first_seen_after,
            first_seen_before=first_seen_before,
            last_seen_after=last_seen_after,
            last_seen_before=last_seen_before,
            as_of=as_of,
            sort=sort,
            output_format=output_format,
            prefer=prefer,
            with_metadata=with_metadata,
            max_wait=max_wait,
            skip=skip,
            limit=limit
        )

        records = raw_response.get('response', {}).get('records', [])

        if not records:
            readable_output = f"No records found for {qtype} {qname}"
        else:
            readable_output = tableToMarkdown(
                f"PADNS Lookup Results for {qtype} {qname}",
                records,
                removeNull=True
            )

        return CommandResults(
            outputs_prefix='SilentPush.PADNSLookup',
            outputs_key_field='qname',
            outputs={
                'qtype': qtype,
                'qname': qname,
                'records': records
            },
            readable_output=readable_output,
            raw_response=raw_response
        )

    except Exception as e:
        return CommandResults(
            readable_output=f"Error performing PADNS lookup: {str(e)}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error',
            outputs={'error': str(e)}
        )
def reverse_padns_lookup_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to perform reverse PADNS lookup.

    Args:
        client (Client): SilentPush API client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Formatted results of the reverse PADNS lookup.
    """
    qtype = args.get('qtype')
    qname = args.get('qname')

    if not qtype or not qname:
        raise DemistoException("Both 'qtype' and 'qname' are required parameters.")


    filtered_args = {
        key: value
        for key, value in args.items()
        if key not in ('qtype', 'qname')
    }

    try:

        raw_response = client.reverse_padns_lookup(
            qtype=qtype,
            qname=qname,
            **filtered_args
        )


        if raw_response.get('error'):
            raise DemistoException(
                f"API Error: {raw_response.get('error')}"
            )


        records = raw_response.get('response', {}).get('records', [])
        if not records:
            readable_output = f"No records found for {qtype} {qname}"
        else:
            readable_output = tableToMarkdown(
                f"Reverse PADNS Lookup Results for {qtype} {qname}",
                records,
                removeNull=True
            )

        return CommandResults(
            outputs_prefix='SilentPush.ReversePADNSLookup',
            outputs_key_field='qname',
            outputs={'qtype': qtype, 'qname': qname, 'records': records},
            readable_output=readable_output,
            raw_response=raw_response
        )

    except Exception as e:
        return CommandResults(
            readable_output=f"Error performing reverse PADNS lookup: {str(e)}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error',
            outputs={'error': str(e)}
        )




def density_lookup_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to perform density lookup.

    Args:
        client (Client): SilentPush API client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Formatted results of the density lookup.
    """
    qtype = args.get('qtype')
    query = args.get('query')

    if not qtype or not query:
        raise DemistoException("Both 'qtype' and 'query' are required parameters.")

    scope = args.get('scope')

    try:
        raw_response = client.density_lookup(
            qtype=qtype,
            query=query,
            scope=scope
        )

        records = raw_response.get('response', {}).get('records', [])

        if not records:
            readable_output = f"No density records found for {qtype} {query}"
        else:
            readable_output = tableToMarkdown(
                f"Density Lookup Results for {qtype} {query}",
                records,
                removeNull=True
            )

        return CommandResults(
            outputs_prefix='SilentPush.DensityLookup',
            outputs_key_field='query',
            outputs={
                'qtype': qtype,
                'query': query,
                'records': records
            },
            readable_output=readable_output,
            raw_response=raw_response
        )

    except Exception as e:
        return CommandResults(
            readable_output=f"Error performing density lookup: {str(e)}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error',
            outputs={'error': str(e)}
        )

def search_scan_data_command(client: Client, args: dict) -> CommandResults:
    """
    Search scan data command handler.

    Args:
        client (Client): SilentPush API client
        args (dict): Command arguments:
            - query (str): Required. SPQL syntax query

    Returns:
        CommandResults: Command results with formatted output
    """
    query = args.get('query')
    if not query:
        raise ValueError('Query parameter is required')

    try:
        raw_response = client.search_scan_data(query=query)

        scan_data = raw_response.get('response', {}).get('scandata_raw', [])

        if not scan_data:
            return CommandResults(
                readable_output="No scan data records found",
                outputs_prefix='SilentPush.ScanData',
                outputs=None
            )
        readable_output = tableToMarkdown(
            "Raw Scan Data Results",
            scan_data,
            removeNull=True
        )

        return CommandResults(
            outputs_prefix='SilentPush.ScanData',
            outputs_key_field='domain',
            outputs={
                'records': scan_data,
                'query': query
            },
            readable_output=readable_output,
            raw_response=raw_response
        )

    except Exception as e:
        raise DemistoException(f"Error in search scan data command: {str(e)}")



def live_url_scan_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for live URL scan command.

    Args:
        client (Client): The SilentPush API client
        args (dict): Command arguments

    Returns:
        CommandResults: Results of the URL scan
    """
    url = args.get('url')
    if not url:
        raise DemistoException("URL is a required parameter")

    platform = args.get('platform')
    os = args.get('os')
    browser = args.get('browser')
    region = args.get('region')
    valid_platforms = ['Desktop', 'Mobile', 'Crawler']
    if platform and platform not in valid_platforms:
        raise DemistoException(f"Invalid platform. Must be one of: {', '.join(valid_platforms)}")

    valid_os = ['Windows', 'Linux', 'MacOS', 'iOS', 'Android']
    if os and os not in valid_os:
        raise DemistoException(f"Invalid OS. Must be one of: {', '.join(valid_os)}")

    valid_browsers = ['Firefox', 'Chrome', 'Edge', 'Safari']
    if browser and browser not in valid_browsers:
        raise DemistoException(f"Invalid browser. Must be one of: {', '.join(valid_browsers)}")

    valid_regions = ['US', 'EU', 'AS', 'TOR']
    if region and region not in valid_regions:
        raise DemistoException(f"Invalid region. Must be one of: {', '.join(valid_regions)}")

    try:
        raw_response = client.live_url_scan(url, platform, os, browser, region)
        scan_results = raw_response.get('response', {}).get('scan', {})

        if not isinstance(scan_results, dict):
            readable_output = f"Unexpected response format for URL scan. Response: {scan_results}"
        elif not scan_results:
            readable_output = f"No scan results found for URL: {url}"
        else:
            headers = list(scan_results.keys())
            readable_output = tableToMarkdown(
                f"URL Scan Results for {url}",
                [scan_results],
                headers=headers,
                removeNull=True
            )

        return CommandResults(
            outputs_prefix='SilentPush.URLScan',
            outputs_key_field='url',
            outputs={
                'url': url,
                'scan_results': scan_results
            },
            readable_output=readable_output,
            raw_response=raw_response
        )

    except Exception as e:
        return CommandResults(
            readable_output=f"Error performing URL scan: {str(e)}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error',
            outputs={'error': str(e)}
        )



def get_future_attack_indicators_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for retrieving indicators of future attack feed.

    Args:
        client (Client): SilentPush API client instance
        args (dict): Command arguments

    Returns:
        CommandResults: Results for XSOAR

    Raises:
        ValueError: If required parameters are missing
    """
    feed_uuid = args.get('feed_uuid')
    if not feed_uuid:
        raise ValueError("feed_uuid is a required parameter")

    page_no = arg_to_number(args.get('page_no', 1))
    page_size = arg_to_number(args.get('page_size', 10000))

    try:
        raw_response = client.get_future_attack_indicators(
            feed_uuid=feed_uuid,
            page_no=page_no,
            page_size=page_size
        )
        headers = list(raw_response[0].keys())
        readable_output = tableToMarkdown(
                f"# Future Attack Indicators\nFeed UUID: {feed_uuid}\n",
                raw_response,
                headers=headers,
                removeNull=True
            )
        return CommandResults(
            outputs_prefix='SilentPush.FutureAttackIndicators',
            outputs_key_field='feed_uuid',
            outputs={
                'feed_uuid': feed_uuid,
                'page_no': page_no,
                'page_size': page_size,
                'indicators': raw_response
            },
            readable_output=readable_output,
            raw_response=raw_response
        )

    except Exception as e:
        return CommandResults(
            readable_output=f"Error retrieving future attack indicators: {str(e)}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error',
            outputs={'error': str(e)}
        )


def screenshot_url_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command handler for taking URL screenshots

    Args:
        client (Client): SilentPush API client instance
        args (Dict[str, Any]): Command arguments

    Returns:
        CommandResults: Results including screenshot data and vault info
    """
    url = args.get("url")
    if not url:
        raise ValueError("URL is required")

    try:
        result = client.screenshot_url(url)
        readable_output = f"### Screenshot captured for {url}\n"
        readable_output += f"- Status: Success\n"
        readable_output += f"- Screenshot URL: {result['screenshot_url']}\n"
        readable_output += f"- File ID: {result['vault_info']['FileID']}"
        readable_output += f"- File Name: {result['filename']}"


        return CommandResults(
            outputs_prefix="SilentPush.Screenshot",
            outputs_key_field="url",
            outputs={
                "url": url,
                "status": "success",
                "status_code": result["status_code"],
                "screenshot_url": result["screenshot_url"],
                "file_id": result["vault_info"]["FileID"],
                "file_name": result["filename"]
            },
            readable_output=readable_output,
            raw_response=result
        )

    except Exception as e:
        raise DemistoException(f"Failed to capture screenshot: {str(e)}")

def main():

    try:
        params = demisto.params()
        api_key = params.get('credentials', {}).get('password')
        base_url = params.get('url', 'https://api.silentpush.com')
        verify_ssl = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_ssl,
            proxy=proxy
        )

        command = demisto.command()

        command_handlers = {
            'test-module': test_module,
            'silentpush-list-domain-information': list_domain_information_command,
            'silentpush-get-domain-certificates': get_domain_certificates_command,
            'silentpush-search-domains': search_domains_command,
            'silentpush-list-domain-infratags': list_domain_infratags_command,
            'silentpush-get-enrichment-data' : get_enrichment_data_command,
            'silentpush-list-ip-information' : list_ip_information_command,
            'silentpush-get-asn-reputation' : get_asn_reputation_command,
            'silentpush-get-asn-takedown-reputation': get_asn_takedown_reputation_command,
            'silentpush-get-ipv4-reputation': get_ipv4_reputation_command,
            'silentpush-get-job-status': get_job_status_command,
            'silentpush-get-nameserver-reputation': get_nameserver_reputation_command,
            'silentpush-get-subnet-reputation': get_subnet_reputation_command,
            'silentpush-get-asns-for-domain': get_asns_for_domain_command,
            'silentpush-forward-padns-lookup': forward_padns_lookup_command,
            'silentpush-reverse-padns-lookup': reverse_padns_lookup_command,
            'silentpush-density-lookup': density_lookup_command,
            'silentpush-search-scan-data': search_scan_data_command,
            'silentpush-live-url-scan': live_url_scan_command,
            'silentpush-get-future-attack-indicators': get_future_attack_indicators_command,
            'silentpush-screenshot-url': screenshot_url_command
        }

        if command in command_handlers:
            if command == 'test-module':
                result = command_handlers[command](client)
                return_results(result)
            else:
                return_results(command_handlers[command](client, demisto.args()))
        else:
            raise DemistoException(f'Unsupported command: {command}')

    except Exception as e:
        demisto.error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
