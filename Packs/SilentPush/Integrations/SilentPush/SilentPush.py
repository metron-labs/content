
"""Base Integration for Cortex XSOAR (aka Demisto)

This is an integration to interact with the SilentPush API and provide functionality within XSOAR.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting
"""

import requests
import urllib3
from typing import Any, Optional, Dict

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
            if response.status_code not in {200, 201}:
                raise DemistoException(f'Error in API call [{response.status_code}] - {response.text}')
            try:
                return response.json() 
            except ValueError:  
                raise DemistoException(f"API response is not JSON: {response.text}")
        except Exception as e:
            raise DemistoException(f'Error in API call: {str(e)}')



    def list_domain_information(self, domains: List[str], fetch_risk_score: Optional[bool] = False, fetch_whois_info: Optional[bool] = False) -> Dict:
        if len(domains) > 100:
            raise DemistoException("Maximum of 100 domains can be submitted in a single request.")

        domains_data = {'domains': domains}
        bulk_info_response = self._http_request('POST', 'explore/bulk/domaininfo', data=domains_data)

        domain_info_list = bulk_info_response.get('response', {}).get('domaininfo', [])
        domain_info_dict = {item['domain']: item for item in domain_info_list}

        risk_score_dict = {}
        if fetch_risk_score:
            bulk_risk_response = self._http_request('POST', 'explore/bulk/domain/riskscore', data=domains_data)
            risk_score_list = bulk_risk_response.get('response', [])
            risk_score_dict = {item['domain']: item for item in risk_score_list}

        live_whois_info = {}
        if fetch_whois_info:
            for domain in domains:
                try:
                    live_whois_response = self._http_request('GET', f'explore/domain/whoislive/{domain}')
                    live_whois_info[domain] = live_whois_response.get('response', {})
                except Exception as e:
                    live_whois_info[domain] = {'error': str(e)}

        combined_results = [{
            'domain': domain,
            **domain_info_dict.get(domain, {}),
            'sp_risk_score': risk_score_dict.get(domain, {}).get('sp_risk_score', 'N/A'),
            'sp_risk_score_explain': risk_score_dict.get(domain, {}).get('sp_risk_score_explain', 'N/A'),
            'whois_info': live_whois_info.get(domain, 'N/A')
        } for domain in domains]

        return {'domains': combined_results}

    def get_domain_certificates(self, domain: str, **kwargs) -> dict:
        url_suffix = f"explore/domain/certificates/{domain}"
        params = {k: v for k, v in kwargs.items() if v is not None}
        response = self._http_request('GET', url_suffix, params=params)
        demisto.debug(f"Raw response for get_domain_certificates: {response}")
        return response


    def search_domains(self, query: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None, risk_score_min: Optional[int] = None, risk_score_max: Optional[int] = None, limit: int = 100, domain_regex: Optional[str] = None, name_server: Optional[str] = None, asnum: Optional[int] = None, asname: Optional[str] = None, min_ip_diversity: Optional[int] = None, registrar: Optional[str] = None, min_asn_diversity: Optional[int] = None, certificate_issuer: Optional[str] = None, whois_date_after: Optional[str] = None, skip: Optional[int] = None) -> dict:
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

    def list_domain_infratags(self, domains: list, cluster: bool = False, mode: str = 'live', match: str = 'self', as_of: Optional[str] = None) -> dict:
        url = 'explore/bulk/domain/infratags'
        payload = {
            'domains': domains
        }
        params = {
            'mode': mode,
            'match': match,
            'clusters': cluster
        }

        if as_of:
            params['as_of'] = as_of

        response = self._http_request(
            method='POST',
            url_suffix=url,
            params=params,
            data=payload
        )

        return response

    def get_enrichment_data(self, resource: str, value: str, explain: Optional[bool] = False, scan_data: Optional[bool] = False) -> dict:
        endpoint = f"explore/enrich/{resource}/{value}"
        
        query_params = {}
        if explain:
            query_params["explain"] = int(explain)
        if scan_data:
            query_params["scan_data"] = int(scan_data)
        
        response = self._http_request(
            method="GET",
            url_suffix=endpoint,
            params=query_params
        )

        if resource in ["ip", "ipv4", "ipv6"]:
            ip2asn_data = response.get("response", {}).get("ip2asn", [])
            if isinstance(ip2asn_data, list) and ip2asn_data: 
                return ip2asn_data[0]  
            else:
                return {}  
        else:
            return response.get("response", {}).get("domaininfo", {})



    def get_asn_reputation(self, asn: int, explain: bool = False, limit: int = None) -> Dict[str, Any]:
        url_suffix = f"explore/ipreputation/history/asn/{asn}"
        query_params = {}
        if explain:
            query_params['explain'] = 'true'
        if limit:
            query_params['limit'] = limit
        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=query_params
        )
        return response

    def get_asn_takedown_reputation(self, args):
        asn = args.get('asn')
        explain = argToBoolean(args.get('explain', 'false'))
        limit = args.get('limit')

        if not asn:
            raise ValueError('The "asn" argument is required.')

        endpoint = f'explore/takedownreputation/asn/{asn}'

        params = {}
        if explain:
            params['explain'] = explain
        if limit:
            params['limit'] = limit

        response = self._http_request(
            method='GET',
            url_suffix=endpoint,
            params=params
        )

        outputs = response.get('response', {}).get('takedown_reputation', {})
        
        readable_output = tableToMarkdown(
            f'Takedown Reputation for ASN {asn}',
            [outputs],
            headers=['asn', 'asname', 'asn_allocation_date', 'asn_allocation_date', 'asn_takedown_reputation']
        )

        return CommandResults(
            outputs_prefix='SilentPush.TakedownReputation',
            outputs_key_field='asn',
            outputs=outputs,
            readable_output=readable_output,
            raw_response=response
        )

    def get_ipv4_reputation(self, ipv4, explain=False, limit=None):
        url_suffix = f"explore/ipreputation/ipv4/{ipv4}"  
        params = {}
        if explain:
            params['explain'] = 'true'
        if limit is not None:
            params['limit'] = limit

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params
        )

        return response
    
    def get_job_status(self, job_id: str, max_wait: Optional[int] = None, result_type: Optional[str] = None) -> Dict[str, Any]:
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
    
    def get_nameserver_reputation(self, nameserver: str, explain: Optional[bool] = False, limit: Optional[int] = None) -> Dict[str, Any]:
        url_suffix = f"explore/nsreputation/history/nameserver/{nameserver}"
        
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
    
    def get_subnet_reputation(self, subnet: str, explain: Optional[bool] = False, limit: Optional[int] = None) -> Dict[str, Any]:
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
        url_suffix = f"explore/padns/lookup/domain/asns/{domain}"

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix
        )

        return response



def test_module(client: Client) -> str:
    try:
        client.list_domain_information('silentpush.com')
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        raise e

def list_domain_information_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    domains_arg = args.get('domains') or args.get('domain')
    if not domains_arg:
        raise DemistoException('No domains provided')

    domains = [domain.strip() for domain in domains_arg.split(',') if domain.strip()]
    fetch_risk_score = argToBoolean(args.get('fetch_risk_score', False))
    fetch_whois_info = argToBoolean(args.get('fetch_whois_info', False))

    raw_response = client.list_domain_information(domains, fetch_risk_score, fetch_whois_info)

    markdown = ['# Domain Information Results\n']
    for domain_info in raw_response.get('domains', []):
        markdown.append(f"## Domain: {domain_info.get('domain', 'N/A')}")

        basic_info = {
            'Created Date': domain_info.get('whois_created_date', 'N/A'),
            'Updated Date': domain_info.get('whois_updated_date', 'N/A'),
            'Expiration Date': domain_info.get('whois_expiration_date', 'N/A'),
            'Registrar': domain_info.get('registrar', 'N/A'),
            'Status': domain_info.get('status', 'N/A'),
            'Name Servers': domain_info.get('nameservers', 'N/A')
        }
        markdown.append(tableToMarkdown('Domain Information', [basic_info]))

        if fetch_risk_score:
            risk_info = {
                'Risk Score': domain_info.get('sp_risk_score', 'N/A'),
                'Risk Score Explanation': domain_info.get('sp_risk_score_explain', 'N/A')
            }
            markdown.append(tableToMarkdown('Risk Assessment', [risk_info]))

        if fetch_whois_info and domain_info.get('whois_info') != 'N/A':
            whois_info = domain_info.get('whois_info', {})
            if isinstance(whois_info, dict):
                whois_data = {
                    'Registrant Name': whois_info.get('registrant_name', 'N/A'),
                    'Registrant Organization': whois_info.get('registrant_organization', 'N/A'),
                    'Registrant Email': whois_info.get('registrant_email', 'N/A'),
                    'Admin Email': whois_info.get('admin_email', 'N/A'),
                    'Tech Email': whois_info.get('tech_email', 'N/A')
                }
                markdown.append(tableToMarkdown('WHOIS Information', [whois_data]))

        markdown.append('\n---\n')

    return CommandResults(
        outputs_prefix='SilentPush.Domain',
        outputs_key_field='domain',
        outputs=raw_response.get('domains', []),
        readable_output='\n'.join(markdown),
        raw_response=raw_response
    )

def get_domain_certificates_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    domain = args.get('domain')
    if not domain:
        raise DemistoException('Domain argument is required.')

    params = {
        'domain_regex': args.get('domain_regex'),
        'certificate_issuer': args.get('certificate_issuer'),
        'date_min': args.get('date_min'),
        'date_max': args.get('date_max'),
        'prefer': args.get('prefer'),
        'max_wait': arg_to_number(args.get('max_wait')) if args.get('max_wait') else None,
        'with_metadata': argToBoolean(args.get('with_metadata')) if args.get('with_metadata') else None,
        'skip': arg_to_number(args.get('skip')) if args.get('skip') else None,
        'limit': arg_to_number(args.get('limit')) if args.get('limit') else None
    }
    params = {k: v for k, v in params.items() if v is not None}

    raw_response = client.get_domain_certificates(domain, **params)

    demisto.debug(f"Raw response for get_domain_certificates: {raw_response}")
    if not isinstance(raw_response, dict):
        raise DemistoException(f"Unexpected response format: {raw_response}")

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
        cert_info = {
            'Issuer': cert.get('issuer', 'N/A'),
            'Issued On': cert.get('not_before', 'N/A'),
            'Expires On': cert.get('not_after', 'N/A'),
            'Common Name': cert.get('subject', {}).get('CN', 'N/A'),
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
    domains = argToList(args.get('domains', ''))
    cluster = argToBoolean(args.get('cluster', False))
    mode = args.get('mode', 'live')
    match = args.get('match', 'self')
    as_of = args.get('as_of', None)

    if not domains:
        raise ValueError('"domains" argument is required and cannot be empty.')

    raw_response = client.list_domain_infratags(domains, cluster, mode, match, as_of)

    infratags = raw_response.get('response', {}).get('infratags', [])
    tag_clusters = raw_response.get('response', {}).get('tag_clusters', [])

    readable_output = tableToMarkdown('Domain Infratags', infratags)
    if tag_clusters:
        readable_output += tableToMarkdown('Domain Tag Clusters', tag_clusters)

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
    ips = args.get("ips")
    if not ips:
        raise ValueError("The 'ips' parameter is required.")
    
    response = client.list_ip_information(ips=ips)
    outputs = response.get("response", {}).get("ip2asn", [])

    readable_output = tableToMarkdown(
        "IP Information",
        outputs,
        headers=["ip", "asn", "organization", "country", "risk_score"],
        removeNull=True
    )

    return CommandResults(
        outputs_prefix="SilentPush.IPInformation",
        outputs_key_field="ip",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response
    )


def get_asn_reputation_command(self, args: dict) -> CommandResults:
    asn = args.get("asn")
    explain = argToBoolean(args.get("explain", False))
    limit = arg_to_number(args.get("limit", None))

    if not asn:
        raise ValueError("ASN is required.")

    try:
        asn_reputation_data = self.get_asn_reputation(asn, explain, limit)

        command_results = CommandResults(
            outputs_prefix="SilentPush.ASNReputation",
            outputs_key_field="asn",
            outputs=asn_reputation_data,
            raw_response=asn_reputation_data
        )

        return command_results

    except Exception as e:
        raise DemistoException(f"Error retrieving ASN reputation data: {str(e)}")

def get_asn_takedown_reputation_command(client: Client, args):
    return client.get_asn_takedown_reputation(args)

def get_ipv4_reputation_command(client: Client, args: dict) -> CommandResults:
    ipv4 = args.get('ipv4')
    if not ipv4:
        raise ValueError("The 'ipv4' parameter is required.")

    explain = argToBoolean(args.get('explain', False))
    limit = arg_to_number(args.get('limit', None))

    try:
        raw_response = client.get_ipv4_reputation(ipv4, explain, limit)
    except Exception as e:
        return CommandResults(
            readable_output=f"Error: {str(e)}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error'
        )

    ip_reputation = raw_response.get('response', {}).get('ip_reputation', [])

    if not ip_reputation:
        readable_output = f"No reputation information found for IPv4: {ipv4}"
    else:
        readable_output = tableToMarkdown(f"IPv4 Reputation for {ipv4}", ip_reputation)

    return CommandResults(
        outputs_prefix='SilentPush.IPv4Reputation',
        outputs_key_field='ip',
        outputs={
            'ip': ipv4,
            'reputation_history': ip_reputation
        },
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
    nameserver = args.get('nameserver')
    explain = argToBoolean(args.get('explain', False))
    limit = arg_to_number(args.get('limit'))

    if not nameserver:
        raise DemistoException("nameserver is a required parameter")

    try:
        raw_response = client.get_nameserver_reputation(nameserver, explain, limit)
        
        ns_reputation = raw_response.get('response', {})
        readable_output = tableToMarkdown(
            f"Nameserver Reputation for {nameserver}", 
            ns_reputation, 
            removeNull=True
        )

        return CommandResults(
            outputs_prefix='SilentPush.NameserverReputation',
            outputs_key_field='nameserver',
            outputs={'nameserver': nameserver, **ns_reputation},
            readable_output=readable_output,
            raw_response=raw_response
        )

    except Exception as e:
        return CommandResults(
            readable_output=f"Error retrieving nameserver reputation: {str(e)}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error',
            outputs={'error': str(e)}
        )
        
def get_subnet_reputation_command(client: Client, args: dict) -> CommandResults:
    subnet = args.get('subnet')
    explain = argToBoolean(args.get('explain', False))
    limit = arg_to_number(args.get('limit'))

    if not subnet:
        raise DemistoException("subnet is a required parameter")

    try:
        raw_response = client.get_subnet_reputation(subnet, explain, limit)
        
        subnet_reputation = raw_response.get('response', {})
        
        readable_output = tableToMarkdown(
            f"Subnet Reputation for {subnet}", 
            subnet_reputation, 
            removeNull=True
        )

        return CommandResults(
            outputs_prefix='SilentPush.SubnetReputation',
            outputs_key_field='subnet',
            outputs={'subnet': subnet, **subnet_reputation},
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
        
        asns = raw_response.get('response', {}).get('asns', [])
        
        readable_output = tableToMarkdown(
            f"ASNs for Domain: {domain}", 
            [{'ASN': asn} for asn in asns], 
            headers=['ASN']
        )

        return CommandResults(
            outputs_prefix='SilentPush.DomainASNs',
            outputs_key_field='domain',
            outputs={'domain': domain, 'asns': asns},
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
            'silentpush-get-asns-for-domain': get_asns_for_domain_command
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
