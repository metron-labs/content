import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Integration for Cortex XSOAR (aka Demisto)

This is an integration to interact with the SilentPush API and provide functionality within XSOAR.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting
"""

from CommonServerUserPython import *  # noqa

import requests
import urllib3
from typing import Any, Optional, Dict

# Disable insecure warnings
urllib3.disable_warnings()


def mock_debug(message):
    """Print debug messages to the XSOAR logs"""
    print(f"DEBUG: {message}")
demisto.debug = mock_debug

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
        demisto.debug(f'Initialized client with base URL: {self.base_url}')

    def _http_request(self, method: str, url_suffix: str, params: dict = None, data: dict = None) -> Any:
        """
        Handles the HTTP requests to the SilentPush API.
        
        This function builds the request URL, adds the necessary headers, and sends a request
        to the API. It returns the response in JSON format.
        
        Args:
            method (str): The HTTP method (GET, POST, etc.).
            url_suffix (str): The specific endpoint to be appended to the base URL.
            params (dict, optional): The URL parameters to be sent with the request.
            data (dict, optional): The data to be sent with the request.
        
        Returns:
            Any: The JSON response from the API.
        
        Raises:
            DemistoException: If there is an error in the API response.
        """
        full_url = f'{self.base_url}{url_suffix}'
        masked_headers = {k: v if k != 'X-API-Key' else '****' for k, v in self._headers.items()}
        demisto.debug(f'Headers: {masked_headers}')
        demisto.debug(f'Params: {params}')
        demisto.debug(f'Data: {data}')

        try:
            response = requests.request(
                method,
                full_url,
                headers=self._headers,
                verify=self.verify,
                params=params,
                json=data
            )
            demisto.debug(f'Response status code: {response.status_code}')
            demisto.debug(f'Response body: {response.text}')

            if response.status_code not in {200, 201}:
                raise DemistoException(f'Error in API call [{response.status_code}] - {response.text}')
            return response.json()
        except Exception as e:
            demisto.error(f'Error in API call: {str(e)}')
            raise
        
    def list_domain_information(self, domains: List[str], fetch_risk_score: Optional[bool] = False, fetch_whois_info: Optional[bool] = False) -> Dict:
        """
        Fetches domain information, including WHOIS data, risk scores, and live WHOIS for multiple domains.

        Args:
            domains: List of domain strings.
            fetch_risk_score: Whether to fetch risk scores (default: False).
            fetch_whois_info: Whether to fetch live WHOIS information (default: False).

        Returns:
            Dict: A dictionary containing combined domain information, risk scores, and live WHOIS information.
        """
        if len(domains) > 100:
            raise DemistoException("Maximum of 100 domains can be submitted in a single request.")

        try:
            
            domains_data = {'domains': domains}

            
            bulk_info_response = self._http_request(
                method='POST',
                url_suffix='explore/bulk/domaininfo',
                data=domains_data
            )

           
            domain_info_list = bulk_info_response.get('response', {}).get('domaininfo', [])
            domain_info_dict = {item['domain']: item for item in domain_info_list}
            combined_results = []

            
            risk_score_dict = {}
            if fetch_risk_score:
                bulk_risk_response = self._http_request(
                    method='POST',
                    url_suffix='explore/bulk/domain/riskscore',
                    data=domains_data
                )
                risk_score_list = bulk_risk_response.get('response', [])
                risk_score_dict = {item['domain']: item for item in risk_score_list}

           
            live_whois_info = {}
            if fetch_whois_info:
                for domain in domains:
                    try:
                        live_whois_response = self._http_request(
                            method='GET',
                            url_suffix=f'explore/domain/whoislive/{domain}'
                        )
                        live_whois_info[domain] = live_whois_response.get('response', {})
                    except Exception as e:
                        live_whois_info[domain] = {'error': f"Failed to fetch WHOIS data: {str(e)}"}

          
            for domain in domains:
                combined_results.append({
                    'domain': domain,
                    **domain_info_dict.get(domain, {}),
                    'sp_risk_score': risk_score_dict.get(domain, {}).get('sp_risk_score', 'N/A'),
                    'sp_risk_score_explain': risk_score_dict.get(domain, {}).get('sp_risk_score_explain', 'N/A'),
                    'whois_info': live_whois_info.get(domain, 'N/A')
                })

            return {'domains': combined_results}

        except Exception as e:
            raise DemistoException(f"Failed to fetch bulk domain information: {str(e)}")
            
        
    def get_domain_certificates(self, domain: str, domain_regex: Optional[str] = None, certificate_issuer: Optional[str] = None,
                                date_min: Optional[str] = None, date_max: Optional[str] = None, prefer: Optional[str] = None,
                                max_wait: Optional[int] = None, with_metadata: Optional[bool] = False, skip: Optional[int] = 0,
                                limit: Optional[int] = 100) -> dict:
        """
        Fetches SSL/TLS certificate data for a given domain.
        If the job is not completed, it polls the job status periodically.

        Args:
            domain (str): The domain to fetch certificate information for.
            domain_regex (Optional[str]): Regular expression to match domains.
            certificate_issuer (Optional[str]): The name of the certificate issuer.
            date_min (Optional[str]): Filter certificates issued on or after this date.
            date_max (Optional[str]): Filter certificates issued on or before this date.
            prefer (Optional[str]): Prefer to wait for longer queries.
            max_wait (Optional[int]): Maximum wait time in seconds.
            with_metadata (Optional[bool]): Whether to include metadata.
            skip (Optional[int]): Number of results to skip.
            limit (Optional[int]): Maximum number of results.

        Returns:
            dict: A dictionary containing certificate information fetched from the API.
        """
        demisto.debug(f'Fetching certificate information for domain: {domain}')
        
        url_suffix = f'explore/domain/certificates/{domain}'
        params = {
            'limit': limit,
            'skip': skip,
            'with_metadata': with_metadata,
            'domain_regex': domain_regex,
            'certificate_issuer': certificate_issuer,
            'date_min': date_min,
            'date_max': date_max,
            'prefer': prefer,
            'max_wait': max_wait
        }
        
        # Remove keys with None values
        params = {k: v for k, v in params.items() if v is not None}

        response = self._http_request('GET', url_suffix, params=params)

        job_status_url = response.get('response', {}).get('job_status', {}).get('get')
        if not job_status_url:
            demisto.error('Job status URL not found in the response')
            return response

        job_complete = False
        while not job_complete:
            demisto.debug(f'Checking job status at {job_status_url}')
            
            job_response = self._http_request('GET', job_status_url)
            job_status = job_response.get('response', {}).get('job_status', {}).get('status')

            if job_status == 'COMPLETED':
                job_complete = True
                demisto.debug('Job completed, fetching certificates.')
            
                certificate_data = job_response.get('response', {}).get('domain_certificates', [])
                return certificate_data
            elif job_status == 'FAILED':
                demisto.error('Job failed to complete.')
                return {'error': 'Job failed'}
            else:
                demisto.debug('Job is still in progress. Retrying...')
                time.sleep(5)

        return {}

        

    def search_domains(self, 
                        query: Optional[str] = None, 
                        start_date: Optional[str] = None,
                        end_date: Optional[str] = None,
                        risk_score_min: Optional[int] = None,
                        risk_score_max: Optional[int] = None,
                        limit: int = 100) -> dict:
        """
        Search for domains with optional filters.
        
        Args:
            query (str, optional): Search query string (e.g., domain pattern, keywords)
            start_date (str, optional): Start date for domain registration (ISO8601 format)
            end_date (str, optional): End date for domain registration (ISO8601 format)
            risk_score_min (int, optional): Minimum risk score filter
            risk_score_max (int, optional): Maximum risk score filter
            limit (int, optional): Maximum number of results to return (default: 100)
            
        Returns:
            dict: A dictionary containing the search results
        """
        demisto.debug(f'Searching domains with query: {query}')
        url_suffix = 'explore/domain/search'
        
        params = {k: v for k, v in {
            'domain': query,
            'start_date': start_date,
            'end_date': end_date,
            'risk_score_min': risk_score_min,
            'risk_score_max': risk_score_max,
            'limit': limit
        }.items() if v is not None}
        
        try:
            response = self._http_request('GET', url_suffix, params=params)
            
            # Log job status if available
            job_status = response.get('response', {}).get('job_status', {})
            if job_status:
                demisto.debug(f"Job Status: {job_status.get('status', 'Unknown')}")
            
            return response
        except Exception as e:
            demisto.error(f"Error in search_domains API request: {str(e)}")
            return {'error': str(e)}

                
    def list_domain_infratags(self, domains: list, cluster: bool = False, mode: str = 'live', match: str = 'self', as_of: Optional[str] = None) -> dict:
        """
        Get infratags for multiple domains with optional clustering and additional filtering options.

        Args:
            domains (list): A list of domains to retrieve infratags for.
            cluster (bool, optional): Whether to cluster the results. Defaults to False.
            mode (str, optional): Mode for the lookup, either 'live' (default) or 'padns'.
            match (str, optional): Handling of self-hosted infrastructure, either 'self' (default) or 'full'.
            as_of (str, optional): Date or timestamp for filtering the data.

        Returns:
            dict: A dictionary containing infratags for the provided domains.
        """
        demisto.debug(f'Fetching infratags for domains: {domains} with cluster={cluster}, mode={mode}, match={match}, as_of={as_of}')
        
        url = 'explore/bulk/domain/infratags'  
        
        payload = {
            'domains': domains
        }
        params = {
            'mode': mode,
            'match': match,
            'clusters': cluster  # Use boolean value directly
        }
        
        if as_of:
            params['as_of'] = as_of

        try:
            response = self._http_request(
                method='POST',
                url_suffix=url,
                params=params,
                data=payload  
            )
            return response
        except Exception as e:
            # Log error if the request fails
            demisto.error(f"Error fetching infratags: {str(e)}")
            raise


                
    def get_enrichment_data(self, resource: str, resource_type: str, explain: bool = False, scan_data: bool = False) -> Dict:
        """
        Retrieve comprehensive enrichment information for a given resource (domain, IPv4, or IPv6).
        
        Args:
            resource (str): The resource identifier (domain name, IPv4 address, or IPv6 address)
            resource_type (str): Type of resource ('domain', 'ipv4', 'ipv6')
            explain (bool, optional): Whether to show details of data used to calculate scores (default: False)
            scan_data (bool, optional): Whether to show details of data collected from scanning (default: False)
        
        Returns:
            Dict: The enrichment data response from the API
                
        Raises:
            ValueError: If resource_type is not one of 'domain', 'ipv4', 'ipv6'
            DemistoException: If the API request fails
        """
        if resource_type not in {'domain', 'ipv4', 'ipv6'}:
            raise ValueError("resource_type must be one of: 'domain', 'ipv4', 'ipv6'")
        
        demisto.debug(f'Fetching enrichment data for {resource_type}: {resource}')
        url_suffix = f'explore/enrich/{resource_type}/{resource}'
        
        params = {
            'explain': 1 if explain else 0,
            'scan_data': 1 if scan_data else 0
        }
        
        try:
            response = self._http_request(
                method='GET',
                url_suffix=url_suffix,
                params=params
            )
            demisto.debug(f'Enrichment response: {response}')
            return response
        
        except Exception as e:
            raise DemistoException(f'Failed to fetch enrichment data for {resource_type} {resource}: {str(e)}')


    def list_ip_information(self, resource: str, explain: bool = False, scan_data: bool = False, sparse: Optional[str] = None) -> Dict:
        """
        Fetches information for an IP address or domain.
        
        Args:
            resource: The IP or domain resource to query
            explain: Whether to show details of data used to calculate scores
            scan_data: Whether to include scan data (IPv4 only)
            sparse: Optional specific data to return ('asn', 'asname', or 'sp_risk_score')
            
        Returns:
            Dict: Results for the requested IP or domain
        """
        
        params = {
            'ips': [resource],
            'explain': 1 if explain else 0,
            'scan_data': 1 if scan_data else 0,
            'sparse': sparse if sparse else ''
        }
        
        url_suffix = "explore/bulk/ip2asn"
        
        try:
            response = self._http_request(
                method='POST',
                url_suffix=url_suffix,
                data=params  
            )
            
            return response
        except Exception as e:
            demisto.error(f"Error fetching information for resource {resource}: {str(e)}")
            return {'error': str(e)}

    def get_asn_reputation(self, asn: str) -> Dict:
        """
        Retrieve reputation information for an Autonomous System Number (ASN).
        
        Args:
            asn (str): The ASN to lookup (can be with or without 'AS' prefix)
            
        Returns:
            Dict: The reputation information response from the API
            
        Raises:
            ValueError: If ASN is invalid
            DemistoException: If the API request fails
        """
        if not asn:
            raise ValueError("ASN cannot be empty")
            
        # Strip 'AS' prefix if present and validate ASN format
        asn_number = asn.upper().replace('AS', '')
        if not asn_number.isdigit():
            raise ValueError("Invalid ASN format. Must be a number or start with 'AS' followed by a number")
            
        demisto.debug(f'Fetching reputation for ASN: {asn_number}')
        
        try:
            url_suffix = f'explore/ipreputation/history/asn/{asn_number}'
            response = self._http_request(
                method='GET',
                url_suffix=url_suffix
            )
            
            return response
            
        except Exception as e:
            raise DemistoException(f'Failed to fetch ASN reputation for {asn}: {str(e)}')
        
    def get_asn_takedown_reputation(self, asn: str) -> Dict:
        """
        Retrieve takedown reputation information for an Autonomous System Number (ASN).
        
        Args:
            asn (str): The ASN to lookup (can be with or without 'AS' prefix)
            
        Returns:
            Dict: The takedown reputation information response from the API
            
        Raises:
            ValueError: If ASN is invalid
            DemistoException: If the API request fails
        """
        if not asn:
            raise ValueError("ASN cannot be empty")
            
        # Strip 'AS' prefix if present and validate ASN format
        asn_number = asn.upper().replace('AS', '')
        if not asn_number.isdigit():
            raise ValueError("Invalid ASN format. Must be a number or start with 'AS' followed by a number")
            
        demisto.debug(f'Fetching takedown reputation for ASN: {asn_number}')
        
        try:
            url_suffix = f'explore/ipreputation/takedown/asn/{asn_number}'
            response = self._http_request(
                method='GET',
                url_suffix=url_suffix
            )
            
            return response
            
        except Exception as e:
            raise DemistoException(f'Failed to fetch ASN takedown reputation for {asn}: {str(e)}')




def test_module(client: Client) -> str:
    """
    Tests connectivity to the SilentPush API and checks the authentication status.
    
    This function will validate the API key and ensure that the client can successfully connect 
    to the API. It is called when running the 'Test' button in XSOAR.
    
    Args:
        client (Client): The client instance to use for the connection test.
    
    Returns:
        str: 'ok' if the connection is successful, otherwise returns an error message.
    """
    demisto.debug('Running test module...')
    try:
        client.list_domain_information('silentpush.com')
        demisto.debug('Test module completed successfully')
        return 'ok'
    except DemistoException as e:
        demisto.debug(f'Test module failed: {str(e)}')
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        raise e
    
    
''' COMMAND FUNCTIONS '''


def list_domain_information_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command handler for the 'silentpush-list-domain-information' command.

    Args:
        client (Client): The client instance for API requests.
        args (Dict[str, Any]): Command arguments passed from XSOAR.

    Returns:
        CommandResults: Formatted results for XSOAR.
    """
    # Extract and validate domains
    domains_arg = args.get('domains') or args.get('domain')
    if not domains_arg:
        raise DemistoException('No domains provided. Use the "domain" or "domains" argument.')

    domains = [domain.strip() for domain in domains_arg.split(',') if domain.strip()]
    if len(domains) > 100:
        raise DemistoException("A maximum of 100 domains can be submitted in a single request.")

    # Extract optional parameters
    fetch_risk_score = argToBoolean(args.get('fetch_risk_score', False))
    fetch_whois_info = argToBoolean(args.get('fetch_whois_info', False))

    # Log input for debugging
    demisto.debug(f"Fetching domain information for: {domains} "
                  f"with fetch_risk_score={fetch_risk_score}, fetch_whois_info={fetch_whois_info}")

    # Call the client method to fetch domain information
    raw_response = client.list_domain_information(domains, fetch_risk_score, fetch_whois_info)
    demisto.debug(f"API response: {raw_response}")

    # Prepare readable output
    markdown = ['# Domain Information Results\n']
    for domain_info in raw_response.get('domains', []):
        markdown.append(f"## Domain: {domain_info.get('domain', 'N/A')}")

        # Add basic domain information
        basic_info = {
            'Created Date': domain_info.get('whois_created_date', 'N/A'),
            'Registrar': domain_info.get('registrar', 'N/A'),
            'Age (days)': domain_info.get('age', 'N/A'),
            'Risk Score': domain_info.get('sp_risk_score', 'N/A'),
        }
        markdown.append(tableToMarkdown('Domain Information', [basic_info]))

        # Add risk score explanation if available
        if risk_explain := domain_info.get('sp_risk_score_explain'):
            markdown.append(f'### Risk Score Explanation\n{risk_explain}')

        # Add WHOIS data if available
        whois_info = domain_info.get('whois_info', {})
        if isinstance(whois_info, dict):
            whois_table = [{'Key': k, 'Value': v} for k, v in whois_info.items()]
            markdown.append(tableToMarkdown('WHOIS Information', whois_table))

        markdown.append('\n---\n')

    readable_output = '\n'.join(markdown)

    # Return command results
    return CommandResults(
        outputs_prefix='SilentPush.Domain',
        outputs_key_field='domain',
        outputs=raw_response.get('domains', []),
        readable_output=readable_output,
        raw_response=raw_response
    )


def get_domain_certificates_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command handler for fetching SSL/TLS certificate data for a given domain.

    Args:
        client (Client): The client instance.
        args (Dict[str, Any]): The arguments passed to the command (including the domain).

    Returns:
        CommandResults: The formatted result for XSOAR.
    """
    domain = args.get('domain')
    if not domain:
        raise DemistoException('Domain argument is required.')

    # Call the client function to get the domain certificates.
    demisto.debug(f'Fetching certificates for domain: {domain}')
    certificate_data = client.get_domain_certificates(domain)

    if not certificate_data:
        raise DemistoException(f'No certificate data found for domain: {domain}')

    # Prepare the markdown output
    markdown = [f'# SSL/TLS Certificate Information for Domain: {domain}\n']

    # Add certificate details to markdown
    if isinstance(certificate_data, list) and certificate_data:
        for cert in certificate_data:
            markdown.append(f"## Certificate for {domain}")
            cert_info = {
                'Issuer': cert.get('issuer', 'N/A'),
                'Issued On': str(cert.get('issued_on', 'N/A')),
                'Expires On': str(cert.get('expires_on', 'N/A')),
                'Common Name': cert.get('common_name', 'N/A'),
                'Subject Alternative Names': ', '.join(cert.get('subject_alt_names', [])),
            }
            markdown.append(tableToMarkdown('Certificate Information', [cert_info]))

            # Add metadata if available
            metadata = cert.get('metadata', {})
            if metadata:
                markdown.append(f"### Metadata: {metadata}")
    else:
        markdown.append(f'No certificate data available for domain: {domain}')

    # Add metadata and job status to the response
    metadata = {
        'job_id': certificate_data.get('response', {}).get('metadata', {}).get('job_id'),
        'query_name': certificate_data.get('response', {}).get('metadata', {}).get('query_name'),
        'results_returned': certificate_data.get('response', {}).get('metadata', {}).get('results_returned'),
        'results_total_at_least': certificate_data.get('response', {}).get('metadata', {}).get('results_total_at_least')
    }
    
    job_status = certificate_data.get('response', {}).get('job_status', {})
    job_status_url = job_status.get('get')
    job_status_status = job_status.get('status', 'N/A')

    # Prepare the raw response
    raw_response = {
        'certificate_data': certificate_data,
        'metadata': metadata,
        'job_status': {
            'url': job_status_url,
            'status': job_status_status
        }
    }

    return CommandResults(
        outputs_prefix='SilentPush.Certificate',
        outputs_key_field='domain',
        outputs={'domain': domain, 'certificates': certificate_data, 'metadata': metadata},
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
    
    demisto.debug(f'Searching domains with query: {query}')

    try:
        raw_response = client.search_domains(
            query=query,
            start_date=start_date,
            end_date=end_date,
            risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
            limit=limit
        )
    except Exception as e:
        return CommandResults(
            readable_output=f"Error: {str(e)}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error'
        )
    
    # Check for response errors
    if raw_response.get('error'):
        return CommandResults(
            readable_output=f"Error: {raw_response['error']}",
            raw_response={},
            outputs_prefix='SilentPush.Error',
            outputs_key_field='error'
        )
    
    # Extract records from the response
    records = raw_response.get('response', {}).get('records', [])
    
    if not records:
        return CommandResults(
            readable_output="No domains found.",
            raw_response=raw_response,
            outputs_prefix='SilentPush.SearchResults',
            outputs_key_field='domain',
            outputs=raw_response
        )
    
    # Format records into a readable markdown table
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
    Command handler for fetching infratags for multiple domains.

    Args:
        client (Client): The client instance to fetch the data.
        args (dict): The arguments passed to the command, including domains, clustering option, and optional filters.

    Returns:
        CommandResults: The command results containing readable output and the raw response.
    """
    domains = argToList(args.get('domains', ''))
    cluster = argToBoolean(args.get('cluster', False)) 
    mode = args.get('mode', 'live')
    match = args.get('match', 'self')
    as_of = args.get('as_of', None)
  
    if not domains:
        raise ValueError('"domains" argument is required and cannot be empty.')

    demisto.debug(f'Processing infratags for domains: {domains} with cluster={cluster}, mode={mode}, match={match}, as_of={as_of}')

    try:
        raw_response = client.list_domain_infratags(domains, cluster, mode, match, as_of)
        demisto.debug(f'Response from API: {raw_response}')
    except Exception as e:
        demisto.error(f'Error occurred while fetching infratags: {str(e)}')
        raise

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

    

def get_enrichment_data_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command handler for fetching enrichment data for a specific resource.
    
    Args:
        client (Client): The client instance to fetch the data
        args (dict): Command arguments including:
            - resource (str): The resource (e.g., domain, IP address, etc.)
            - resource_type (str): The type of resource ('domain', 'ip', etc.)
            - explain (bool): Whether to show calculation details
            - scan_data (bool): Whether to include scan data (IPv4 only)
            
    Returns:
        CommandResults: XSOAR command results
    """
    
    resource = args.get('resource')
    resource_type = args.get('resource_type')
    
    if not resource or not resource_type:
        raise DemistoException('Resource and resource_type are required arguments.')
    
    explain = argToBoolean(args.get('explain', False))
    scan_data = argToBoolean(args.get('scan_data', False))
    
    try:
        raw_response = client.get_enrichment_data(resource, resource_type, explain, scan_data)
        enrichment_data = raw_response.get('data', [])
        
        markdown = [f"### Enrichment Data for {resource} ({resource_type})\n"]
        
        for data in enrichment_data:
            markdown.append(f"#### Enrichment Data:\n")
            markdown.append(f"Data: {data}\n")
        
        return CommandResults(
            outputs_prefix='SilentPush.Enrichment',
            outputs_key_field='resource',
            outputs=enrichment_data,
            readable_output='\n'.join(markdown),
            raw_response=raw_response
        )
        
    except Exception as e:
        demisto.error(f"Error in get_enrichment_data_command: {str(e)}")
        raise


def list_ip_information_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command handler for fetching IP information.
    
    Args:
        client (Client): The client instance to fetch the data
        args (dict): Command arguments including:
            - ips (str): Comma-separated list of IP addresses
            - explain (bool): Whether to show calculation details
            - scan_data (bool): Whether to include scan data (IPv4 only)
            - sparse (str): Optional specific data to return
            
    Returns:
        CommandResults: XSOAR command results
    """
    
    ips = args.get('ips')
    if not ips:
        raise DemistoException('No IPs provided. Please provide IPs using the "ips" argument.')
    
    explain = argToBoolean(args.get('explain', False))
    scan_data = argToBoolean(args.get('scan_data', False))
    sparse = args.get('sparse')
    
    if sparse and sparse not in ['asn', 'asname', 'sp_risk_score']:
        raise DemistoException('Invalid sparse value. Must be one of: asn, asname, sp_risk_score')
    
    try:
        ip_list = [ip.strip() for ip in ips.split(',')]
        
        results = []
        markdown = ['### IP Information Results\n']
        
        for ip in ip_list:
            resource = ip 
            raw_response = client.list_ip_information(resource, explain, scan_data, sparse)
            ip_data = raw_response.get('ips', [])
            
            for ip_info in ip_data:
                if 'error' in ip_info:
                    markdown.append(f"#### IP: {ip_info.get('ip', 'N/A')} (Error)\n")
                    markdown.append(f"Error: {ip_info['error']}\n")
                    continue
                
                markdown.append(f"#### IP: {ip_info.get('ip', 'N/A')} ({ip_info.get('ip_type', 'unknown').upper()})")
                
                basic_info = {
                    'ASN': ip_info.get('asn', 'N/A'),
                    'AS Name': ip_info.get('asname', 'N/A'),
                    'Risk Score': ip_info.get('sp_risk_score', 'N/A'),
                    'Subnet': ip_info.get('subnet', 'N/A')
                }
                markdown.append(tableToMarkdown('Basic Information', [basic_info], headers=basic_info.keys()))
                
                if location_info := ip_info.get('ip_location', {}):
                    location_data = {
                        'Country': location_info.get('country_name', 'N/A'),
                        'Continent': location_info.get('continent_name', 'N/A'),
                        'EU Member': 'Yes' if location_info.get('country_is_in_european_union') else 'No'
                    }
                    markdown.append(tableToMarkdown('Location Information', [location_data], headers=location_data.keys()))
                
                if ip_info.get('ip_type') == 'ipv4':
                    additional_info = {
                        'PTR Record': ip_info.get('ip_ptr', 'N/A'),
                        'Is TOR Exit Node': 'Yes' if ip_info.get('ip_is_tor_exit_node') else 'No',
                        'Is DSL/Dynamic': 'Yes' if ip_info.get('ip_is_dsl_dynamic') else 'No'
                    }
                    markdown.append(tableToMarkdown('Additional Information', [additional_info], headers=additional_info.keys()))
                
                markdown.append('\n')
        
        return CommandResults(
            outputs_prefix='SilentPush.IP',
            outputs_key_field='ip',
            outputs=ip_data,
            readable_output='\n'.join(markdown),
            raw_response=raw_response
        )
        
    except Exception as e:
        demisto.error(f"Error in list_ip_information_command: {str(e)}")
        raise
    
def get_asn_reputation_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command handler for fetching ASN reputation information.
    
    Args:
        client (Client): The client instance to fetch the data
        args (dict): Command arguments including:
            - asn (str): The ASN to lookup
            
    Returns:
        CommandResults: XSOAR command results
    """
    asn = args.get('asn')
    if not asn:
        raise DemistoException('ASN is a required argument')
    
    try:
        raw_response = client.get_asn_reputation(asn)
        reputation_data = raw_response.get('response', {})
        
        # Create a readable output
        markdown = [f"### ASN Reputation Information for {asn}\n"]
        
        # Basic reputation information
        if basic_info := reputation_data.get('reputation', {}):
            reputation_table = {
                'Risk Score': basic_info.get('risk_score', 'N/A'),
                'First Seen': basic_info.get('first_seen', 'N/A'),
                'Last Seen': basic_info.get('last_seen', 'N/A'),
                'Total Reports': basic_info.get('total_reports', 'N/A')
            }
            markdown.append(tableToMarkdown('Reputation Overview', [reputation_table]))
            
        # Historical data if available
        if history := reputation_data.get('history', []):
            history_table = []
            for entry in history:
                history_table.append({
                    'Date': entry.get('date', 'N/A'),
                    'Risk Score': entry.get('risk_score', 'N/A'),
                    'Reports': entry.get('reports', 'N/A')
                })
            if history_table:
                markdown.append('\n### Historical Reputation Data')
                markdown.append(tableToMarkdown('', history_table))
                
        # Additional metadata if available
        if metadata := reputation_data.get('metadata', {}):
            metadata_table = {k: str(v) for k, v in metadata.items()}
            if metadata_table:
                markdown.append('\n### Additional Information')
                markdown.append(tableToMarkdown('', [metadata_table]))
        
        return CommandResults(
            outputs_prefix='SilentPush.ASNReputation',
            outputs_key_field='asn',
            outputs={
                'asn': asn,
                'reputation': reputation_data
            },
            readable_output='\n'.join(markdown),
            raw_response=raw_response
        )
        
    except Exception as e:
        demisto.error(f"Error in get_asn_reputation_command: {str(e)}")
        raise
    
def get_asn_takedown_reputation_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command handler for fetching ASN takedown reputation information.
    
    Args:
        client (Client): The client instance to fetch the data
        args (dict): Command arguments including:
            - asn (str): The ASN to lookup
            
    Returns:
        CommandResults: XSOAR command results
    """
    asn = args.get('asn')
    if not asn:
        raise DemistoException('ASN is a required argument')
    
    try:
        raw_response = client.get_asn_takedown_reputation(asn)
        takedown_data = raw_response.get('response', {})
        
      
        markdown = [f"### ASN Takedown Reputation Information for {asn}\n"]
        
        
        if basic_info := takedown_data.get('takedown', {}):
            takedown_table = {
                'Risk Score': basic_info.get('risk_score', 'N/A'),
                'First Seen': basic_info.get('first_seen', 'N/A'),
                'Last Seen': basic_info.get('last_seen', 'N/A'),
                'Total Reports': basic_info.get('total_reports', 'N/A')
            }
            markdown.append(tableToMarkdown('Takedown Reputation Overview', [takedown_table]))
            
        
        if history := takedown_data.get('history', []):
            history_table = []
            for entry in history:
                history_table.append({
                    'Date': entry.get('date', 'N/A'),
                    'Risk Score': entry.get('risk_score', 'N/A'),
                    'Reports': entry.get('reports', 'N/A')
                })
            if history_table:
                markdown.append('\n### Historical Takedown Reputation Data')
                markdown.append(tableToMarkdown('', history_table))
                
       
        if metadata := takedown_data.get('metadata', {}):
            metadata_table = {k: str(v) for k, v in metadata.items()}
            if metadata_table:
                markdown.append('\n### Additional Information')
                markdown.append(tableToMarkdown('', [metadata_table]))
        
        return CommandResults(
            outputs_prefix='SilentPush.ASNTakedownReputation',
            outputs_key_field='asn',
            outputs={
                'asn': asn,
                'takedown_reputation': takedown_data
            },
            readable_output='\n'.join(markdown),
            raw_response=raw_response
        )
        
    except Exception as e:
        demisto.error(f"Error in get_asn_takedown_reputation_command: {str(e)}")
        raise



''' MAIN FUNCTION '''


def main():
    """
    Main function to initialize the client and process the commands.
    
    This function parses the parameters, sets up the client, and routes the command to 
    the appropriate function.
    
    It handles the setup of authentication, base URL, SSL verification, and proxy configuration.
    Also, it routes the `test-module` and `silentpush-list-domain-information` commands to the
    corresponding functions.
    """
    try:
        params = demisto.params()
        api_key = params.get('credentials', {}).get('password')
        base_url = params.get('url', 'https://api.silentpush.com')
        verify_ssl = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        demisto.debug(f'Base URL: {base_url}')
        demisto.debug('Initializing client...')

        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_ssl,
            proxy=proxy
        )

        command = demisto.command()
        demisto.debug(f'Command being called is {command}')

        command_handlers = {
                        
            'test-module': test_module,
            'silentpush-list-domain-information': list_domain_information_command,
            'silentpush-get-domain-certificates': get_domain_certificates_command,
            'silentpush-search-domains': search_domains_command,
            'silentpush-list-domain-infratags': list_domain_infratags_command,
            'silentpush-get-enrichment-data' : get_enrichment_data_command,
            'silentpush-list-ip-information' : list_ip_information_command,
            'silentpush-get-asn-reputation' : get_asn_reputation_command,
            'silentpush-get-asn-takedown-reputation' : get_asn_takedown_reputation_command
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