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
        
    def list_domain_information(self, domains: Union[str, List[str]]) -> Dict:
        """
        Fetches domain information including WHOIS data and risk scores for multiple domains.
        
        Args:
            domains: Either a single domain string or a list of domain strings
            
        Returns:
            Dict: A dictionary containing combined domain information and risk scores
        """
        demisto.debug(f'Fetching domain information for: {domains}')
        domain_list = [domains] if isinstance(domains, str) else domains
        
        if len(domain_list) > 100:
            raise DemistoException("Maximum of 100 domains can be submitted in a single request")
        
        if len(domain_list) == 1:

            domain = domain_list[0]
            try:

                domain_info_response = self._http_request(
                    method='GET',
                    url_suffix=f'explore/domain/domaininfo/{domain}'
                )
                domain_info = domain_info_response.get('response', {}).get('domaininfo', {})
                
                risk_score_response = self._http_request(
                    method='GET',
                    url_suffix=f'explore/domain/riskscore/{domain}'
                )
                risk_info = risk_score_response.get('response', {})
                
                combined_info = {
                    'domain': domain,
                    **domain_info,
                    'sp_risk_score': risk_info.get('sp_risk_score'),
                    'sp_risk_score_explain': risk_info.get('sp_risk_score_explain')
                }
                
                return {'domains': [combined_info]}
                
            except Exception as e:
                raise DemistoException(f'Failed to fetch information for domain {domain}: {str(e)}')
        
        else:
            
            try:
              
                domains_data = {'domains': domain_list}
                bulk_info_response = self._http_request(
                    method='POST',
                    url_suffix='explore/bulk/domaininfo',
                    data=domains_data 
                )
                
                bulk_risk_response = self._http_request(
                    method='POST',
                    url_suffix='explore/bulk/domain/riskscore',
                    data=domains_data  
                )
                
                domain_info_list = bulk_info_response.get('response', {}).get('domaininfo', [])
                risk_score_list = bulk_risk_response.get('response', [])
                domain_info_dict = {item['domain']: item for item in domain_info_list}
                risk_score_dict = {item['domain']: item for item in risk_score_list}
                
                combined_results = []
                for domain in domain_list:
                    domain_data = domain_info_dict.get(domain, {})
                    risk_data = risk_score_dict.get(domain, {})
                    
                    combined_results.append({
                        'domain': domain,
                        **domain_data,
                        'sp_risk_score': risk_data.get('sp_risk_score'),
                        'sp_risk_score_explain': risk_data.get('sp_risk_score_explain')
                    })
                
                return {'domains': combined_results}
                
            except Exception as e:
                raise DemistoException(f'Failed to fetch bulk domain information: {str(e)}')
        
    
    def get_domain_certificates(self, domain: str) -> dict:
        """
        Fetches SSL/TLS certificate data for a given domain.
        If the job is not completed, it polls the job status periodically.

        Args:
            domain (str): The domain to fetch certificate information for.

        Returns:
            dict: A dictionary containing certificate information fetched from the API.
        """
        demisto.debug(f'Fetching certificate information for domain: {domain}')
        
      
        url_suffix = f'explore/domain/certificates/{domain}'
        response = self._http_request('GET', url_suffix, params={
            'limit': 100,
            'skip': 0,
            'with_metadata': 0
        })

       
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
            return self._http_request('GET', url_suffix, params=params)
        except Exception as e:
                demisto.error(f"Error in search_domains API request: {str(e)}")

    def list_domain_infratags(self, domains: list, cluster: Optional[bool] = False, mode: Optional[str] = 'live', match: Optional[str] = 'self', as_of: Optional[str] = None) -> dict:
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
        
       
        results = {}
        for domain in domains:
            url = f'https://api.silentpush.com/api/v1/merge-api/explore/domain/infratag/{domain}'
            data = {
                'cluster': cluster,
                'mode': mode,
                'match': match,
                'as_of': as_of
            }
            try:
             
                response = self._http_request('GET', url, params=data) 
                results[domain] = response
            except Exception as e:
                demisto.error(f"Error fetching infratags for domain {domain}: {str(e)}")
                
                
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
    Command handler for fetching domain information.
    
    Args:
        client (Client): The client instance to fetch the data
        args (dict): Command arguments
        
    Returns:
        CommandResults: XSOAR command results
    """
 
    domains_arg = args.get('domains', args.get('domain'))
    
    if not domains_arg:
        raise DemistoException('No domains provided. Please provide domains using either the "domain" or "domains" argument.')
    
   
    if isinstance(domains_arg, str):
        domains = [d.strip() for d in domains_arg.split(',')]
    else:
        domains = domains_arg
    
    demisto.debug(f'Processing domain(s): {domains}')
    
   
    raw_response = client.list_domain_information(domains)
    demisto.debug(f'Response from API: {raw_response}')
    
 
    markdown = []
    for domain_info in raw_response.get('domains', []):
        markdown.append(f"### Domain: {domain_info.get('domain')}")
        markdown.append("#### Domain Information:")
        markdown.append(f"- Age: {domain_info.get('age', 'N/A')} days")
        markdown.append(f"- Registrar: {domain_info.get('registrar', 'N/A')}")
        markdown.append(f"- Created Date: {domain_info.get('whois_created_date', 'N/A')}")
        markdown.append(f"- Risk Score: {domain_info.get('sp_risk_score', 'N/A')}")
        markdown.append("\n")
    
    readable_output = '\n'.join(markdown)
    
    return CommandResults(
        outputs_prefix='SilentPush.Domain',
        outputs_key_field='domain',
        outputs=raw_response.get('domains', []),
        readable_output=readable_output,
        raw_response=raw_response
    )

def get_domain_certificates_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for fetching domain certificate information.
    """
    domain = args.get('domain', 'silentpush.com')
    demisto.debug(f'Processing certificates for domain: {domain}')

    raw_response = client.get_domain_certificates(domain)
    demisto.debug(f'Response from API: {raw_response}')

    if 'error' in raw_response:
        return CommandResults(
            outputs_prefix='SilentPush.Certificates',
            outputs_key_field='domain',
            outputs=raw_response,
            readable_output=f"Error: {raw_response['error']}",
            raw_response=raw_response
        )

    readable_output = tableToMarkdown('Domain Certificates', raw_response)

    return CommandResults(
        outputs_prefix='SilentPush.Certificates',
        outputs_key_field='domain',
        outputs=raw_response,
        readable_output=readable_output,
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
    
   
    if raw_response.get('response') and 'records' in raw_response['response']:
        records = raw_response['response']['records']
    else:
        records = []

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

    readable_output = tableToMarkdown('Domain Infratags', raw_response.get('results', []))

    return CommandResults(
        outputs_prefix='SilentPush.InfraTags',
        outputs_key_field='domain',
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response
    )


def get_enrichment_data_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command handler for fetching enrichment data for a resource (domain, IPv4, or IPv6).
    
    Args:
        client (Client): The client instance to use for API calls
        args (Dict[str, Any]): Command arguments
            - resource (str): The resource to get enrichment data for (domain name, IPv4, or IPv6)
            - resource_type (str): Type of resource ('domain', 'ipv4', 'ipv6') 
            - explain (bool, optional): Whether to show calculation details
            - scan_data (bool, optional): Whether to include scan data
    
    Returns:
        CommandResults: The formatted results for XSOAR
    """
    resource = args.get('resource')
    resource_type = args.get('resource_type')  
    
    if not resource or not resource_type:
        raise ValueError('"resource" and "resource_type" arguments are required')
        
   
    if resource_type not in {'domain', 'ipv4', 'ipv6'}:
        raise ValueError("'resource_type' must be one of: 'domain', 'ipv4', 'ipv6'")
        
    explain = argToBoolean(args.get('explain', False))
    scan_data = argToBoolean(args.get('scan_data', False))
    
    demisto.debug(f'Processing enrichment data for {resource_type}: {resource}')
    
    try:
        raw_response = client.get_enrichment_data(
            resource=resource,
            resource_type=resource_type,
            explain=explain,
            scan_data=scan_data
        )
        
        if not raw_response:
            return CommandResults(
                readable_output=f'No enrichment data found for {resource_type}: {resource}',
                outputs_prefix='SilentPush.Enrichment',
                outputs_key_field='resource',
                outputs={
                    'resource': resource,
                    'type': resource_type,
                    'found': False
                }
            )
        
        markdown = []
        markdown.append(f'## Enrichment Data for {resource_type}: {resource}\n')
        
        enrichment_data = raw_response.get('response', {})
        
       
        overview = {
            'Resource': resource,
            'Type': resource_type
        }
       
        if 'risk_score' in enrichment_data:
            overview['Risk Score'] = enrichment_data['risk_score']   
        if 'first_seen' in enrichment_data:
            overview['First Seen'] = enrichment_data['first_seen']
        if 'last_seen' in enrichment_data:
            overview['Last Seen'] = enrichment_data['last_seen']
            
        markdown.append(tableToMarkdown('Overview', [overview]))
        
        if scan_data and enrichment_data.get('scan_data'):
            scan_info = enrichment_data['scan_data']
            markdown.append('\n### Scan Data')
            markdown.append(tableToMarkdown('', [scan_info]))
               
        if explain and enrichment_data.get('explanation'):
            explain_info = enrichment_data['explanation']
            markdown.append('\n### Score Explanation')
            markdown.append(tableToMarkdown('', [explain_info]))
            
        readable_output = '\n'.join(markdown)
        
        outputs = {
            'resource': resource,
            'type': resource_type,
            'found': True,
            'data': enrichment_data
        }
        
        return CommandResults(
            outputs_prefix='SilentPush.Enrichment',
            outputs_key_field='resource',
            outputs=outputs,
            readable_output=readable_output,
            raw_response=raw_response
        )
        
    except Exception as e:
        demisto.error(f'Failed to get enrichment data: {str(e)}')
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
            'silentpush-get-enrichment-data' : get_enrichment_data_command
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