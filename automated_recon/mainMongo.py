import os
import json
import logging
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from dotenv import load_dotenv
from collections import defaultdict
from pymongo import MongoClient
from bson import ObjectId

# Import MongoDB handler
from automated_recon.mongodb_handler import MongoDBHandler

# Import all tool modules
from automated_recon.shodan.script_shodan import ShodanScanner
from automated_recon.nmap.script_nmap import NmapScanner
from automated_recon.dnsrecon.dnsrecon import DNSReconWrapper
from automated_recon.virustotal.virustotal import Virustotal
from automated_recon.nuclei.nuclei import Nuclei
from automated_recon.nikto.nikto import NiktoScanner
from automated_recon.wappalyzer.script_wappalyzer import WappalyzerScanner
from automated_recon.whois.whois import WhoisTool
from automated_recon.crt_sh.crt_sh import Crtsh
from automated_recon.subfinder.subfinder import Subfinder
from automated_recon.cloudenum.cloudenum import CloudEnumScanner
from automated_recon.gobuster.gobuster import Gobuster
from automated_recon.google_dorks.google_dorks import GoogleDorker
from automated_recon.intelx.intelx import IntelXScanner

# Configure logging
def setup_logging():
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Generate log filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = f'logs/recon_{timestamp}.log'
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()  # This will also print to console
        ]
    )
    
    logging.info(f"Logging initialized. Log file: {log_file}")
    return log_file

class AutomatedRecon:
    def __init__(self, target: str, target_type: str, scan_type: str = "passive", tools: List[str] = None):
        """
        Initialize the automated reconnaissance system.
        
        Args:
            target (str): The target to scan (IP, domain, or organization name)
            target_type (str): Type of target ('ip', 'domain', 'organization')
            scan_type (str): Type of scan ('passive' or 'active')
            tools (List[str]): List of tools to use. If None, uses all available tools
        """
        # Setup logging
        self.log_file = setup_logging()
        logging.info(f"Initializing AutomatedRecon for target: {target} ({target_type})")
        
        # Load environment variables from project root
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
        load_dotenv(env_path)
        logging.debug(f"Loading environment variables from: {env_path}")
        
        # Initialize MongoDB handler
        self.mongo = MongoDBHandler()
        
        # Load API keys
        self.shodan_api_key = os.getenv('SHODAN_API_KEY')
        self.vt_api_key = os.getenv('VT_API_KEY')
        self.intelx_api_key = os.getenv('INTELX_API_KEY')
        self.google_api_key = os.getenv('GOOGLE_API_KEY')
        self.google_cx_id = os.getenv('GOOGLE_CX_ID')
        self.whois_api_key = os.getenv('WHOIS_API_KEY')
        
        # Debug print for API keys
        logging.debug(f"Shodan API Key loaded: {'Yes' if self.shodan_api_key else 'No'}")
        logging.debug(f"VirusTotal API Key loaded: {'Yes' if self.vt_api_key else 'No'}")
        logging.debug(f"IntelX API Key loaded: {'Yes' if self.intelx_api_key else 'No'}")
        logging.debug(f"Google API Key loaded: {'Yes' if self.google_api_key else 'No'}")
        logging.debug(f"WHOIS API Key loaded: {'Yes' if self.whois_api_key else 'No'}")
        
        # Validate required API keys
        if 'shodan' in tools and not self.shodan_api_key:
            logging.error("SHODAN_API_KEY is required for Shodan scans")
            raise ValueError("SHODAN_API_KEY is required for Shodan scans")
        if 'virustotal' in tools and not self.vt_api_key:
            logging.error("VT_API_KEY is required for VirusTotal scans")
            raise ValueError("VT_API_KEY is required for VirusTotal scans")
        if 'intelx' in tools and not self.intelx_api_key:
            logging.error("INTELX_API_KEY is required for IntelX scans")
            raise ValueError("INTELX_API_KEY is required for IntelX scans")
        if 'google_dorks' in tools and not (self.google_api_key and self.google_cx_id):
            logging.error("GOOGLE_API_KEY and GOOGLE_CX_ID are required for Google Dorks")
            raise ValueError("GOOGLE_API_KEY and GOOGLE_CX_ID are required for Google Dorks")
        if 'whois' in tools and not self.whois_api_key:
            logging.error("WHOIS_API_KEY is required for WHOIS lookups")
            raise ValueError("WHOIS_API_KEY is required for WHOIS lookups")
        
        self.target = target
        self.target_type = target_type
        self.scan_type = scan_type
        self.tools = tools or self._get_all_tools()
        logging.info(f"Selected tools: {', '.join(self.tools)}")
        
        # Initialize results structure with asset-centric design
        self.results = {
            'scan_info': {
                'target': target,
                'target_type': target_type,
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'status': 'running',
                'tools_used': self.tools
            },
            'assets': {},  # Will store all discovered assets
            'relationships': [],  # Will store relationships between assets
            'raw_results': {}  # Will store raw tool outputs
        }
        
        # Initialize tracking sets
        self.discovered_assets = set()  # Track all discovered assets
        self.processed_assets = set()  # Track processed assets
        
        # Initialize tools with API keys
        if 'shodan' in self.tools:
            self.shodan = ShodanScanner(self.shodan_api_key)
        if 'nmap' in self.tools:
            self.nmap = NmapScanner(target)
        if 'dnsrecon' in self.tools:
            self.dnsrecon = DNSReconWrapper()
        if 'virustotal' in self.tools:
            self.virustotal = Virustotal(self.vt_api_key)
        if 'nuclei' in self.tools:
            self.nuclei = Nuclei(target)
        if 'nikto' in self.tools:
            self.nikto = NiktoScanner({'target': target})
        if 'wappalyzer' in self.tools:
            self.wappalyzer = WappalyzerScanner()
        if 'whois' in self.tools:
            self.whois = WhoisTool(target, self.whois_api_key)
        if 'crt_sh' in self.tools:
            self.crt_sh = Crtsh(target)
        if 'subfinder' in self.tools:
            self.subfinder = Subfinder(target)
        if 'cloudenum' in self.tools:
            self.cloudenum = CloudEnumScanner()
        if 'gobuster' in self.tools:
            self.gobuster = Gobuster(target)
        if 'google_dorks' in self.tools:
            self.google_dorks = GoogleDorker(target, self.google_api_key, self.google_cx_id)
        if 'intelx' in self.tools:
            self.intelx = IntelXScanner(target, self.intelx_api_key)

    def _get_all_tools(self) -> List[str]:
        """Get list of all available tools."""
        return [
            'shodan', 'nmap', 'cloudenum', 'crt_sh', 'dnsrecon',
            'gobuster', 'google_dorks', 'intelx', 'nikto', 'nuclei',
            'subfinder', 'virustotal', 'wappalyzer', 'whois'
        ]

    def _create_asset(self, identifier: str, asset_type: str, source: str, parent_asset: str = None) -> Dict[str, Any]:
        """Create a new asset entry in the results structure."""
        asset = {
            'identifier': identifier,
            'ip_addresses': [],  # Will be populated for domains
            'status': 'unknown',  # Will be set to 'up' or 'down' based on IP resolution
            'type': asset_type,
            'discovery_context': {
                'source': source,
                'parent_asset': parent_asset,
                'discovery_timestamp': datetime.now().isoformat()
            },
            'osint_data': {
                'dns': {},
                'certificates': {},
                'web_technologies': {},
                'shodan': {},
                'virustotal': {},
                'whois': {}
            },
            'relationships': [],
            'metadata': {
                'last_scan': datetime.now().isoformat()
            }
        }
        
        # Add to results
        self.results['assets'][identifier] = asset
        
        # Add relationship if parent asset exists
        if parent_asset:
            self._add_relationship(identifier, parent_asset, 'discovered_from')
        
        return asset

    def _add_relationship(self, source_asset: str, target_asset: str, relationship_type: str, evidence: str = None) -> None:
        """Add a relationship between two assets."""
        relationship = {
            'source': source_asset,
            'target': target_asset,
            'type': relationship_type,
            'evidence': evidence,
            'timestamp': datetime.now().isoformat()
        }
        
        # Add to relationships list
        self.results['relationships'].append(relationship)
        
        # Add to both assets' relationship lists
        if source_asset in self.results['assets']:
            self.results['assets'][source_asset]['relationships'].append(relationship)
        if target_asset in self.results['assets']:
            self.results['assets'][target_asset]['relationships'].append(relationship)

    def _check_domain_status(self, domain: str) -> tuple[List[str], str]:
        """Check domain status by testing DNS resolution and HTTP/HTTPS connectivity.
        Returns tuple of (ip_addresses, status)"""
        try:
            import socket
            import requests
            from urllib.parse import urlparse
            
            ips = []
            status = 'down'
            
            # First check DNS resolution
            try:
                logging.debug(f"Resolving IPs for {domain}")
                info = socket.getaddrinfo(domain, None)
                for item in info:
                    ip = item[4][0]
                    # Only keep IPv4 addresses
                    if ':' not in ip and ip not in ips:
                        ips.append(ip)
                logging.debug(f"Found IPs for {domain}: {ips}")
            except socket.gaierror as e:
                logging.debug(f"DNS resolution failed for {domain}: {str(e)}")
                return [], 'down'
            
            if not ips:
                logging.debug(f"No IPs found for {domain}")
                return [], 'down'
            
            # If we have IPs, check HTTP/HTTPS connectivity
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{domain}"
                    logging.debug(f"Testing {url}")
                    response = requests.get(url, timeout=5, allow_redirects=True)
                    if response.status_code < 400:  # Any status code less than 400 means the server responded
                        status = 'up'
                        logging.debug(f"{url} is up (status code: {response.status_code})")
                        break
                except requests.exceptions.RequestException as e:
                    logging.debug(f"{url} failed: {str(e)}")
                    continue
            
            return ips, status
            
        except Exception as e:
            logging.error(f"Error checking status for {domain}: {str(e)}")
            return [], 'down'

    def _process_shodan_data(self, ip: str, asset: Dict[str, Any]) -> None:
        """Process Shodan data for an IP address and store it in the asset."""
        if 'shodan' in self.tools:
            shodan_results = self.shodan.scan_host(ip)
            if shodan_results and 'hosts' in shodan_results:
                # Get the first host result since we're scanning a single IP
                host_data = shodan_results['hosts'][0]
                
                # Store services data in the asset's osint_data
                asset['osint_data']['shodan'] = {
                    'services': [],
                    'banners': [],
                    'timestamp': datetime.now().isoformat()
                }
                
                # Process each service
                for service in host_data.get('services', []):
                    service_info = {
                        'port': service.get('port'),
                        'transport': service.get('transport'),
                        'module': service.get('module'),
                        'data': service.get('data'),
                        'timestamp': service.get('timestamp'),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'cpe': service.get('cpe', []),
                        'vulns': {}
                    }
                    
                    # Process vulnerabilities if they exist
                    if 'vulns' in service:
                        for cve_id in service['vulns']:
                            vuln_info = self.shodan.get_vuln_info(cve_id)
                            if vuln_info:
                                summary, cvss_score = vuln_info
                                service_info['vulns'][cve_id] = {
                                    'summary': summary,
                                    'cvss_v3': cvss_score
                                }
                            else:
                                service_info['vulns'][cve_id] = {
                                    'summary': 'Failed to fetch vulnerability information',
                                    'cvss_v3': None
                                }
                    
                    asset['osint_data']['shodan']['services'].append(service_info)
                    
                    # Add banner if available
                    if 'data' in service:
                        asset['osint_data']['shodan']['banners'].append(service['data'])
                
                # Add relationships for domains
                for domain in host_data.get('domains', []):
                    self._add_relationship(ip, domain, 'hosts', 'Shodan data')

    def _process_domain_asset(self, asset: Dict[str, Any], is_initial_target: bool = False) -> None:
        """Process a domain asset with all applicable tools."""
        domain = asset['identifier']
        logging.info(f"Processing domain asset: {domain}")
        
        # Get IP addresses and check domain status
        domain_ips, status = self._check_domain_status(domain)
        if domain_ips:
            asset['ip_addresses'] = domain_ips
            asset['status'] = status
            logging.info(f"Domain {domain} resolved to IPs: {domain_ips}")
            # Add relationships for IPs
            for ip in domain_ips:
                self._add_relationship(domain, ip, 'resolves_to', 'DNS resolution')
                # Run Shodan on each IP
                self._process_shodan_data(ip, asset)
        else:
            logging.warning(f"No IPs found for {domain}")
            asset['status'] = 'down'
        
        # WHOIS information
        if 'whois' in self.tools:
            logging.info(f"Running WHOIS lookup for {domain}")
            whois_results = self.whois.process_domain(domain)
            if whois_results:
                logging.info(f"WHOIS lookup successful for {domain}")
                asset['osint_data']['whois'] = whois_results
                
                # Add relationships for nameservers
                for ns in whois_results.get('name_servers', []):
                    ns_asset_id = f"nameserver:{ns}"
                    if ns_asset_id not in self.results['assets']:
                        logging.debug(f"Creating new asset for nameserver: {ns}")
                        self._create_asset(ns_asset_id, 'nameserver', 'whois', domain)
                    self._add_relationship(domain, ns_asset_id, 'nameserver', 'WHOIS data')
            else:
                logging.warning(f"WHOIS lookup failed for {domain}")
        
        # DNS records (only run on initial target or new domains)
        if 'dnsrecon' in self.tools:
            output_file = self.dnsrecon.run_dnsrecon(domain)
            dns_results = self.dnsrecon.parse_findings(output_file)
            if dns_results:
                asset['osint_data']['dns'] = dns_results
                
                # Process and add relationships for DNS records
                for record_type, records in dns_results.get('records', {}).items():
                    for record in records:
                        if record_type == 'a':
                            ip_asset_id = record['address']
                            # Only add relationship, don't create new asset for IP
                            self._add_relationship(domain, ip_asset_id, 'resolves_to', 'DNS A record')
                        elif record_type == 'cname':
                            cname_domain = record['target']
                            if cname_domain not in self.results['assets']:
                                self._create_asset(cname_domain, 'domain', 'dnsrecon', domain)
                            self._add_relationship(domain, cname_domain, 'aliases_to', 'DNS CNAME record')

        # Subdomain discovery - only run on initial target domain
        if is_initial_target:
            # Use VirusTotal for subdomain discovery
            if 'virustotal' in self.tools:
                logging.info(f"Getting subdomains for {domain} from VirusTotal")
                subdomains_data = self.virustotal.get_subdomains(domain)
                
                if subdomains_data and 'data' in subdomains_data:
                    logging.info(f"Found {len(subdomains_data['data'])} subdomains")
                    for sub_data in subdomains_data['data']:
                        if 'id' in sub_data:
                            subdomain = sub_data['id']
                            logging.debug(f"Found subdomain: {subdomain}")
                            if subdomain and subdomain not in self.results['assets']:
                                logging.debug(f"Creating new asset for subdomain: {subdomain}")
                                sub_asset = self._create_asset(subdomain, 'domain', 'virustotal', domain)
                                self._add_relationship(domain, subdomain, 'has_subdomain', 'VirusTotal discovery')
                                
                                # Process subdomain with all tools EXCEPT subdomain discovery tools
                                logging.debug(f"Processing subdomain with tools: {subdomain}")
                                self._process_domain_asset(sub_asset, is_initial_target=False)
                        else:
                            logging.debug(f"No 'id' found in subdomain data: {sub_data}")
                else:
                    logging.debug(f"No subdomains found in VirusTotal response")

        # Web technologies (run on all domains)
        if 'wappalyzer' in self.tools:
            wapp_results = self.wappalyzer.process_domain(domain)
            if wapp_results and 'results' in wapp_results:
                # Handle empty version lists safely
                technologies = {}
                for tech_name, tech_data in wapp_results['results'].get('technologies', {}).items():
                    # Get versions list or empty list if none exists
                    versions = tech_data.get('versions', [])
                    
                    # Use first version if available, otherwise 'unknown'
                    version = versions[0] if versions else 'unknown'
                    
                    technologies[tech_name] = version
                
                asset['osint_data']['web_technologies'] = technologies

        # Certificate transparency (only initial target and new subdomains)
        if 'crt_sh' in self.tools and (is_initial_target or asset['discovery_context']['source'] == 'subfinder'):
            crt_results_file = self.crt_sh.download_certificates()
            if crt_results_file:
                with open(crt_results_file, 'r') as f:
                    crt_results = json.load(f)
                    asset['osint_data']['certificates'] = crt_results
                
                for cert in crt_results:
                    if 'name_value' in cert:
                        cert_domain = cert['name_value']
                        if cert_domain not in self.results['assets'] and cert_domain != domain:
                            cert_asset = self._create_asset(cert_domain, 'domain', 'cert_sh', domain)
                            self._add_relationship(domain, cert_domain, 'certificate_relationship', 'Certificate transparency')
                            self._process_domain_asset(cert_asset)

        # Mark initial target as processed
        if is_initial_target:
            self.processed_assets.add(domain)

    def _process_ip_asset(self, asset: Dict[str, Any]) -> None:
        """Process an IP asset with all applicable tools."""
        ip = asset['identifier']
        
        # Shodan data
        self._process_shodan_data(ip, asset)
        
        # Active scanning if enabled
        if self.scan_type == 'active':
            if 'nmap' in self.tools:
                nmap_results = self.nmap.scan_host(ip)
                if nmap_results:
                    asset['osint_data']['nmap'] = nmap_results

    def _process_cloud_asset(self, asset: Dict[str, Any]) -> None:
        """Process a cloud asset with all applicable tools."""
        cloud_id = asset['identifier']
        
        # Cloud-specific enumeration
        if 'cloudenum' in self.tools:
            cloud_results = self.cloudenum.scan_domain(cloud_id)
            if cloud_results:
                asset['osint_data']['cloud'] = cloud_results
                
                # Add relationships for discovered resources
                for resource_type, resources in cloud_results.items():
                    for resource in resources:
                        self._add_relationship(cloud_id, resource, f'has_{resource_type}', 'Cloud enumeration')

    def run_scan(self) -> Dict[str, Any]:
        """
        Run the appropriate scan based on target type and scan type.
        """
        try:
            # Create initial asset
            initial_asset = self._create_asset(
                identifier=self.target,
                asset_type=self.target_type,
                source='initial_scan',
                parent_asset=None
            )
            
            # Process initial asset based on type
            if self.target_type == 'domain':
                self._process_domain_asset(initial_asset, is_initial_target=True)
            elif self.target_type == 'ip':
                self._process_ip_asset(initial_asset)
            elif self.target_type == 'organization':
                self._process_organization_asset(initial_asset)
            
            # Process discovered assets recursively
            while True:
                # Find newly discovered assets that haven't been processed
                new_assets = [
                    asset_id for asset_id in self.results['assets']
                    if asset_id not in self.processed_assets
                    and asset_id != self.target  # Skip initial target
                ]
                
                if not new_assets:
                    break

                for asset_id in new_assets:
                    asset = self.results['assets'][asset_id]
                    logging.info(f"Processing discovered asset: {asset_id} ({asset['type']})")
                    
                    try:
                        if asset['type'] == 'domain':
                            self._process_domain_asset(asset)
                        elif asset['type'] == 'ip':
                            self._process_ip_asset(asset)
                        elif asset['type'] == 'cloud_resource':
                            self._process_cloud_asset(asset)
                        
                        # Mark as processed
                        self.processed_assets.add(asset_id)
                    except Exception as e:
                        logging.error(f"Error processing asset {asset_id}: {str(e)}")
                        continue

            # Store results to MongoDB
            self._store_results()
            
            self.results['scan_info']['status'] = 'completed'
            return self.results
            
        except Exception as e:
            self.results['scan_info']['status'] = 'failed'
            self.results['scan_info']['error'] = str(e)
            self._store_results()
            raise

    def _store_results(self) -> None:
        """Store all scan results in MongoDB."""
        try:
            # Store results using MongoDB handler
            scan_id = self.mongo.store_scan_results(self.results)
            logging.info(f"Results stored in MongoDB with scan ID: {scan_id}")
            
        except Exception as e:
            logging.error(f"Error storing results in MongoDB: {str(e)}")
            raise

def main():
    # Example usage
    target = "bcnsoluciona.com"
    target_type = "domain"
    scan_type = "passive"
    tools = ['shodan', 'virustotal', 'wappalyzer', 'whois']  # Example subset of tools
    
    # Initialize scanner
    recon = AutomatedRecon(target, target_type, scan_type, tools)
    
    try:
        # Run scan
        results = recon.run_scan()
        
        # Print scan ID for reference
        scan_id = results['scan_info']['_id']
        logging.info(f"\nScan completed successfully!")
        logging.info(f"Scan ID: {scan_id}")
        logging.info("\nYou can query the results in MongoDB using:")
        logging.info(f"db.scans.findOne({{'_id': ObjectId('{scan_id}')}})")
        logging.info(f"db.assets.find({{'scan_id': '{scan_id}'}})")
        logging.info(f"db.relationships.find({{'scan_id': '{scan_id}'}})")
        
    except Exception as e:
        logging.error(f"Error during scan: {str(e)}")

if __name__ == "__main__":
    main() 
