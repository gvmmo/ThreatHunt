import os
import json
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv
from collections import defaultdict

# Import all tool modules
from shodan.script_shodan import ShodanScanner
from nmap.script_nmap import NmapScanner
from cloudenum.cloudenum import CloudEnumScanner
from crt_sh.crt_sh import CRTScanner
from dnsrecon.dnsrecon import DNSReconScanner
from gobuster.gobuster import GoBusterScanner
from google_dorks.google_dorks import GoogleDorksScanner
from intelx.intelx import IntelXScanner
from nikto.nikto import NiktoScanner
from nuclei.nuclei import NucleiScanner
from subfinder.subfinder import SubfinderScanner
from virustotal.virustotal import VirusTotalScanner
from wappalyzer.script_wappalyzer import WappalyzerScanner
from whois.whois import WhoisScanner

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
        load_dotenv()
        self.target = target
        self.target_type = target_type
        self.scan_type = scan_type
        self.tools = tools or self._get_all_tools()
        
        # Initialize MongoDB connection
        self.mongo_client = MongoClient(os.getenv('MONGODB_URI'))
        self.db = self.mongo_client['asm_database']
        
        # Define collections
        self.scans = self.db['scans']
        self.assets = self.db['assets']
        self.services = self.db['services']
        self.vulnerabilities = self.db['vulnerabilities']
        self.dns_records = self.db['dns_records']
        self.certificates = self.db['certificates']
        self.relationships = self.db['relationships']
        self.web_technologies = self.db['web_technologies']
        self.whois_records = self.db['whois_records']
        
        # Initialize results structure
        self.results = {
            'scan_info': {
                'target': target,
                'target_type': target_type,
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'status': 'running',
                'tools_used': self.tools
            },
            'assets': {
                'ips': [],
                'domains': [],
                'cloud_assets': [],
                'web_apps': []
            },
            'findings': {
                'vulnerabilities': [],
                'misconfigurations': [],
                'exposed_data': []
            },
            'relationships': [],
            'raw_results': {}
        }
        
        # Initialize tools
        self._initialize_tools()
        
        # Initialize tracking sets
        self.discovered_ips = set()
        self.discovered_domains = set()
        self.discovered_services = set()
        self.processed_urls = set()

    def _get_all_tools(self) -> List[str]:
        """Get list of all available tools."""
        return [
            'shodan', 'nmap', 'cloudenum', 'crt_sh', 'dnsrecon',
            'gobuster', 'google_dorks', 'intelx', 'nikto', 'nuclei',
            'subfinder', 'virustotal', 'wappalyzer', 'whois'
        ]

    def _initialize_tools(self) -> None:
        """Initialize all selected tools."""
        if 'shodan' in self.tools:
            self.shodan = ShodanScanner(os.getenv('SHODAN_API_KEY'))
        if 'nmap' in self.tools:
            self.nmap = NmapScanner()
        if 'cloudenum' in self.tools:
            self.cloudenum = CloudEnumScanner()
        if 'crt_sh' in self.tools:
            self.crt_sh = CRTScanner()
        if 'dnsrecon' in self.tools:
            self.dnsrecon = DNSReconScanner()
        if 'gobuster' in self.tools:
            self.gobuster = GoBusterScanner()
        if 'google_dorks' in self.tools:
            self.google_dorks = GoogleDorksScanner()
        if 'intelx' in self.tools:
            self.intelx = IntelXScanner(os.getenv('INTELX_API_KEY'))
        if 'nikto' in self.tools:
            self.nikto = NiktoScanner()
        if 'nuclei' in self.tools:
            self.nuclei = NucleiScanner()
        if 'subfinder' in self.tools:
            self.subfinder = SubfinderScanner()
        if 'virustotal' in self.tools:
            self.virustotal = VirusTotalScanner(os.getenv('VIRUSTOTAL_API_KEY'))
        if 'wappalyzer' in self.tools:
            self.wappalyzer = WappalyzerScanner()
        if 'whois' in self.tools:
            self.whois = WhoisScanner()

    def run_scan(self) -> Dict[str, Any]:
        """
        Run the appropriate scan based on target type and scan type.
        """
        try:
            # Phase 1: Initial Discovery
            if self.target_type == 'organization':
                self._scan_organization()
            elif self.target_type == 'domain':
                self._scan_domain(self.target)
            elif self.target_type == 'ip':
                self._scan_ip(self.target)
            
            # Phase 2: Subdomain Discovery and Analysis
            self._process_subdomains()
            
            # Phase 3: Service Discovery and Analysis
            self._process_services()
            
            # Phase 4: Web Application Analysis
            self._process_web_applications()
            
            # Phase 5: Vulnerability Scanning
            self._process_vulnerabilities()
            
            # Phase 6: Cloud Asset Discovery
            self._process_cloud_assets()
            
            # Store all results
            self._store_results()
            
            self.results['scan_info']['status'] = 'completed'
            return self.results
            
        except Exception as e:
            self.results['scan_info']['status'] = 'failed'
            self.results['scan_info']['error'] = str(e)
            self._store_results()
            raise

    def _scan_organization(self) -> None:
        """Run organization-based scans."""
        # Start with Shodan organization search
        if 'shodan' in self.tools:
            org_results = self.shodan.search_organization(self.target)
            self.results['raw_results']['shodan_org'] = org_results
            self._process_shodan_results(org_results)
            
            # Extract and process discovered assets
            for host in org_results.get('hosts', []):
                if 'ip' in host:
                    self.discovered_ips.add(host['ip'])
                if 'domains' in host:
                    self.discovered_domains.update(host['domains'])

    def _scan_domain(self, domain: str) -> None:
        """Run domain-based scans."""
        # Passive scans
        if self.scan_type == 'passive':
            # WHOIS and DNS records first
            if 'whois' in self.tools:
                whois_results = self.whois.scan_domain(domain)
                self._process_whois_results(whois_results)
            
            if 'dnsrecon' in self.tools:
                dns_results = self.dnsrecon.scan_domain(domain)
                self._process_dnsrecon_results(dns_results)
            
            # Certificate transparency
            if 'crt_sh' in self.tools:
                crt_results = self.crt_sh.scan_domain(domain)
                self._process_crt_sh_results(crt_results)
            
            # Subdomain discovery
            if 'subfinder' in self.tools:
                subfinder_results = self.subfinder.scan_domain(domain)
                self._process_subfinder_results(subfinder_results)
            
            # VirusTotal relationships
            if 'virustotal' in self.tools:
                vt_results = self.virustotal.scan_domain(domain)
                self._process_virustotal_results(vt_results)
            
            # Google dorks
            if 'google_dorks' in self.tools:
                dorks_results = self.google_dorks.scan_domain(domain)
                self.results['raw_results'][f'google_dorks_{domain}'] = dorks_results

    def _scan_ip(self, ip: str) -> None:
        """Run IP-based scans."""
        # Passive scans
        if self.scan_type == 'passive':
            if 'shodan' in self.tools:
                shodan_results = self.shodan.scan_host(ip)
                self._process_shodan_results(shodan_results)
            
            if 'virustotal' in self.tools:
                vt_results = self.virustotal.scan_ip(ip)
                self._process_virustotal_results(vt_results)
            
            if 'whois' in self.tools:
                whois_results = self.whois.scan_ip(ip)
                self._process_whois_results(whois_results)
        
        # Active scans
        if self.scan_type == 'active':
            if 'nmap' in self.tools:
                nmap_results = self.nmap.scan_host(ip)
                self._process_nmap_results(nmap_results)

    def _process_subdomains(self) -> None:
        """Process all discovered subdomains."""
        for domain in self.discovered_domains:
            # Skip if already processed
            if domain in self.processed_urls:
                continue
                
            # Run subdomain-specific scans
            if 'wappalyzer' in self.tools:
                wapp_results = self.wappalyzer.scan_domain(domain)
                self._process_wappalyzer_results(wapp_results)
            
            if 'gobuster' in self.tools and self.scan_type == 'active':
                gobuster_results = self.gobuster.scan_domain(domain)
                self.results['raw_results'][f'gobuster_{domain}'] = gobuster_results
            
            if 'nikto' in self.tools and self.scan_type == 'active':
                nikto_results = self.nikto.scan_host(domain)
                self._process_nikto_results(nikto_results)
            
            self.processed_urls.add(domain)

    def _process_services(self) -> None:
        """Process all discovered services."""
        for service in self.discovered_services:
            ip, port = service.split(':')
            
            # Run service-specific scans
            if 'nuclei' in self.tools and self.scan_type == 'active':
                nuclei_results = self.nuclei.scan_host(f"{ip}:{port}")
                self._process_nuclei_results(nuclei_results)

    def _process_web_applications(self) -> None:
        """Process all discovered web applications."""
        # Group URLs by domain for efficient scanning
        urls_by_domain = defaultdict(list)
        for url in self.processed_urls:
            domain = url.split('/')[0]
            urls_by_domain[domain].append(url)
        
        # Process each domain's URLs
        for domain, urls in urls_by_domain.items():
            # Run web-specific scans
            if 'wappalyzer' in self.tools:
                for url in urls:
                    wapp_results = self.wappalyzer.scan_domain(url)
                    self._process_wappalyzer_results(wapp_results)
            
            if 'nuclei' in self.tools and self.scan_type == 'active':
                for url in urls:
                    nuclei_results = self.nuclei.scan_host(url)
                    self._process_nuclei_results(nuclei_results)

    def _process_vulnerabilities(self) -> None:
        """Process all discovered vulnerabilities."""
        # Group vulnerabilities by target
        vulns_by_target = defaultdict(list)
        for vuln in self.results['findings']['vulnerabilities']:
            vulns_by_target[vuln['target']].append(vuln)
        
        # Process each target's vulnerabilities
        for target, vulns in vulns_by_target.items():
            # Add correlation data
            for vuln in vulns:
                vuln['related_vulnerabilities'] = [
                    v['identifier'] for v in vulns 
                    if v['identifier'] != vuln['identifier']
                ]

    def _process_cloud_assets(self) -> None:
        """Process all discovered cloud assets."""
        # Group domains by potential cloud providers
        domains_by_provider = defaultdict(list)
        for domain in self.discovered_domains:
            if 'aws' in domain.lower():
                domains_by_provider['aws'].append(domain)
            elif 'azure' in domain.lower():
                domains_by_provider['azure'].append(domain)
            elif 'gcp' in domain.lower() or 'google' in domain.lower():
                domains_by_provider['gcp'].append(domain)
        
        # Run cloud-specific scans
        if 'cloudenum' in self.tools:
            for provider, domains in domains_by_provider.items():
                cloud_results = self.cloudenum.scan_domain(domains[0])
                self._process_cloudenum_results(cloud_results)

    def _store_results(self) -> None:
        """Store all scan results in MongoDB."""
        # Store scan metadata
        scan_id = self.scans.insert_one(self.results['scan_info']).inserted_id
        
        # Store assets
        self._store_assets(scan_id)
        
        # Store services
        self._store_services(scan_id)
        
        # Store vulnerabilities
        self._store_vulnerabilities(scan_id)
        
        # Store DNS records
        self._store_dns_records(scan_id)
        
        # Store certificates
        self._store_certificates(scan_id)
        
        # Store relationships
        self._store_relationships(scan_id)
        
        # Store web technologies
        self._store_web_technologies(scan_id)
        
        # Store WHOIS records
        self._store_whois_records(scan_id)

    def _store_assets(self, scan_id: str) -> None:
        """Store discovered assets."""
        for ip in self.results['assets']['ips']:
            self.assets.update_one(
                {'identifier': ip['identifier'], 'type': 'ip'},
                {'$set': {
                    **ip,
                    'last_seen': datetime.now().isoformat(),
                    'scan_id': str(scan_id)
                }},
                upsert=True
            )
        
        for domain in self.results['assets']['domains']:
            self.assets.update_one(
                {'identifier': domain['identifier'], 'type': 'domain'},
                {'$set': {
                    **domain,
                    'last_seen': datetime.now().isoformat(),
                    'scan_id': str(scan_id)
                }},
                upsert=True
            )
        
        for cloud_asset in self.results['assets']['cloud_assets']:
            self.assets.update_one(
                {'identifier': cloud_asset['identifier'], 'type': 'cloud'},
                {'$set': {
                    **cloud_asset,
                    'last_seen': datetime.now().isoformat(),
                    'scan_id': str(scan_id)
                }},
                upsert=True
            )

    def _store_services(self, scan_id: str) -> None:
        """Store discovered services."""
        for service in self.results['services']:
            self.services.update_one(
                {
                    'identifier': service['identifier'],
                    'type': service['type'],
                    'port': service['port']
                },
                {'$set': {
                    **service,
                    'last_seen': datetime.now().isoformat(),
                    'scan_id': str(scan_id)
                }},
                upsert=True
            )

    def _store_vulnerabilities(self, scan_id: str) -> None:
        """Store discovered vulnerabilities."""
        for vuln in self.results['findings']['vulnerabilities']:
            self.vulnerabilities.update_one(
                {
                    'identifier': vuln['identifier'],
                    'type': vuln['type'],
                    'target': vuln['target']
                },
                {'$set': {
                    **vuln,
                    'last_seen': datetime.now().isoformat(),
                    'scan_id': str(scan_id)
                }},
                upsert=True
            )

    def _store_dns_records(self, scan_id: str) -> None:
        """Store DNS records."""
        for record in self.results['dns_records']:
            self.dns_records.update_one(
                {
                    'domain': record['domain'],
                    'type': record['type'],
                    'value': record['value']
                },
                {'$set': {
                    **record,
                    'last_seen': datetime.now().isoformat(),
                    'scan_id': str(scan_id)
                }},
                upsert=True
            )

    def _store_certificates(self, scan_id: str) -> None:
        """Store SSL/TLS certificates."""
        for cert in self.results['certificates']:
            self.certificates.update_one(
                {
                    'domain': cert['domain'],
                    'serial_number': cert['serial_number']
                },
                {'$set': {
                    **cert,
                    'last_seen': datetime.now().isoformat(),
                    'scan_id': str(scan_id)
                }},
                upsert=True
            )

    def _store_relationships(self, scan_id: str) -> None:
        """Store relationships between assets."""
        for rel in self.results['relationships']:
            self.relationships.update_one(
                {
                    'source': rel['source'],
                    'target': rel['target'],
                    'type': rel['type']
                },
                {'$set': {
                    **rel,
                    'last_seen': datetime.now().isoformat(),
                    'scan_id': str(scan_id)
                }},
                upsert=True
            )

    def _store_web_technologies(self, scan_id: str) -> None:
        """Store web technologies information."""
        for tech in self.results['web_technologies']:
            self.web_technologies.update_one(
                {
                    'url': tech['url'],
                    'technology': tech['technology']
                },
                {'$set': {
                    **tech,
                    'last_seen': datetime.now().isoformat(),
                    'scan_id': str(scan_id)
                }},
                upsert=True
            )

    def _store_whois_records(self, scan_id: str) -> None:
        """Store WHOIS records."""
        for record in self.results['whois_records']:
            self.whois_records.update_one(
                {
                    'domain': record['domain']
                },
                {'$set': {
                    **record,
                    'last_seen': datetime.now().isoformat(),
                    'scan_id': str(scan_id)
                }},
                upsert=True
            )

    def _process_tool_results(self, tool_name: str, results: Dict[str, Any]) -> None:
        """Process and store results from a specific tool."""
        if tool_name == 'shodan':
            self._process_shodan_results(results)
        elif tool_name == 'nmap':
            self._process_nmap_results(results)
        elif tool_name == 'dnsrecon':
            self._process_dnsrecon_results(results)
        elif tool_name == 'virustotal':
            self._process_virustotal_results(results)
        elif tool_name == 'nuclei':
            self._process_nuclei_results(results)
        elif tool_name == 'nikto':
            self._process_nikto_results(results)
        elif tool_name == 'wappalyzer':
            self._process_wappalyzer_results(results)
        elif tool_name == 'whois':
            self._process_whois_results(results)
        elif tool_name == 'crt_sh':
            self._process_crt_sh_results(results)
        elif tool_name == 'subfinder':
            self._process_subfinder_results(results)
        elif tool_name == 'cloudenum':
            self._process_cloudenum_results(results)

    def _process_shodan_results(self, results: Dict[str, Any]) -> None:
        """Process Shodan scan results."""
        # Process host information
        for host in results.get('hosts', []):
            self.results['assets']['ips'].append({
                'identifier': host['ip'],
                'type': 'ip',
                'organization': host.get('org'),
                'hostnames': host.get('hostnames', []),
                'domains': host.get('domains', []),
                'isp': host.get('isp'),
                'asn': host.get('asn'),
                'os': host.get('os'),
                'tags': host.get('tags', [])
            })
            
            # Process services
            for service in host.get('data', []):
                service_data = {
                    'identifier': f"{host['ip']}:{service.get('port')}",
                    'type': 'service',
                    'ip': host['ip'],
                    'port': service.get('port'),
                    'transport': service.get('transport'),
                    'product': service.get('product'),
                    'version': service.get('version'),
                    'banner': service.get('data'),
                    'cpe': service.get('cpe', [])
                }
                self.results['services'].append(service_data)
                
                # Process vulnerabilities
                for cve, vuln in service.get('vulns', {}).items():
                    self.results['findings']['vulnerabilities'].append({
                        'identifier': cve,
                        'type': 'cve',
                        'target': f"{host['ip']}:{service.get('port')}",
                        'summary': vuln.get('summary'),
                        'cvss': vuln.get('cvss_v3'),
                        'source': 'shodan'
                    })

    def _process_nmap_results(self, results: Dict[str, Any]) -> None:
        """Process Nmap scan results."""
        for host in results.get('hosts', []):
            for port in host.get('ports', []):
                service_data = {
                    'identifier': f"{host['ip']}:{port['port']}",
                    'type': 'service',
                    'ip': host['ip'],
                    'port': port['port'],
                    'state': port['state'],
                    'service': port.get('service', {}),
                    'scripts': port.get('scripts', [])
                }
                self.results['services'].append(service_data)

    def _process_dnsrecon_results(self, results: Dict[str, Any]) -> None:
        """Process DNSRecon scan results."""
        for record in results.get('records', []):
            self.results['dns_records'].append({
                'domain': results['domain'],
                'type': record['type'],
                'value': record['value'],
                'source': 'dnsrecon'
            })

    def _process_virustotal_results(self, results: Dict[str, Any]) -> None:
        """Process VirusTotal scan results."""
        # Process relationships
        for rel_type, rel_data in results.get('relationships', {}).items():
            if isinstance(rel_data, list):
                for item in rel_data:
                    self.results['relationships'].append({
                        'source': results['target'],
                        'target': item.get('id'),
                        'type': rel_type,
                        'data': item
                    })

    def _process_nuclei_results(self, results: Dict[str, Any]) -> None:
        """Process Nuclei scan results."""
        for finding in results.get('findings', []):
            self.results['findings']['vulnerabilities'].append({
                'identifier': finding.get('id'),
                'type': 'web_vulnerability',
                'target': finding.get('target'),
                'severity': finding.get('severity'),
                'description': finding.get('description'),
                'source': 'nuclei'
            })

    def _process_nikto_results(self, results: Dict[str, Any]) -> None:
        """Process Nikto scan results."""
        for finding in results.get('results', []):
            for vuln in finding.get('vulnerabilities', []):
                self.results['findings']['vulnerabilities'].append({
                    'identifier': vuln.get('id'),
                    'type': 'web_vulnerability',
                    'target': f"{finding.get('target')}:{finding.get('port')}",
                    'description': vuln.get('description'),
                    'references': vuln.get('references'),
                    'source': 'nikto'
                })

    def _process_wappalyzer_results(self, results: Dict[str, Any]) -> None:
        """Process Wappalyzer scan results."""
        for url, technologies in results.items():
            for tech in technologies:
                self.results['web_technologies'].append({
                    'url': url,
                    'technology': tech['name'],
                    'version': tech.get('version'),
                    'categories': tech.get('categories', []),
                    'confidence': tech.get('confidence')
                })

    def _process_whois_results(self, results: Dict[str, Any]) -> None:
        """Process WHOIS scan results."""
        self.results['whois_records'].append({
            'domain': results['domain'],
            'registrar': results.get('registrar'),
            'registrant': results.get('registrant'),
            'creation_date': results.get('creation_date'),
            'expiration_date': results.get('expiration_date'),
            'name_servers': results.get('name_servers', []),
            'source': 'whois'
        })

    def _process_crt_sh_results(self, results: Dict[str, Any]) -> None:
        """Process crt.sh scan results."""
        for cert in results.get('certificates', []):
            self.results['certificates'].append({
                'domain': results['domain'],
                'serial_number': cert.get('serial_number'),
                'issuer': cert.get('issuer'),
                'valid_from': cert.get('valid_from'),
                'valid_to': cert.get('valid_to'),
                'source': 'crt_sh'
            })

    def _process_subfinder_results(self, results: Dict[str, Any]) -> None:
        """Process Subfinder scan results."""
        for subdomain in results.get('subdomains', []):
            self.results['assets']['domains'].append({
                'identifier': subdomain,
                'type': 'domain',
                'parent_domain': results['domain'],
                'source': 'subfinder'
            })

    def _process_cloudenum_results(self, results: Dict[str, Any]) -> None:
        """Process CloudEnum scan results."""
        for provider, assets in results.items():
            for asset in assets:
                self.results['assets']['cloud_assets'].append({
                    'identifier': asset,
                    'type': 'cloud',
                    'provider': provider,
                    'source': 'cloudenum'
                })

def main():
    # Example usage
    target = "example.com"
    target_type = "domain"
    scan_type = "passive"
    tools = ['shodan', 'cloudenum', 'whois', 'crt_sh', 'subfinder', 'nuclei', 'wappalyzer', 'dnsrecon']  # Example subset of tools
    
    recon = AutomatedRecon(target, target_type, scan_type, tools)
    results = recon.run_scan()
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 