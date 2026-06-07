from Wappalyzer import Wappalyzer, WebPage
from urllib.parse import urlparse
import os
import json
import requests
from concurrent.futures import ThreadPoolExecutor
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem
from typing import List, Dict, Optional
from datetime import datetime

class WappalyzerScanner:
    def __init__(self, max_threads: int = 5):
        """Initialize the Wappalyzer analyzer"""
        self.max_threads = max_threads
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Initialize user agent rotator
        software_names = [SoftwareName.CHROME.value]
        operating_systems = [OperatingSystem.WINDOWS.value, OperatingSystem.LINUX.value]
        self.user_agent_rotator = UserAgent(
            software_names=software_names,
            operating_systems=operating_systems,
            limit=100
        )
        
    def set_user_agent(self, url: str, user_agent: str) -> Optional[WebPage]:
        """Set up a custom user agent and create a WebPage object"""
        try:
            custom_headers = {
                'User-Agent': user_agent
            }

            # Create requests session with custom user agent
            session = requests.Session()
            session.headers.update(custom_headers)

            # Build WebPage manually with custom user agent
            response = session.get(url, timeout=30)
            response.raise_for_status()
            
            webpage = WebPage(
                url=url,
                html=response.text,
                headers=response.headers
            )
            return webpage
        except requests.RequestException as e:
            print(f"[!] Error accessing {url}: {str(e)}")
            return None

    def analyze_website(self, url: str, webpage: WebPage) -> Dict:
        """Analyze a website using Wappalyzer"""
        try:
            wappalyzer = Wappalyzer.latest()
            
            # Get technologies, versions and categories
            technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
            
            return {
                "url": url,
                "technologies": technologies
            }
        except Exception as e:
            print(f"[!] Error analyzing {url}: {str(e)}")
            return {
                "url": url,
                "error": str(e)
            }

    def process_domain(self, domain: str) -> Dict:
        """Process a single domain"""
        try:
            # Ensure domain has proper format
            if not domain.startswith(('http://', 'https://')):
                domain = f"https://{domain}"
                
            parsed_url = urlparse(domain)
            domain_name = parsed_url.netloc
            
            # Get random user agent
            user_agent = self.user_agent_rotator.get_random_user_agent()
            
            # Create webpage object
            webpage = self.set_user_agent(domain, user_agent)
            if not webpage:
                return {
                    "domain": domain_name,
                    "error": "Failed to access website"
                }
                
            # Analyze website
            results = self.analyze_website(domain, webpage)
            
            return {
                "domain": domain_name,
                "results": results
            }
            
        except Exception as e:
            return {
                "domain": domain_name if 'domain_name' in locals() else domain,
                "error": str(e)
            }

    def analyze_domains(self, domains: List[str], output_dir: str = "/output") -> Dict:
        """
        Run Wappalyzer analysis on a list of domains
        
        Args:
            domains: List of domains to analyze
            output_dir: Directory to save results
            
        Returns:
            Dict containing results and metadata
        """
        #print(f"\n[+] Starting Wappalyzer analysis for {len(domains)} domains...")
        
        results = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self.process_domain, domain) for domain in domains]
            
            for future in futures:
                try:
                    result = future.result()
                    results.append(result)
                    print(f"[+] Completed analysis for {result.get('domain', 'unknown')}")
                except Exception as e:
                    print(f"[!] Error processing domain: {str(e)}")
        
        # Save results
        try:
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"wappalyzer_results_{self.timestamp}.json")
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4)
                
            print(f"\n[+] Results saved to: {output_file}")
            
        except Exception as e:
            print(f"[!] Error saving results: {str(e)}")
        
        return {
            "tool": "wappalyzer",
            "timestamp": self.timestamp,
            "domains_analyzed": len(domains),
            "results": results,
            "output_file": output_file if 'output_file' in locals() else None
        }

    @classmethod
    def run_wappalyzer(cls, domains: List[str], output_dir: str = "output", max_threads: int = 5) -> Dict:
        """
        Wrapper function to maintain backward compatibility
        
        Args:
            domains: List of domains to analyze
            output_dir: Directory to save results
            max_threads: Maximum number of concurrent threads
            
        Returns:
            Dict containing results and metadata
        """
        analyzer = WappalyzerScanner(max_threads=max_threads)
        return analyzer.analyze_domains(domains, output_dir)

if __name__ == "__main__":
    # This section only runs if the script is executed directly
    import argparse
    
    parser = argparse.ArgumentParser(description="Wappalyzer Technology Stack Analyzer")
    parser.add_argument("-d", "--domains", nargs="+", required=True, help="List of domains to analyze")
    parser.add_argument("-o", "--output", default="output", help="Output directory for results")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads")
    
    args = parser.parse_args()
    
    results = WappalyzerScanner.run_wappalyzer(args.domains, args.output, args.threads)
    print("\n[+] Analysis completed!")