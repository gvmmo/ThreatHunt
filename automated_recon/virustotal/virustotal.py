import requests
import json
from time import sleep
import os
from dotenv import load_dotenv

class Virustotal:
    def __init__(self, api_key: str):
        self.api_key = api_key
        if not self.api_key:
            raise ValueError("VT_API_KEY is required")
        self.url = 'https://www.virustotal.com/api/v3'
        self.headers = {
            'x-apikey': self.api_key,
            'accept': 'application/json'
        }
        self.rate_limit_delay = 15  # Time to wait between requests (free API: 4 requests/minute)

    def _make_request(self, endpoint):
        """Helper method to make API requests with rate limiting"""
        try:
            response = requests.get(f"{self.url}/{endpoint}", headers=self.headers)
            response.raise_for_status()
            sleep(self.rate_limit_delay)  # Respect rate limits
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    def domain_report(self, domain):
        """Get basic domain report"""
        return self._make_request(f"domains/{domain}")

    def get_subdomains(self, domain):
        """Get subdomains for the target domain"""
        print(f"\n[DEBUG] Making VirusTotal API request for subdomains of {domain}")
        response = self._make_request(f"domains/{domain}/subdomains")
        print(f"[DEBUG] Raw VirusTotal API response: {json.dumps(response, indent=2)}")
        return response

    def get_relationships(self, domain):
        """Get domain relationships including communicating files, URLs, etc."""
        relationships = {}
        
        # List of relationship types to check
        relation_types = [
            "communicating_files",
            "downloaded_files",
            "referrer_files",
            "resolutions",
            "urls",
            "historical_whois"
        ]

        for relation_type in relation_types:
            relationships[relation_type] = self._make_request(
                f"domains/{domain}/relationships/{relation_type}"
            )

        return relationships

    def get_domain_intelligence(self, domain):
        """
        Gather comprehensive intelligence about a domain
        Returns a structured JSON with all available information
        """
        intelligence = {
            "timestamp": "",
            "domain": domain,
            "basic_report": None,
            "subdomains": None,
            "relationships": None
        }

        try:
            # Get basic domain report
            intelligence["basic_report"] = self.domain_report(domain)
            
            # Get subdomains
            intelligence["subdomains"] = self.get_subdomains(domain)
            
            # Get all relationships
            intelligence["relationships"] = self.get_relationships(domain)

            # Add timestamp
            from datetime import datetime
            intelligence["timestamp"] = datetime.utcnow().isoformat()

            return intelligence

        except Exception as e:
            return {"error": f"Error gathering intelligence: {str(e)}"}

    def save_to_json(self, data, filename):
        """Save results to a JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving to file: {str(e)}")
            return False


def main():
    try:
        # Load environment variables
        load_dotenv()
        
        # Get API key from environment
        api_key = os.getenv('VT_API_KEY')
        if not api_key:
            raise ValueError("VT_API_KEY environment variable is not set")
        
        vt = Virustotal(api_key)
        
        # Example domain
        target_domain = "bcnsoluciona.com"
        
        # Gather intelligence
        intel = vt.get_domain_intelligence(target_domain)
        
        # Save results
        output_file = f"vt_intel_{target_domain}_{intel['timestamp'].split('T')[0]}.json"
        vt.save_to_json(intel, output_file)
        
        print(f"Intelligence gathering completed. Results saved to {output_file}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
