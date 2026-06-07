import requests
import json
import os
import argparse
import re
import sys
from dotenv import load_dotenv

class WhoisTool:
    def __init__(self, target: str, api_key: str):
        self.target = target
        self.api_key = api_key
        if not self.api_key:
            raise ValueError("WHOIS_API_KEY is required")
        self.url = "https://whois.whoisxmlapi.com/api/v1"
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def load_api_key(self):
        try:
            # Load the .env file
            load_dotenv()
            # Get the API key from the environment variables
            return os.getenv("APILAYER_KEY")
        except Exception as e:
            print(f"Error reading the .env file: {e}")
            return False

    def set_output_file(self, target):
        os.makedirs("output", exist_ok=True)
        return f"output/whois_{target}.json"

    def consult_whois(self, domain):
        url = f"https://api.apilayer.com/whois/query?domain={domain}"
        headers = {"apikey": self.api_key}
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred for {domain}: {http_err}")
        except requests.exceptions.RequestException as err:
            print(f"Error occurred for {domain}: {err}")
        return None

    def read_domains_from_file(self, file):
        try:
            with open(file, 'r') as f:
                return [domain.strip() for domain in f if domain.strip()]
        except FileNotFoundError:
            print(f"The file {file} was not found.")
        except Exception as e:
            print(f"Error reading the file {file}: {e}")
        return []

    def is_file(self, path):
        return os.path.isfile(path)

    def is_domain(self, text):
        domain_regex = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
        return bool(domain_regex.match(text))

    def process_domain(self, domain):
        result = self.consult_whois(domain)
        if result:
            print(f"\nWHOIS information for {domain}:")
            print("\nMain details:")
            print(f"Registrar: {result.get('registrar', 'Not available')}")
            print(f"Creation date: {result.get('created_date', 'Not available')}")
            print(f"Expiration date: {result.get('expiration_date', 'Not available')}")
            output_file = self.set_output_file(domain)
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=4)
            print(f"Result saved in {output_file}")
        else:
            print(f"Could not obtain WHOIS information for {domain}")

    def run(self):
        target = self.target
        
        if self.is_file(target):
            domains = self.read_domains_from_file(target)
            if not domains:
                print("No domains were found in the provided file.")
            else:
                for domain in domains:
                    if self.is_domain(domain):
                        self.process_domain(domain)
                    else:
                        print(f"The domain {domain} is not valid.")
        elif self.is_domain(target):
            self.process_domain(target)
        else:
            print("The provided parameter is not a valid file or a valid domain.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Python wrapper for Whois - Domain WHOIS lookup')
    parser.add_argument('target', help='Text file with domains or a single domain')
    args = parser.parse_args()
    
    tool = WhoisTool(args.target, args.api_key)
    tool.run()