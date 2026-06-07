import subprocess
import argparse
import sys
import os
import json

class Subfinder:
    def __init__(self, domain):
        self.domain = domain
        self.output_file = self.set_output_file(domain)

    def set_output_file(self, target):
        os.makedirs("output", exist_ok=True)
        return f"output/subfinder_{target}.json"

    def run_subfinder(self):
        """
        Runs Subfinder for a given domain and saves/returns the results
        """
        try:
            # Build the command
            command = ['subfinder', '-d', self.domain, '-silent', '-all', '-oJ']
            
            # Run subfinder
            result = subprocess.run(
                command,
                check=True,
                text=True,
                capture_output=True
            )
            
            # Handle the output
            subdomains = result.stdout.splitlines()
            
            # Convert each line of the output into a JSON dictionary
            subdomains_list = [json.loads(subdomain) for subdomain in subdomains]
            
            # Save the results as a list in a JSON file
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(subdomains_list, f, indent=4)
            print(f"\n[+] Results saved in: {self.output_file}")
            
            return subdomains_list
        
        except subprocess.CalledProcessError as e:
            print(f"\n[!] Error running Subfinder: {e.stderr}")
            sys.exit(1)
        except FileNotFoundError:
            print("\n[!] Subfinder not found. Is it installed and in the PATH?")
            return False
        except json.JSONDecodeError as e:
            print(f"\n[!] JSON decoding error: {e}")
            return False
        except Exception as e:
            print(f"\n[!] Unexpected error: {str(e)}")
            return False

    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(
            description='Python wrapper for Subfinder - Subdomain discovery'
        )
        parser.add_argument('domain', help='Target domain')
        return parser.parse_args()

    def run(self):
        print(f"\n[+] Scanning subdomains for: {self.domain}")
        subdomains = self.run_subfinder()
        print("\n[+] Subdomains found:")
        for sub in subdomains:
            print(f"  • {sub['host']}")
        print(f"\n[+] Total found: {len(subdomains)} subdomains")

if __name__ == "__main__":
    args = Subfinder.parse_arguments()
    scanner = Subfinder(args.domain)
    scanner.run()