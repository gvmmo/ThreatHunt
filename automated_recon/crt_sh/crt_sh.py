import requests
import json
import argparse
from datetime import datetime
import os

class Crtsh:
    def __init__(self, domain):
        self.domain = domain

    def download_certificates(self):
        """
        Downloads certificates in JSON format for a specific domain
        
        :return: Path to the saved JSON file
        """
        # URL of the crt.sh API
        url = f'https://crt.sh/?q={self.domain}&output=json'
        
        try:
            output_dir = "output"
            os.makedirs(output_dir, exist_ok=True)
            # Make the request
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"output/crtsh_{self.domain}_{timestamp}_certificates.json"
            
            # Save JSON directly
            with open(filename, 'w', encoding='utf-8') as file:
                file.write(response.text)
            
            print(f"Certificates saved in {filename}")
            return filename
        
        except requests.RequestException as e:
            print(f"Error making the request: {e}")
            return None
        except IOError as e:
            print(f"Error saving the file: {e}")
            return None

    @staticmethod
    def parse_arguments():
        # Configure the argument parser
        parser = argparse.ArgumentParser(description='Download certificates from crt.sh')
        parser.add_argument('domain', help='Domain to search for certificates')
        return parser.parse_args()

    def run(self):
        # Download certificates
        self.download_certificates()

if __name__ == '__main__':
    args = Crtsh.parse_arguments()
    downloader = Crtsh(args.domain)
    downloader.run()