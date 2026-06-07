import subprocess
import argparse
import sys
import os
import re

class Nuclei:
    def __init__(self, target):
        self.target = target
        self.json_file, self.nuclei_findings_file = self.set_output_file()
        self.time_pattern = re.compile(r'\[\d+:\d{2}:\d{2}\]')
        self.ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

    def clean_ansi(self, line):
        # Removes ANSI escape codes from a line
        return self.ansi_escape.sub('', line)

    def set_output_file(self):
        os.makedirs("output", exist_ok=True)
        json_file = f"output/nuclei_scan_{self.target}.json"
        nuclei_findings_file = f"output/nuclei_findings_{self.target}.txt"
        return json_file, nuclei_findings_file

    def run_nuclei_scan(self):
        nuclei_findings_outputs = []
        
        nuclei_command = [
            "nuclei",
            "-target", self.target,
            "-severity", "critical,high,medium,low,info",
            "-rate-limit", "100",
            "-concurrency", "50",
            "-timeout", "10",
            "-retries", "3",
            "-headless",
            "-system-resolvers",
            "-stats",
            "-silent",
            "-json-export", self.json_file,
            "-irr",
        ]
        
        print(f"\n[+] Command to execute: {' '.join(nuclei_command)}")

        try:
            print(f"\n[+] Starting full scan for: {self.target}")
            process = subprocess.Popen(
                nuclei_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    cleaned_line = self.clean_ansi(output.strip())
                    print(cleaned_line)
                    if not self.time_pattern.search(cleaned_line):
                        nuclei_findings_outputs.append(cleaned_line)

            if nuclei_findings_outputs:
                with open(self.nuclei_findings_file, 'w') as f:
                    f.write('\n'.join(nuclei_findings_outputs))
                print(f"\n[+] Findings saved in: {self.nuclei_findings_file}")

        except Exception as e:
            print(f"\n[!] Error during the scan: {str(e)}")
            sys.exit(1)

    @staticmethod
    def check_nuclei_installed():
        try:
            subprocess.run(["nuclei", "-version"], check=True, capture_output=True)
        except:
            print("[!] Nuclei is not installed or not in the PATH")
            sys.exit(1)

    def run(self):
        try:
            self.check_nuclei_installed()
            self.run_nuclei_scan()
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by the user")
            sys.exit(1)
        except Exception as e:
            print(f"\n[!] Error during the scan: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Security Scanner with Nuclei')
    parser.add_argument('target', help='Target URL')
    
    args = parser.parse_args()
    target = args.target
    
    scanner = Nuclei(target)
    scanner.run()