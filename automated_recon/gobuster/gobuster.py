import subprocess
import argparse
import sys
import os
import shutil
import datetime

class Gobuster:
    # Default paths to wordlists used for different types of scans
    DEFAULT_WORDLISTS = {
        'dir': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
        'dns': '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt',
        'vhost': '/usr/share/seclists/Discovery/DNS/namelist.txt'
    }

    # Common file extensions and HTTP status codes to include in the scan
    COMMON_EXTENSIONS = "php,html,js,txt,asp,aspx,jsp,json,zip,bak,conf,config,sh,py"
    STATUS_CODES = "200,204,301,302,307,401,403,500"

    # Number of threads to use for concurrent scanning
    THREADS = 200

    def __init__(self, target):
        self.target = target
        self.check_dependencies()
        self.output_dir = self.set_up_output_dir()

    def check_dependencies(self):
        # Verify required tools (GoBuster) are installed and available in PATH
        if not shutil.which("gobuster"):
            print("\n[!] Error: GoBuster is not installed or not in the PATH")
            sys.exit(1)

    def set_up_output_dir(self):
        # Create timestamped output directory for scan results
        output_dir = os.makedirs("output", exist_ok=True)
        output_dir = "output"
        return output_dir

    def run_gobuster(self, cmd):
        # Execute GoBuster command with error handling and output capture
        try:
            print(f"\n[+] Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"[!] Error in the command (Code {result.returncode})")
            return result.returncode
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            return 1

    def gobuster_dir(self, wordlist):
        # Run directory/file brute-force scan
        now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        print("\n[+] GoBuster in directory mode")
        cmd = [
            "gobuster", "dir",  # Mode
            "-u", f"http://{self.target}",  # URL
            "-w", wordlist,  # Wordlist
            # "-x", self.COMMON_EXTENSIONS,  # Extensions
            # "-s", self.STATUS_CODES,  # Status codes
            "-t", str(self.THREADS),  # Threads
            "-o", f"{self.output_dir}/gobuster_directory_scan_{self.target}_{now}.txt"  # Output file
        ]
        return self.run_gobuster(cmd)

    def gobuster_dns(self, wordlist):
        # Run DNS subdomain brute-force scan
        if not os.path.isfile(wordlist):
            print(f"[!] Wordlist para DNS no encontrada: {wordlist}")
            return
        cmd = [
            "gobuster", "dns",  # Mode
            "-d", self.target,  # Domain
            "-w", wordlist,  # Wordlist
            "-t", str(self.THREADS),  # Threads
            "-o", f"{self.output_dir}/subdomains_file.txt"  # Output file
        ]
        return self.run_gobuster(cmd)

    def gobuster_vhost(self, wordlist):
        # Run virtual host brute-force scan
        print("\n[+] GoBuster in Vhost mode")
        if not os.path.isfile(wordlist):
            print(f"[!] Wordlist for VHost not found: {wordlist}")
            return
        cmd = [
            "gobuster", "vhost",  # Mode
            "-u", f"http://{self.target}",  # URL
            "-w", wordlist,  # Wordlist
            "-t", str(self.THREADS),  # Threads
            "-o", f"{self.output_dir}/vhost_file.txt"  # Output file
        ]
        return self.run_gobuster(cmd)

    def run(self):
        # Run GoBuster in different modes
        self.gobuster_dir(self.DEFAULT_WORDLISTS['dir'])
        # self.gobuster_dns(self.DEFAULT_WORDLISTS['dns'])
        # self.gobuster_vhost(self.DEFAULT_WORDLISTS['vhost'])

if __name__ == "__main__":
    # Configure command line arguments
    parser = argparse.ArgumentParser(description="GoBuster automation script")
    parser.add_argument("target", help="Target domain or IP address")
    args = parser.parse_args()
    target = args.target

    # Create an instance of GobusterScanner and run the scans
    scanner = Gobuster(target)
    print(f"\n[+] Results stored in: {scanner.output_dir}")
    scanner.run()