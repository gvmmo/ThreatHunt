import subprocess
import sys
import os

def run_command(command, check=True):
	"""Executes a command in the operating system."""
	try:
		subprocess.run(command, check=check, shell=True)
	except subprocess.CalledProcessError as e:
		print(f"Error executing the command: {e}")
		sys.exit(1)

def install_gobuster():
	"""Installs GoBuster."""
	print("Installing GoBuster...")
	run_command("sudo apt-get update")
	run_command("sudo apt-get install -y gobuster")

def install_python_dependencies():
	"""Installs Python dependencies."""
	print("Installing Python dependencies...")
	run_command(f"pip install -r requirements.txt")

def install_leaksearch():
	"""Installs the leaksearch repository from GitHub."""
	print("Installing leaksearch from GitHub...")
	# Define the destination path
	tools_dir = "automated_recon/leaksearch/tool"
	leaksearch_dir = os.path.join(tools_dir, "leaksearch")
	
	# Check if the leaksearch folder already exists
	if os.path.exists(leaksearch_dir):
		print(f"leaksearch is already installed in {leaksearch_dir}.")
		return
	
	# Create the 'tools' folder if it does not exist
	if not os.path.exists(tools_dir):
		os.makedirs(tools_dir)
	
	# Clone the GitHub repository into the 'tools/leaksearch' folder
	run_command(f"git clone https://github.com/JoelGMSec/LeakSearch.git {leaksearch_dir}")
	
	# Change to the cloned repository directory
	os.chdir(leaksearch_dir)
	
	# Install Python dependencies for leaksearch
	run_command(f"pip install -r requirements.txt")
	
	# Return to the original directory
	os.chdir("../../../..")
	
def install_go():
	# Installs Go if it is not already installed.
	print("Installing Go...")
	run_command("sudo apt-get update")
	run_command("sudo apt-get install -y golang-go")

def install_nuclei():
	# Installs Nuclei using Go.
	print("Installing Nuclei...")	
	run_command("sudo apt install nuclei")
 
def install_subfinder():
    print("Installing Subfinder...")
    run_command("sudo apt-get install -y subfinder")

def install_git():
	"""Installs Git."""
	print("Installing Git...")
	run_command("sudo apt-get install -y git")

def install_shodan():
	#Installs shodan python module
	print("Installing the Shodan python module...")
	run_command("pip install shodan")

def install_wappalyzer():
	#Installs wappalyzer python module
	print("Installing the Wappalyzer python module...")
	run_command("pip install wappalyzer")

def install_nikto():
	#Installs the Nikto cli tool
	print("Installing Nikto...")
	run_command("sudo apt install nikto -y")

def install_cloudenum():
	#Installs the cloudenum tool
	print("Installing cloudenum...")
	run_command("sudo apt install cloud-enum -y")
 
def install_amass():
	#Installs amass
	print("Installing amass...")
	run_command("sudo apt install amass -y")

def install_trufflehog():
	#Installs trufflehog
	print("Installing trufflehog...")
	run_command("sudo apt install trufflehog -y")
def install_dnsrecon():
	#Installs dnsrecon
	print("Installing dnsrecon...")
	run_command("sudo apt install dnsrecon")
 
def install_spiderfoot():
	#Installs spiderfoot
	print("Installing spiderfoot...")
	run_command("git clone https://github.com/smicallef/spiderfoot.git")
	run_command("mv spiderfoot spiderfoot_tool")
	run_command("cd spiderfoot_tool")
	run_command("pip3 install -r requirements.txt")

def main():
	print("Initiating the installation...")
	install_git()
	install_gobuster()
	install_leaksearch()
	install_go()
	install_nuclei()
	install_shodan()
	install_wappalyzer()
	install_nikto()
	install_cloudenum()
	install_amass()
	install_trufflehog()
	install_subfinder()
	install_dnsrecon()
	install_python_dependencies()
	print("Installation completed.")

if __name__ == "__main__":
	main()
