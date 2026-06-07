import nmap
import subprocess
import argparse
import sys
import os
import getpass
import socket


class NmapScanner:
    def __init__(self, host):
        self.host = host
        if not self.resolve_host(host):
            print(f"Error: Unable to resolve host {host}.")
            self.host_ip = None
            return None
        else:
            self.host_ip = self.resolve_host(host)
        self.scan_types = ["sS", "sT", "sU"]  # SYN, Connect, UDP scans

    def resolve_host(self, host):
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror as e:
            print(f"[!] Error resolving hostname: {e}")
            return False

    def is_host_up(self):
        """Checks if a host is reachable using the ping command."""
        if self.host_ip:
            try:
                command = ["ping", "-c", "3", self.host_ip]
                p = subprocess.run(command, capture_output=True, text=True, timeout=5)
                if p.returncode == 0:
                    print(f"Host {self.host_ip} is up")
                    return True
                else:
                    print(f"Host {self.host_ip} is down")
                    return False
            except subprocess.TimeoutExpired:
                print(f"\n[{self.host_ip}] Timeout in ping")
                return False
        else: 
            print(f"[!] Host IP address is not available.")
            return False

    def scan_open_ports_on_host(self, ports, scan_type):
        """Performs initial port scanning using the specified scan type."""
        nm = nmap.PortScanner()
        arguments = f"-{scan_type} --open --min-rate 5000 -vvv -n -Pn"
        try:
            nm.scan(self.host_ip, arguments=arguments + " " + ports)
            print(f"Scanning open ports with the command: {nm.command_line()}")
            return nm[self.host_ip]
        except Exception as e:
            print(f"An error occurred in scan_open_ports_on_host: {e}")

    def detect_services_in_ports(self, ports, scan_type):
        """Performs service and version detection on specified ports."""
        nm = nmap.PortScanner()
        
        output_dir = "output"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Archivo de salida en la carpeta 'output'
        output_file = os.path.join(output_dir, f"nmap-scan-{self.host_ip}-{scan_type}.txt")
        argument = f"-sCV -oN {output_file}"
        
        try:
            if scan_type == "sU":
                argument += " -sU"  # Add UDP scan flag if needed
            nm.scan(self.host_ip, arguments=argument + " " + ports)
            print(f"Scanning services with the command: {nm.command_line()}")
            return nm[self.host_ip]
        except Exception as e:
            print(f"An error occurred in detect_services_in_ports: {e}")

    def ports_to_ranges(self, ports):
        """Converts a list of port numbers to Nmap-style port ranges."""
        if not ports:
            return ""
        ports = sorted(ports)
        ranges = []
        start = ports[0]
        end = ports[0]
        for port in ports[1:]:
            if port == end + 1:
                end = port
            else:
                if start == end:
                    ranges.append(str(start))
                else:
                    ranges.append(f"{start}-{end}")
                start = port
                end = port
        # Add the last range
        if start == end:
            ranges.append(str(start))
        else:
            ranges.append(f"{start}-{end}")
        return ",".join(ranges)

    def print_scan_results(self, scan_data):
        """Prints formatted Nmap scan results to console."""
        if not scan_data:
            return

        print(f"\nResultados para {scan_data['addresses']['ipv4']}")
        print(f"Estado: {scan_data['status']['state']}")
        print(f"Hostname: {scan_data['hostnames'][0]['name'] if scan_data['hostnames'] else 'Desconocido'}")

        # Iterate through all protocols (tcp/udp)
        for proto in scan_data.all_protocols():
            print(f"\nProtocolo: {proto.upper()}")
            ports = scan_data[proto].keys()

            # Print details for each port
            for port in ports:
                state = scan_data[proto][port]['state']
                service = scan_data[proto][port]['name']
                product = scan_data[proto][port]['product']
                version = scan_data[proto][port]['version']

                print(f"  Puerto: {port}")
                print(f"  Estado: {state}")
                print(f"  Servicio: {service}")
                if product:
                    print(f"  Producto: {product}")
                if version:
                    print(f"  Versión: {version}")
                print("-" * 40)

    def run(self):
        """Main method to run the tool."""
        initial_ports = "-p-"  # Scan all ports

        if not self.is_host_up():
            print(f"\n[!] Host {self.host_ip} is down or unreachable.")
            
        else: 
            # Handle privilege escalation for raw socket scans
            sudo_password = None
            if os.geteuid() != 0:
                print("\n[!] WARNING: TCP SYN (-sS) and UDP (-sU) scans require root privileges!")
                print("[!] Running as non-root user. Some scans may fail.\n")
                sudo_password = getpass.getpass(prompt='Enter sudo password: ')

            # Perform different types of scans
            for scan_type in self.scan_types:
                result = self.scan_open_ports_on_host(initial_ports, scan_type)
                if not result:
                    print(f"Open ports were not found in host {self.host_ip} with scan type: {scan_type}")
                    continue

                self.print_scan_results(result)

                # Collect open ports for service detection
                open_ports = []
                for proto in result.all_protocols():
                    for port in result[proto].keys():
                        if proto == "udp" and result[proto][port].get('reason') == 'no-response':
                            continue
                        else:
                            open_ports.append(port)

                if open_ports:
                    # Convert port list to Nmap format and run service detection
                    port_ranges = self.ports_to_ranges(open_ports)
                    ports_str = f"-p {port_ranges}"
                    services = self.detect_services_in_ports(ports_str, scan_type)
                    if services:
                        self.print_scan_results(services)

            print("\n[+] Finished scanning.")


if __name__ == "__main__":
    # Configure command line argument parsing
    parser = argparse.ArgumentParser(description='Advanced Recon Tool with Nmap')
    parser.add_argument('host', help='IP or domain to scan')
    args = parser.parse_args()
    host_input = args.host

    tool = NmapScanner(host_input)
    tool.run()