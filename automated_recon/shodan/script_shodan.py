import shodan
import json
import requests
import os
from datetime import datetime
from typing import Dict, Any

class ShodanScanner:
    def __init__(self, api_key: str):
        self.api = shodan.Shodan(api_key)

    def scan_host(self, ip: str) -> Dict[str, Any]:
        """
        Escanea un único host y devuelve información detallada incluyendo puertos, servicios y vulns
        """
        results = {
            'metadata': {
                'organization': None,
                'timestamp': datetime.now().isoformat(),
                'total_results': 1
            },
            'hosts': []
        }
        
        try:
            host_info = self.api.host(ip)
            
            # Crea la estructura host_data
            host_data = {
                'ip': ip,
                'organization': host_info.get('org'),
                'hostnames': host_info.get('hostnames', []),
                'domains': host_info.get('domains', []),
                'timestamp': host_info.get('last_update'),
                'isp': host_info.get('isp'),
                'asn': host_info.get('asn'),
                'all_ports': host_info.get('ports', []),
                'os': host_info.get('os'),
                'last_update': host_info.get('last_update'),
                'tags': host_info.get('tags', []),
                'services': []
            }
            
            results['metadata']['organization'] = host_info.get('org')
            
            # Procesa la información de los servicios
            for service in host_info.get('data', []):
                service_info = {
                    'port': service.get('port'),
                    'transport': service.get('transport'),
                    'module': service.get('_shodan', {}).get('module'),
                    'data': service.get('data'),
                    'timestamp': service.get('timestamp'),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'cpe': service.get('cpe', []),
                    'vulns': {},
                    'opts': service.get('opts', {}),
                    'hash': service.get('hash'),
                    'location': service.get('location', {}),
                    'domains': service.get('domains', []),
                    'hostnames': service.get('hostnames', []),
                }
                
                # Procesa vulnerabilidades si existen para añadir descripción y score
                if 'vulns' in service:
                    for cve_id in service['vulns']:
                        vuln_info = self.get_vuln_info(cve_id)
                        if vuln_info:
                            summary, cvss_score = vuln_info
                            service_info['vulns'][cve_id] = {
                                'summary': summary,
                                'cvss_score': cvss_score
                            }
                        else:
                            service_info['vulns'][cve_id] = {
                                'summary': 'Failed to fetch vulnerability information',
                                'cvss_score': None
                            }
                
                host_data['services'].append(service_info)
            
            results['hosts'].append(host_data)
            return results

        except shodan.APIError as e:
            print(f"Error scanning host {ip}: {e}")
            return None

    
    def search_organization(self, org_name: str, limit: int = 100) -> Dict[str, Any]:
        """
        Busca una organización y recopila información detallada sobre cada resultado
        usando la función scan_host para cada host encontrado
        """
        results = {
            'metadata': {
                'organization': org_name,
                'timestamp': datetime.now().isoformat(),
                'total_results': 0
            },
            'hosts': []
        }
        
        try:
            # Construye la consulta para la organización
            query = f'org:"{org_name}"'
            search_results = self.api.search(query, limit=limit)
            
            results['metadata']['total_results'] = search_results['total']
            
            # Procesa cada resultado usando scan_host
            for item in search_results['matches']:
                ip = item.get('ip_str')
                if ip:
                    host_result = self.scan_host(ip)
                    if host_result and host_result['hosts']:
                        # Solo añadimos el host si se encontró información
                        results['hosts'].append(host_result['hosts'][0])
                    else:
                        # Si scan_host falla, creamos una entrada básica con la información disponible
                        basic_host_data = {
                            'ip': ip,
                            'organization': item.get('org'),
                            'hostnames': item.get('hostnames', []),
                            'domains': item.get('domains', []),
                            'timestamp': item.get('timestamp'),
                            'isp': item.get('isp'),
                            'asn': item.get('asn'),
                            'scan_error': 'Failed to get detailed host information'
                        }
                        results['hosts'].append(basic_host_data)
            
            return results
                
        except shodan.APIError as e:
            print(f"Error al realizar la búsqueda: {e}")
            return None

    def get_vuln_info(self, cve_id: str):
        """Obtiene información detallada de una CVE"""
        try:
            cvedb_url = "https://cvedb.shodan.io/cve/"
            result = requests.get(cvedb_url + cve_id)
            cve_info = result.json().get("summary")
            cvss_score = result.json().get("cvss_v3")
            return cve_info, cvss_score
        except Exception as e:
            print(f"Error al obtener información de la CVE {cve_id}: {e}")
            return None

    def save_to_json(self, data: Dict[str, Any], filename: str = None) -> None:
        """Guarda los resultados en un archivo JSON"""
        if filename is None:
            org_name = data['metadata']['organization'].replace(' ', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shodan_{org_name}_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            print(f"Resultados guardados en {filename}")
        except Exception as e:
            print(f"Error al guardar los resultados: {e}")

def main():
    # Obtiene la clave API desde la variable de entorno
    api_key = os.getenv('SHODAN_API_KEY')
    if not api_key:
        print("Por favor, establece la variable de entorno SHODAN_API_KEY")
        return

    scanner = ShodanScanner(api_key)
    
    # Ejemplo de organización a buscar
    org_name = input("Introduce el nombre de la organización a buscar: ")
    limit = int(input("Introduce el número máximo de resultados (por defecto 100): ") or "100")
    
    # Realiza la búsqueda y recopila información
    results = scanner.search_organization(org_name, limit)
    
    if results:
        scanner.save_to_json(results)
    else:
        print("No se encontraron resultados o ocurrió un error")

if __name__ == "__main__":
    main()