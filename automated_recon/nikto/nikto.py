import subprocess
import shutil
import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

class NiktoScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_command = ['nikto']
        self.output_file = "niktoout.json"

    def run_nikto_scan(self, nikto_params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Ejecuta Nikto y analiza los resultados del archivo de salida."""
        # Verifica si Nikto está instalado en el sistema
        if not shutil.which('nikto'):
            raise FileNotFoundError("Nikto not found in PATH")

        # Prepara el comando base de Nikto con los parámetros requeridos
        cmd = [
            'nikto',
            '-h', nikto_params['host'],
            '-p', str(nikto_params.get('port', 8000)),
            '-Format', 'json',
            '-o', self.output_file
        ]

        # Agrega parámetros opcionales si están presentes en la configuración
        if tuning := nikto_params.get('Tuning'):
            cmd.extend(['-Tuning', str(tuning)])
        if timeout := nikto_params.get('timeout'):
            cmd.extend(['-timeout', str(timeout)])

        try:
            # Ejecuta el proceso de Nikto
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=nikto_params.get('timeout', 3600)
            )
            
            # Continúa incluso si el código de retorno es 1 (vulnerabilidades encontradas)
            if process.returncode not in [0, 1]:
                print(f"Nikto exited with code {process.returncode}")
                return None
            
            # Verifica si el archivo de salida existe y lo procesa
            if os.path.exists(self.output_file):
                result = self.parse_nikto_file(self.output_file)
                # Elimina el archivo temporal de Nikto después de procesarlo
                os.remove(self.output_file)
                if result:
                    return result
                else:
                    print("Failed to parse output file")
            else:
                print("Output file was not created")
            return None
            
        except subprocess.TimeoutExpired:
            print("Scan timed out")
        except Exception as e:
            print(f"Unexpected error during scan: {str(e)}")
        finally:
            # Asegura que el archivo temporal se elimine incluso si hay errores
            if os.path.exists(self.output_file):
                os.remove(self.output_file)
        return None

    def parse_nikto_file(self, filename: str) -> Optional[Dict[str, Any]]:
        """Analiza el archivo JSON de salida de Nikto y mapea los campos correctamente."""
        try:
            # Lee y parsea el archivo JSON
            with open(filename, 'r') as f:
                raw_data = json.load(f)
            
            # Inicializa la lista de vulnerabilidades
            vulnerabilities = []
            
            # Verifica diferentes estructuras posibles del JSON
            vuln_data = raw_data.get('vulnerabilities', [])
            if not vuln_data and isinstance(raw_data, list):
                vuln_data = raw_data  # Algunas versiones devuelven una lista directa
            
            # Procesa cada vulnerabilidad encontrada
            for item in vuln_data:
                vuln = {
                    'id': item.get('id', item.get('osvdb', '')),
                    'method': item.get('method', 'GET'),
                    'uri': item.get('uri', item.get('url', '')),
                    'description': item.get('message', item.get('msg', '')),
                    'references': item.get('references', [])
                }
                vulnerabilities.append(vuln)

            # Construye el resultado final
            result = {
                'target': raw_data.get('host', raw_data.get('target_ip', '')),
                'target_ip': raw_data.get('ip', ''),
                'port': raw_data.get('port', ''),
                'banner': raw_data.get('banner', ''),
                'vulnerabilities': vulnerabilities
            }
        
            return result
        
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in output file {filename}: {str(e)}")
        except Exception as e:
            print(f"Error parsing {filename}: {str(e)}")
        return None

    def scan_multiple_hosts(self) -> List[Dict[str, Any]]:
        """Escanea múltiples hosts y maneja los archivos de salida."""
        results = []
        hosts = self.config.pop('hosts', [])

        # Procesa cada host en la lista
        for host in hosts:
            host_params = self.config.copy()
            host_parts = host.split(':')
            host_params['host'] = host_parts[0]
            if len(host_parts) > 1:
                host_params['port'] = host_parts[1]
            print(f"Scanning {host_params['host']}:{host_params.get('port', 80)}")
            result = self.run_nikto_scan(host_params)
            if result:
                results.append(result)
    
        return results

    def save_results(self, results: List[Dict[str, Any]]) -> str:
        """Guarda los resultados estructurados con metadatos."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nikto_results_{timestamp}.json"
        
        # Prepara el reporte con metadatos
        report = {
            'metadata': {
                'generated_at': timestamp,
                'total_hosts': len(results),
                'total_findings': sum(len(r.get('vulnerabilities', [])) for r in results)
            },
            'results': results
        }

        # Guarda el reporte en formato JSON
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
        return filename

    def run(self):
        try:
            print("Starting Nikto scans...")
            results = self.scan_multiple_hosts()
            
            if results:
                output_file = self.save_results(results)
                print(f"Scan complete. Results saved to {output_file}")
                print(f"Total vulnerabilities found: {sum(len(r.get('vulnerabilities', [])) for r in results)}")
            else:
                print("No results collected")
        except Exception as e:
            print(f"Critical error: {str(e)}")

if __name__ == '__main__':
    config = {
        'hosts': ['localhost:8000'],
        'timeout': 300  # 5 minutes timeout
    }

    scanner = NiktoScanner(config)
    scanner.run()