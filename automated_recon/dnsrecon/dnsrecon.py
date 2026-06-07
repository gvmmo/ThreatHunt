import subprocess
import json
import os
from datetime import datetime
from typing import List, Dict, Any

class DNSReconWrapper:
    def __init__(self, output_dir: str = "results"):
        """Inicializar el wrapper DNSRecon con el directorio de salida"""
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def run_dnsrecon(self, domain: str) -> str:
        """
        Ejecutar DNSRecon con enumeración estándar e intentos de transferencia de zona
        Devuelve la ruta al archivo JSON de salida
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"dnsrecon_{domain}_{timestamp}.json")
        
        try:
            # Ejecutar dnsrecon con enumeración estándar (-t std), transferencia de zona (-a),
            # y salida JSON (-j)
            cmd = [
                "dnsrecon",
                "-d", domain,
                "-t", "std",
                "-a",
                "-j", output_file
            ]
            
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            return output_file
        
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar dnsrecon: {e}")
            print(f"Salida de error: {e.stderr}")
            raise

    def parse_findings(self, json_file: str) -> Dict[str, Any]:
        """Analizar la salida JSON de DNSRecon en un formato estructurado preservando campos específicos por tipo"""
        try:
            with open(json_file, 'r') as f:
                raw_data = json.load(f)

            structured_findings = {
                "scan_info": {
                    "timestamp": datetime.now().isoformat(),
                    "domain": "",
                    "nameservers": []
                },
                "records": {
                    "a": [],
                    "aaaa": [],
                    "mx": [],
                    "ns": [],
                    "soa": [],
                    "txt": [],
                    "srv": [],
                    "spf": [],
                    "zone_transfer": []
                },
                "statistics": {
                    "total_records": 0,
                    "record_types": {}
                }
            }

            # Procesar cada registro
            for record in raw_data:
                # Extraer dominio del primer registro SOA
                if record.get("type") == "SOA" and not structured_findings["scan_info"]["domain"]:
                    structured_findings["scan_info"]["domain"] = record.get("domain", "")

                # Categorizar registros por tipo y preservar todos los campos
                record_type = record.get("type", "").lower()
                if record_type in structured_findings["records"]:
                    # Crear un registro limpio con todos los campos disponibles
                    cleaned_record = {}
                    
                    # Campos comunes para todos los tipos de registro
                    common_fields = ["name", "domain", "type"]
                    for field in common_fields:
                        if field in record:
                            cleaned_record[field] = record[field]

                    # Campos específicos por tipo
                    if record_type == "a":
                        for field in ["address", "domain", "name", "zone_server"]:
                            if field in record:
                                cleaned_record[field] = record[field]

                    elif record_type == "aaaa":
                        if "address" in record:
                            cleaned_record["address"] = record["address"]

                    elif record_type == "ns":
                        for field in ["address", "target", "zone_server"]:
                            if field in record:
                                cleaned_record[field] = record[field]

                    elif record_type == "mx":
                        for field in ["address", "target", "priority", "zone_server"]:
                            if field in record:
                                cleaned_record[field] = record[field]

                    elif record_type == "soa":
                        for field in ["mname", "address", "serial", "refresh", 
                                    "retry", "expire", "minimum", "zone_server"]:
                            if field in record:
                                cleaned_record[field] = record[field]

                    elif record_type == "txt":
                        for field in ["domain", "name", "strings", "zone_server"]:
                            if field in record:
                                cleaned_record[field] = record[field]

                    elif record_type == "srv":
                        for field in ["address", "domain", "name", "port", "target", "zone_server"]:
                            if field in record:
                                cleaned_record[field] = record[field]

                    elif record_type == "spf":
                        if "strings" in record:
                            cleaned_record["strings"] = record["strings"]

                    elif record_type == "cname":
                        for field in ["address", "name", "target", "zone_server"]:
                            if field in record:
                                cleaned_record[field] = record[field]

                    # Agregar campos adicionales que no fueron manejados explícitamente
                    for key, value in record.items():
                        if key not in cleaned_record and key not in ["type"]:
                            cleaned_record[key] = value

                    structured_findings["records"][record_type].append(cleaned_record)

                    # Registrar estadísticas
                    structured_findings["statistics"]["total_records"] += 1
                    structured_findings["statistics"]["record_types"][record_type] = \
                        structured_findings["statistics"]["record_types"].get(record_type, 0) + 1

            return structured_findings

        except json.JSONDecodeError as e:
            print(f"Error al analizar archivo JSON: {e}")
            raise
        except Exception as e:
            print(f"Error inesperado procesando hallazgos: {e}")
            raise

    def process_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """Procesar múltiples dominios y devolver hallazgos estructurados"""
        all_findings = []
        
        for domain in domains:
            try:
                print(f"Procesando dominio: {domain}")
                json_file = self.run_dnsrecon(domain)
                findings = self.parse_findings(json_file)
                all_findings.append(findings)
                
            except Exception as e:
                print(f"Error procesando dominio {domain}: {e}")
                continue
                
        return all_findings

def save_structured_findings(findings: List[Dict[str, Any]], output_file: str):
    """Guardar hallazgos estructurados en archivo JSON"""
    try:
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=4)
        print(f"Hallazgos estructurados guardados en: {output_file}")
    except Exception as e:
        print(f"Error al guardar hallazgos: {e}")

def main():
    # Ejemplo de uso
    domains = ["vulnweb.com", "zonetransfer.me"]  # Reemplazar con dominios objetivo
    output_dir = "dnsrecon_results"
    
    recon = DNSReconWrapper(output_dir)
    findings = recon.process_domains(domains)
    
    # Guardar hallazgos estructurados
    output_file = os.path.join(output_dir, "structured_findings.json")
    save_structured_findings(findings, output_file)

if __name__ == "__main__":
    main()
