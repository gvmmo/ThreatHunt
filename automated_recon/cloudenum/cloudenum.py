#!/usr/bin/env python3
import subprocess
import json
import datetime
import os
import time
import signal
from pathlib import Path

class CloudEnumScanner:
    def __init__(self):
        self.results_dir = "cloud_enum_results"
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.temp_output = None
        self.output_file = None
        self.process = None
        self.start_time = None
        
    def setup_output_directory(self):
        """Crear directorio de salida si no existe"""
        Path(self.results_dir).mkdir(exist_ok=True)
        
    def signal_handler(self, signum, frame):
        """Manejar SIGINT procesando resultados parciales"""
        print("\n[*] Ctrl+C received. Processing partial results...")
        
        if self.process:
            self.process.terminate()
            self.process.wait()
            
        if self.temp_output and os.path.exists(self.temp_output):
            end_time = time.time()
            try:
                # Procesar cualquier resultado que tengamos
                results = self._process_results(
                    self.temp_output,
                    os.getenv('CLOUD_ENUM_KEYWORDS', 'default'),
                    self.start_time,
                    end_time
                )
                
                # Guardar resultados parciales
                partial_output = self.output_file.replace('.json', '_partial.json')
                with open(partial_output, 'w') as f:
                    json.dump(results, f, indent=4)
                print(f"[+] Partial results saved to: {partial_output}")
                
            except Exception as e:
                print(f"[-] Error saving partial results: {str(e)}")
                
            finally:
                # Limpieza
                try:
                    os.remove(self.temp_output)
                except:
                    pass
                    
        print("[*] Exiting...")
        exit(0)

    def run_cloud_enum(self, keywords, output_file=None):
        """
        Ejecutar cloud-enum con palabras clave especificadas y capturar la salida
        """
        if not output_file:
            output_file = f"{self.results_dir}/cloud_enum_{self.timestamp}.json"
            
        self.output_file = output_file
        
        try:
            self.start_time = time.time()
            
            # Configurar archivo temporal para la salida sin procesar de cloud-enum
            self.temp_output = f"{self.results_dir}/raw_output_{self.timestamp}.json"
            
            # Configurar el manejador de señales para SIGINT
            signal.signal(signal.SIGINT, self.signal_handler)
            
            # Preparar comando cloud-enum con salida JSON
            cmd = ["cloud_enum", "-k", keywords, "-l", self.temp_output, "-f", "json"]
            
            # Ejecutar cloud-enum
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            self.process.communicate()  # Esperar a que termine
            
            end_time = time.time()
            
            # Procesar los resultados
            results = self._process_results(self.temp_output, keywords, self.start_time, end_time)
            
            # Guardar resultados procesados
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
                
            # Limpiar archivo temporal
            os.remove(self.temp_output)
                
            return True, output_file
            
        except Exception as e:
            if self.temp_output and os.path.exists(self.temp_output):
                try:
                    os.remove(self.temp_output)
                except:
                    pass
            return False, str(e)

    def get_metadata(self, keywords, start_time, end_time):
        """
        Recolectar metadatos esenciales sobre el escaneo
        """
        return {
            "keywords": keywords.split(','),
            "timestamp_start": start_time,
            "timestamp_end": end_time,
            "duration_seconds": f"{end_time - start_time:.2f}",
            "status": "partial" if end_time < time.time() else "complete"
        }

    def _process_results(self, input_file, keywords, start_time, end_time):
        """
        Procesar la salida JSON sin procesar de cloud-enum
        """
        findings = {
            "aws": {
                "s3_buckets": {"public": [], "protected": []},
                "other": []
            },
            "azure": {
                "storage_accounts": {"public": [], "protected": []},
                "containers": {"public": [], "protected": []},
                "other": []
            },
            "gcp": {
                "storage_buckets": {"public": [], "protected": []},
                "other": []
            }
        }
            
        try:
            with open(input_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("####"):  # Saltar líneas de encabezado
                        try:
                            finding = json.loads(line)
                            platform = finding.get("platform")
                            msg = finding.get("msg", "").lower()
                            target = finding.get("target")
                            access = finding.get("access")
                            
                            if platform == "aws":
                                if "s3" in msg:
                                    bucket_type = "public" if access == "public" else "protected"
                                    findings["aws"]["s3_buckets"][bucket_type].append({
                                        "target": target,
                                        "message": msg
                                    })
                                else:
                                    findings["aws"]["other"].append(finding)
                                    
                            elif platform == "azure":
                                if "storage account" in msg:
                                    access_type = "public" if access == "public" else "protected"
                                    findings["azure"]["storage_accounts"][access_type].append({
                                        "target": target,
                                        "message": msg
                                    })
                                elif "container" in msg:
                                    access_type = "public" if access == "public" else "protected"
                                    findings["azure"]["containers"][access_type].append({
                                        "target": target,
                                        "message": msg
                                    })
                                else:
                                    findings["azure"]["other"].append(finding)
                                    
                            elif platform == "gcp":
                                if "bucket" in msg:
                                    bucket_type = "public" if access == "public" else "protected"
                                    findings["gcp"]["storage_buckets"][bucket_type].append({
                                        "target": target,
                                        "message": msg
                                    })
                                else:
                                    findings["gcp"]["other"].append(finding)
                                    
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            return {"error": "No results file found"}
            
        # Generar estadísticas
        statistics = self._generate_statistics(findings)
        
        # Obtener metadatos
        metadata = self.get_metadata(keywords, start_time, end_time)
        
        # Crear resultados finales con estructura reordenada
        return {
            "metadata": metadata,
            "statistics": statistics,  # Movido antes de findings
            "findings": findings
        }

    def _generate_statistics(self, findings):
        """
        Generar estadísticas sobre los hallazgos
        """
        stats = {
            "total_findings": 0,
            "findings_by_provider": {
                "aws": {
                    "total": 0,
                    "s3_buckets": {"total": 0, "public": 0, "protected": 0},
                    "other": 0
                },
                "azure": {
                    "total": 0,
                    "storage_accounts": {"total": 0, "public": 0, "protected": 0},
                    "containers": {"total": 0, "public": 0, "protected": 0},
                    "other": 0
                },
                "gcp": {
                    "total": 0,
                    "storage_buckets": {"total": 0, "public": 0, "protected": 0},
                    "other": 0
                }
            }
        }

        # Definir la estructura de lo que se va a contar
        count_map = {
            "aws": {"s3_buckets": ["public", "protected"]},
            "azure": {
                "storage_accounts": ["public", "protected"],
                "containers": ["public", "protected"]
            },
            "gcp": {"storage_buckets": ["public", "protected"]}
        }

        # Calcular estadísticas para cada proveedor
        for provider, resources in count_map.items():
            provider_stats = stats["findings_by_provider"][provider]
            
            # Contar tipos de recursos (buckets, contenedores, etc)
            for resource_type, access_types in resources.items():
                resource_stats = provider_stats[resource_type]
                
                # Contar recursos públicos y protegidos
                for access in access_types:
                    count = len(findings[provider][resource_type][access])
                    resource_stats[access] = count
                    resource_stats["total"] += count
                
                provider_stats["total"] += resource_stats["total"]
            
            # Contar otros hallazgos
            other_count = len(findings[provider]["other"])
            provider_stats["other"] = other_count
            provider_stats["total"] += other_count
            
            # Agregar al total de hallazgos
            stats["total_findings"] += provider_stats["total"]

        return stats


def main():
    try:
        scanner = CloudEnumScanner()
        scanner.setup_output_directory()
        
        # Obtener palabras clave de variable de entorno o usar valor predeterminado
        keywords = os.getenv('CLOUD_ENUM_KEYWORDS', 'example,test')
        
        success, result = scanner.run_cloud_enum(keywords)
        
        if success:
            print(f"[+] Scan completed successfully. Results saved to: {result}")
        else:
            print(f"[-] Scan failed: {result}")
            
    except KeyboardInterrupt:
        # Esto no debería alcanzarse ya que el manejador de señales debería capturarlo,
        # pero por si acaso...
        print("\n[-] Scan interrupted by user")
        exit(1)

if __name__ == "__main__":
    main()