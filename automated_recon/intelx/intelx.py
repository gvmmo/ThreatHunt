import os
import requests
import json
from time import sleep
from datetime import datetime
from dotenv import load_dotenv

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# Obtener la API key desde las variables de entorno
INTELX_API_KEY = os.getenv('INTELX_API_KEY')

# Verificar si la API key está disponible
if not INTELX_API_KEY:
    raise ValueError("No se encontró la API key en el archivo .env")

class IntelXScanner:
    def __init__(self, target, api_key=INTELX_API_KEY, output_dir="results"):
        self.target = target
        self.api_key = api_key
        self.output_dir = output_dir
        self.baseurl = "https://free.intelx.io/"
        self.headers = {
            "x-key": self.api_key,
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/json"
        }
        self.data = {
            "term": self.target,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": 100,
            "datefrom": "",
            "dateto": "",
            "terminate": [],
            "media": 0,
            "timeout": 20
        }

    def clean_ansi(self, line):
        # Removes ANSI escape codes from a line
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_escape.sub('', line)

    def intel_search(self):
        try:
            r = requests.post(self.baseurl + "search", headers=self.headers, json=self.data)
            r.raise_for_status()
            result = r.json()
            if result.get("id"):
                return result["id"]
            return None
        except requests.exceptions.RequestException as e:
            print(f"Error durante la búsqueda: {e}")
            return None

    def intel_result(self, search_id):
        results = {
            "records": [],
            "status": None,
            "error": None
        }

        try:
            # Primero obtener el estado de la búsqueda
            status_url = f"{self.baseurl}/status/{search_id}"
            status_response = requests.get(status_url, headers=self.headers)
            status_response.raise_for_status()
            status_data = status_response.json()

            # Esperar hasta que la búsqueda esté completa
            while status_data.get("status") != 2:  # 2 típicamente significa completado
                sleep(1)
                status_response = requests.get(status_url, headers=self.headers)
                status_data = status_response.json()

            # Obtener resultados
            result_url = f"{self.baseurl}/result?id={search_id}"
            r = requests.get(result_url, headers=self.headers)
            r.raise_for_status()
            
            result_data = r.json()
            
            # Estructurar los resultados
            results = {
                "records": [],
                "status": "completed",
                "total_records": len(result_data.get("records", [])),
                "search_id": search_id,
                "timestamp": datetime.now().isoformat()
            }

            # Procesar cada registro
            for record in result_data.get("records", []):
                processed_record = {
                    "type": record.get("type"),
                    "media": record.get("media"),
                    "date": record.get("date"),
                    "system_id": record.get("systemid"),
                    "name": record.get("name"),
                    "bucket": record.get("bucket"),
                    "size": record.get("size"),
                    "stored": record.get("stored")
                }
                results["records"].append(processed_record)

            return results

        except requests.exceptions.RequestException as e:
            results["error"] = str(e)
            results["status"] = "failed"
            return results

    def save_to_json(self, data):
        """
        Guardar los resultados en un archivo JSON en el directorio especificado
        """
        # Crear directorio de resultados si no existe
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        # Crear nombre de archivo con marca de tiempo
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.target}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            print(f"Resultados guardados en: {filepath}")
            return True
        except Exception as e:
            print(f"Error al guardar resultados: {e}")
            return False

    def run(self):
        search_id = self.intel_search()
        
        if search_id:
            results = self.intel_result(search_id)
            
            # Guardar resultados en archivo JSON
            self.save_to_json(results)
            
            # También imprimir resultados en consola
            print("Resultados de la búsqueda:")
            print(json.dumps(results, indent=4))
        else:
            print("La búsqueda falló al devolver un ID")

if __name__ == "__main__":
    target = "example.com"
    scanner = IntelXScanner(target)
    scanner.run()