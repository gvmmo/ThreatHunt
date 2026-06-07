import requests
import argparse
import time
import random
import sys
import os
import json
from dotenv import load_dotenv

class GoogleDorker:
    def __init__(self, target: str, api_key: str, cx_id: str):
        self.target = target
        self.api_key = api_key
        self.cx_id = cx_id
        if not self.api_key or not self.cx_id:
            raise ValueError("GOOGLE_API_KEY and GOOGLE_CX_ID are required")
        self.delay = 1
        self.output_file = f'/output/{self.target}_google_dorking_results.txt'
        self.results = []
        self.api_url = "https://www.googleapis.com/customsearch/v1"
        self.dorks_file = './automated_recon/google_dorks/prueba_dorks.txt'
        
    def load_api_key(self):
        try:
            # Load the .env file
            load_dotenv()
            # Get the API key from the environment variables
            return os.getenv("GOOGLE_API_KEY")
        except Exception as e:
            print(f"Error reading the .env file: {e}")
            sys.exit(1)
            
    def load_cx_id(self):
        try:
            # Load the .env file
            load_dotenv()
            # Get the API key from the environment variables
            return os.getenv("GOOGLE_CX_ID")
        except Exception as e:
            print(f"Error reading the .env file: {e}")
            sys.exit(1)
        
    def search(self, dork, start_index=1):
        """Realiza una búsqueda con un dork específico usando la API de Google"""
        query = dork
        params = {
            'key': self.api_key,
            'cx': self.cx_id,
            'q': query,
            'start': start_index,
            'num': 10  # Número máximo permitido por solicitud
        }
        
        try:
            print(f"[*] Buscando: {dork} (Índice: {start_index})")
            response = requests.get(self.api_url, params=params)
            data = response.json() 
            return self._parse_results(data, dork)
        
        except Exception as e:
            print(f"[!] Error durante la búsqueda: {e}")
            return []
        
    def run_dorks(self):
        """Ejecuta una lista de dorks contra el objetivo"""
        with open(self.dorks_file, 'r') as f:
            dorks = [line.strip() for line in f if line.strip()]
        
        for dork in dorks:
            start_index = 1
            max_results = 3  # Límite para evitar costos excesivos de API
            
            all_dork_results = []
            total_found = 0
            
            if not dork or dork.startswith("#"):
                continue
            
            actual_dork = dork.replace('TARGET_DOMAIN', self.target)
            
            # Realizar búsquedas paginadas (la API limita a 10 resultados por solicitud)
            while start_index <= max_results:
                result_data = self.search(actual_dork, start_index)
                
                if not result_data or not result_data['items']:
                    break
                    
                all_dork_results.extend(result_data['items'])
                total_found = result_data['total_results']
                
                # Verificar si hemos recuperado todos los resultados
                if len(all_dork_results) >= total_found or len(result_data['items']) < 10:
                    break
                    
                start_index += 10  # Avanzar a la siguiente página
                
                # Pausa para respetar límites de la API
                time.sleep(self.delay + random.uniform(0, 0.5))
            
            if all_dork_results:
                self.results.extend(all_dork_results)
                print(f"[+] Encontrados {len(all_dork_results)} resultados para: {actual_dork}")
            else:
                print(f"[-] No se encontraron resultados para: {actual_dork} \n")
            
            # Pausa entre diferentes dorks
            time.sleep(self.delay)
        
        return self.results
    
    def _parse_results(self, data, dork):
        """Analiza los resultados de la API de Google Custom Search"""
        results = []
        
        # Verificar si hay resultados
        if 'items' not in data:
            return results
            
        for item in data['items']:
            results.append({
                'dork': dork,
                'url': item['link'],
                'title': item.get('title', 'Sin título'),
                'snippet': item.get('snippet', 'Sin descripción')
            })
        
        # También devolvemos información sobre resultados totales para paginación
        total_results = int(data['searchInformation'].get('totalResults', '0'))
        return {
            'items': results,
            'total_results': total_results
        }
    
    def save_results(self):
        """Guarda los resultados en un archivo si se especificó"""
        if not self.output_file:
            return False
        
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(f"Resultados de Google Dorking para: {self.target}\n")
                f.write("="*70 + "\n\n")
                
                for result in self.results:
                    f.write(f"Dork: {result['dork']}\n")
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Título: {result['title']}\n")
                    f.write(f"Descripción: {result['snippet']}\n")
                    f.write("-"*70 + "\n")
            
            print(f"[+] Resultados guardados en: {self.output_file}")
            return True
        except Exception as e:
            print(f"[!] Error al guardar los resultados: {e}")
            return False
    
    def save_json_results(self):
        """Guarda los resultados en formato JSON"""
        try:
            json_output = f"./output/{self.target}_google_dorking_results.json"
            with open(json_output, 'w', encoding='utf-8') as f:
                json_data = {
                    "target": self.target,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "results": {}
                }
                
                # Organizar resultados por dork
                for result in self.results:
                    dork = result['dork']
                    if dork not in json_data['results']:
                        json_data['results'][dork] = []
                        
                    json_data['results'][dork].append({
                        'url': result['url'],
                        'title': result['title'],
                        'snippet': result['snippet']
                    })
                
                json.dump(json_data, f, indent=4)
                
            print(f"[+] Resultados JSON guardados en: {json_output}")
            return True
        except Exception as e:
            print(f"[!] Error al guardar los resultados JSON: {e}")
            return False
    
    def print_results(self):
        """Imprime los resultados en la consola"""
        if not self.results:
            print("[-] No se encontraron resultados.")
            return
        
        print("\n" + "="*70)
        print(f"Resultados para {self.target}:")
        print("="*70)
        
        current_dork = ""
        for result in self.results:
            if current_dork != result['dork']:
                current_dork = result['dork']
                print(f"\n[Dork: {current_dork}]")
            print(f"  → {result['url']}")
            print(f"    Título: {result['title']}")
            print(f"    Descripción: {result['snippet'][:100]}...")

def main():
    parser = argparse.ArgumentParser(description="Herramienta de Google Dorking con API")
    parser.add_argument('target', help='Dominio objetivo (ejemplo: example.com)')
    
    args = parser.parse_args()
    
    dorker = GoogleDorker(args.target, args.api_key, args.cx_id)
    
    print(f"[*] Iniciando Google Dorking para {args.target}")
    
    # Ejecutar los dorks
    dorker.run_dorks()
    
    # Mostrar y guardar resultados
    dorker.print_results()
    #dorker.save_results()
    dorker.save_json_results()

if __name__ == "__main__":
    print("Herramienta de Google Dorking con API de Google Custom Search")
    print("Uso ético y legal solamente. El autor no se hace responsable del mal uso.\n")
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Programa interrumpido por el usuario.")
        sys.exit(0)