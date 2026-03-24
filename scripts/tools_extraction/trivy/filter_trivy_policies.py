import os
import shutil
import csv
import yaml
import json
import re

# --- CONFIGURACIÓN ---
REPO_PATH = r"C:\Users\CAOSD\projects\folder_repos_information\trivy-checks\checks\kubernetes" # Tu ruta al clone de Trivy
DEST_DIR = "../../../resources/trivy_dataset_validated02"
OUTPUT_CSV = "reporte_validacion_trivy.csv"
KINDS_CSV = "../../../resources/mapping_csv/kubernetes_kinds_versions_detected.csv" # Tu nuevo CSV maestro para Kinds

# --- CARGA DEL DICCIONARIO DE KINDS ---
def load_supported_kinds(csv_file):
    """
    Lee el CSV de versiones y recursos para generar un Set con todos
    los Kinds soportados por nuestro modelo UVL (en minúsculas para machear con Trivy).
    """
    supported_kinds = set()
    print(f"Cargando diccionario de Kinds desde: {csv_file}")
    try:
        with open(csv_file, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if "Kind" in row:
                    # Guardamos en minúsculas porque Trivy usa 'pod', 'deployment', etc.
                    supported_kinds.add(row["Kind"].strip().lower())
    except Exception as e:
        print(f"Error cargando CSV de Kinds: {e}")
        exit()
        
    print(f"Diccionario cargado: {len(supported_kinds)} Kinds soportados (ej. {list(supported_kinds)[:3]}...).")
    return supported_kinds

def extract_rego_metadata_and_code(filepath):
    """Extrae el bloque YAML respetando la indentación, y el código Rego por separado."""
    metadata_lines = []
    code_lines = []
    in_metadata = False
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            stripped = line.strip()
            if stripped == "# METADATA":
                in_metadata = True
                continue
                
            if in_metadata:
                if stripped.startswith("#"):
                    # Quitamos el '#'
                    yaml_line = stripped[1:]
                    # Quitamos SOLO el primer espacio de separación, manteniendo la indentación real
                    if yaml_line.startswith(" "):
                        yaml_line = yaml_line[1:]
                    metadata_lines.append(yaml_line)
                elif stripped == "":
                    in_metadata = False
            else:
                code_lines.append(line)
                
    meta_dict = None
    if metadata_lines:
        try:
            yaml_content = "\n".join(metadata_lines)
            meta_dict = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            print(f"Error parseando YAML en {filepath}: {e}")
            
    return meta_dict, "\n".join(code_lines)

# --- PROCESO PRINCIPAL ---
supported_kinds_set = load_supported_kinds(KINDS_CSV)

if os.path.exists(DEST_DIR): shutil.rmtree(DEST_DIR)
os.makedirs(DEST_DIR)

stats = {"total": 0, "aceptadas": 0, "descartadas": 0}
accepted_policies_data = []

print("\n--- INICIANDO FILTRADO DE TRIVY (Basado en Diccionario de Kinds) ---")

with open(OUTPUT_CSV, "w", encoding="utf-8") as f_out:
    f_out.write("Archivo;ID_Trivy;Resultado;Razon\n")

    for root, _, files in os.walk(REPO_PATH):
        for file in files:
            if not file.endswith(".rego") or file.endswith("_test.rego") or file.endswith(".json"):
                continue

            filepath = os.path.join(root, file)
            stats["total"] += 1
            rel_path = os.path.relpath(filepath, REPO_PATH)

            meta, rego_code = extract_rego_metadata_and_code(filepath)
                        
            # Si no hay metadatos o no se pudo parsear como diccionario, lo descartamos
            if not meta or not isinstance(meta, dict):
                f_out.write(f"{rel_path};Unknown;DESCARTADA;No contiene bloque # METADATA válido\n")
                stats["descartadas"] += 1
                continue

            # Extracción segura del bloque 'custom'
            custom_block = meta.get('custom', {})
            if not isinstance(custom_block, dict): 
                custom_block = {}
                
            trivy_id = custom_block.get('id', 'Unknown')
            
            # --- FASE 2: VERIFICACIÓN SEMÁNTICA (NAVEGACIÓN SEGURA) ---
            is_k8s = False
            kinds_in_policy = []
            
            # Fallback 1: Comprobar schemas globales
            if 'kubernetes' in str(meta.get('schemas', [])):
                is_k8s = True

            # Navegación profunda y segura por custom -> input -> selector
            input_block = custom_block.get('input', {})
            if isinstance(input_block, dict):
                selectors = input_block.get('selector', [])
                
                # Normalizamos 'selectors' para que siempre sea una lista
                if isinstance(selectors, dict):
                    selectors = [selectors]
                elif not isinstance(selectors, list):
                    selectors = []
                    
                # Recorremos los selectores buscando el type: kubernetes
                for sel in selectors:
                    if isinstance(sel, dict):
                        if sel.get('type') == 'kubernetes':
                            is_k8s = True
                            
                            # Extraemos los subtypes si los hay
                            subtypes = sel.get('subtypes', [])
                            if isinstance(subtypes, list):
                                for st in subtypes:
                                    if isinstance(st, dict) and 'kind' in st:
                                        kinds_in_policy.append(st['kind'].lower())

            # Filtro Dominio Kubernetes
            if not is_k8s:
                f_out.write(f"{rel_path};{trivy_id};DESCARTADA;No orientada a Kubernetes\n")
                stats["descartadas"] += 1
                continue

            # Filtro Exhaustivo de Kinds (Usando tu CSV)
            if not kinds_in_policy:
                # Caso como el KSV036: es de k8s pero no especifica Kinds. 
                # Si quieres ACEPTARLAS y asumir que aplican a todos (ej. Pod), comenta el 'continue' y pon valid_kinds = ['pod']
                f_out.write(f"{rel_path};{trivy_id};DESCARTADA;Sin Kinds definidos explícitamente en subtypes\n")
                stats["descartadas"] += 1
                continue
                
            valid_kinds = [k for k in kinds_in_policy if k in supported_kinds_set]
            
            if not valid_kinds:
                f_out.write(f"{rel_path};{trivy_id};DESCARTADA;Kinds no soportados por el CSV: {kinds_in_policy}\n")
                stats["descartadas"] += 1
                continue

            # --- NUEVA FASE 3: FILTRO DE COMPLEJIDAD REGO (BLACKLIST) ---
            # Descartamos reglas que usan lógicas imposibles de modelar en Z3 (Regex, manipulación de strings, entorno)
            forbidden_patterns = [
                # Manipulación de Strings y Regex (DLP y payloads)
                r'regex\.match',
                r'regex\.find',
                r'split\(',
                r'is_interpolation',
                
                # Dependencias del Entorno o Datos libres
                r'k8s\.version',
                r'\.data\b',          # Acceso a campos de payload libre (ConfigMaps, Secrets)
                
                # Iteraciones de Arrays Complejos (Especialmente RBAC)
                r'input\.rules\[',    # Iteración sobre reglas RBAC
                r'\[_\] ==',          # Intersección de arrays (ej: == criticalVerbs[_])
                r'== [a-zA-Z0-9_]+\[_\]',
                
                # Manipulación Dinámica de Diccionarios y Objetos
                r'object\.get\(',     # Extracción segura de diccionarios en Rego
                r'is_empty\(',        # Función custom para evaluar diccionarios vacíos
                r'==\s*\{\}'          # Comprobación literal de diccionario vacío
            ]
            
            is_complex = False
            for pattern in forbidden_patterns:
                if re.search(pattern, rego_code):
                    is_complex = True
                    matched_pattern = pattern
                    break
                    
            if is_complex:
                f_out.write(f"{rel_path};{trivy_id};DESCARTADA;Contiene lógica dinámica/compleja no mapeable a UVL ({matched_pattern})\n")
                stats["descartadas"] += 1
                continue
            # --- ÉXITO ---
            f_out.write(f"{rel_path};{trivy_id};ACEPTADA;Semántica OK. Kinds Soportados: {valid_kinds}\n")
            stats["aceptadas"] += 1
            
            policy_info = {
                "name": file.replace(".rego", ""),
                "trivy_id": trivy_id,
                "title": meta.get("title", ""),
                "description": meta.get("description", ""),
                "severity": custom_block.get("severity", "UNKNOWN"),
                "recommended_action": custom_block.get("recommended_action", ""),
                "kinds": valid_kinds,
                "filepath": filepath
            }
            accepted_policies_data.append(policy_info)
            shutil.copy2(filepath, os.path.join(DEST_DIR, file))

with open(os.path.join(DEST_DIR, "trivy_policies_info.json"), "w", encoding="utf-8") as json_out:
    json.dump(accepted_policies_data, json_out, indent=4, ensure_ascii=False)

print(f"\n--- RESUMEN FINAL TRIVY ---")
print(f"Total Analizados: {stats['total']}")
print(f"Aceptadas (Kinds existen en CSV): {stats['aceptadas']}")
print(f"Descartadas: {stats['descartadas']}")