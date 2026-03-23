import os
import csv
import time
from pathlib import Path

from flamapy.metamodels.fm_metamodel.transformations import UVLReader, FlatFM
from flamapy.metamodels.z3_metamodel.transformations import FmToZ3
from flamapy.metamodels.configuration_metamodel.models import Configuration

from scripts.configurationJSON import ConfigurationJSON
from scripts.valid_config import evaluate_config_security
from scripts._inference_policy import extract_policy_kinds_from_constraints, infer_policies_from_kind
from scripts.remediator_registry import RemediationRegistry  # Asegúrate de que el nombre del archivo es correcto


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent  # Asume que el script está en /scripts/ y ROOT es la carpeta del proyecto
FM_PATH = ROOT / "variability_model" / "model_policies02.uvl"
VALID_JSONS_DIR = ROOT.parent / "valid_jsons"
OUTPUT_CSV = ROOT / "evaluation" / "remediation_benchmark_results.csv"


def filter_context_aware_actions(original_config_elements: dict, actions_list: list, strip_suffixes: bool = False) -> list:
  """
  Filtro semántico (Configuration-Space Pruning).
  Asegura el Cambio Mínimo evitando inyectar ramas de jerarquía inexistentes.
  """
  if not original_config_elements:
      return []
      
  workload_root = ""
  for key in original_config_elements.keys():
      if "_spec" in key:
          workload_root = key.split("_spec")[0]
          break
      elif "_metadata" in key:
          workload_root = key.split("_metadata")[0]
          break
          
  existing_keys_str = " ".join(original_config_elements.keys())
  valid_actions = []
  
  for action in actions_list:
      feat = action["feature_to_fix"]
      safe_val = action["safe_value"]
      
      # Filtro de Kind (Workload)
      if workload_root and "io_k8s_api" in feat and not feat.startswith(workload_root):
          continue
          
      # Filtro de recursos fantasma
      if "initContainers" in feat and "initContainers" not in existing_keys_str:
          continue
      if "ephemeralContainers" in feat and "ephemeralContainers" not in existing_keys_str:
          continue
          
      # Limpieza de sufijos (Solo si va para AST. Para Z3 en este script será False)
      if strip_suffixes:
          feat = feat.replace("_valueInt", "") \
                      .replace("_StringValue", "") \
                      .replace("_IntegerValue", "") \
                      .replace("_Always", "")
                      
      valid_actions.append({"feature_to_fix": feat, "safe_value": safe_val})
      
  return valid_actions

def calculate_hamming_distance(original_elements: dict, remediated_elements: dict) -> int:
  """
  Calcula la Distancia de Hamming (Δ) sobre el conjunto de features del modelo.
  """
  distance = 0
  all_keys = set(original_elements.keys()).union(set(remediated_elements.keys()))
  for k in all_keys:
      if original_elements.get(k) != remediated_elements.get(k):
          distance += 1
  return distance


def run_remediation_benchmark():
    print("[INFO] Iniciando inicialización de métricas y modelos...")
    
    # 1. Cargar modelos base (solo se hace una vez)
    start_startup = time.time()
    fm_model = UVLReader(str(FM_PATH)).transform()
    flat_fm_op = FlatFM(fm_model)
    flat_fm_op.set_maintain_namespaces(False)
    flat_fm = flat_fm_op.transform()
    z3_model = FmToZ3(flat_fm).transform()
    constraint_kinds_map = extract_policy_kinds_from_constraints(str(FM_PATH))
    
    remediation_registry = RemediationRegistry(str(FM_PATH))
    print(f"[INFO] Modelos cargados en {round(time.time() - start_startup, 2)}s.")
    
    # 2. Preparar archivo de salida
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    
    with open(OUTPUT_CSV, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Filename", 
            "Num_Features", 
            "Original_Score", 
            "New_Score", 
            "Score_Improvement",
            "Hamming_Distance", 
            "T_Initial_Val_ms", 
            "T_Remediation_Val_ms", 
            "Is_Fully_Remediated"
        ])
        
        json_files = [file for file in os.listdir(VALID_JSONS_DIR) if file.endswith('.json')]
        print(f"[INFO] Comenzando Benchmarking de Auto-Remediación sobre {len(json_files)} manifiestos...")

        for filename in json_files:
            file_path = os.path.join(VALID_JSONS_DIR, filename)
            try:
                # --- A. LECTURA ---
                config_reader = ConfigurationJSON(file_path)
                configurations = config_reader.transform()
                if not configurations: 
                    continue
                
                base_config = configurations[0]
                auto_policies = infer_policies_from_kind(base_config.elements, constraint_kinds_map)
                if not auto_policies: 
                    continue

                # --- B. VALIDACIÓN INICIAL ---
                t0_init = time.perf_counter()
                secure_init, sec_score_init, _, report_init, _ = evaluate_config_security(
                    base_config, flat_fm, z3_model, constraint_kinds_map, auto_policies
                )
                t1_init = time.perf_counter()
                t_initial_ms = round((t1_init - t0_init) * 1000, 2)

                # Si es seguro desde el principio, guardamos y pasamos al siguiente
                if secure_init:
                    writer.writerow([
                        filename, len(base_config.elements), 
                        round(sec_score_init, 4), round(sec_score_init, 4), 0.0, 
                        0, t_initial_ms, 0.0, True
                    ])
                    continue

                # --- C. MOTOR DE REMEDIACIÓN (Z3 Space) ---
                remediated_elements = dict(base_config.elements)
                
                for issue in report_init:
                    policy_name = issue["policy"]
                    raw_actions = remediation_registry.get_remediation_actions(policy_name)
                    
                    # Filtramos usando el contexto real del JSON actual.
                    # strip_suffixes=False porque estamos en el espacio lógico de Z3, no en el AST de YAML.
                    smart_actions = filter_context_aware_actions(base_config.elements, raw_actions, strip_suffixes=False)
                    
                    for action in smart_actions:
                        remediated_elements[action["feature_to_fix"]] = action["safe_value"]
                
                remediated_config = Configuration(remediated_elements)

                # --- D. CÁLCULO DE DISTANCIA DE HAMMING ---
                hamming_dist = calculate_hamming_distance(base_config.elements, remediated_elements)

                # --- E. VALIDACIÓN POST-REMEDIACIÓN ---
                t0_rem = time.perf_counter()
                secure_new, sec_score_new, _, _, _ = evaluate_config_security(
                    remediated_config, flat_fm, z3_model, constraint_kinds_map, auto_policies
                )
                t1_rem = time.perf_counter()
                t_remediation_ms = round((t1_rem - t0_rem) * 1000, 2)

                score_improvement = round(sec_score_new - sec_score_init, 4)

                # --- F. ESCRITURA DE RESULTADOS ---
                writer.writerow([
                    filename, 
                    len(base_config.elements), 
                    round(sec_score_init, 4), 
                    round(sec_score_new, 4), 
                    score_improvement,
                    hamming_dist,
                    t_initial_ms, 
                    t_remediation_ms, 
                    secure_new
                ])

            except Exception as e:
                print(f"[ERROR] Fallo procesando {filename}: {e}")

    print(f"\n[OK] Benchmarking finalizado con éxito.")
    print(f"[OK] Los resultados están listos en: {OUTPUT_CSV}")

if __name__ == '__main__':
    run_remediation_benchmark()