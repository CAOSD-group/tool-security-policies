import os
import csv
import time
import subprocess
import difflib
import yaml
import sys
from pathlib import Path
import traceback
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# para que pueda encontrar el módulo 'back_kube_tool'
sys.path.append(str(ROOT))

# --- Importaciones exactas de tu API (Arquitectura Dual-Oracle) ---
from back_kube_tool.core.model_loader import ModelLoader
from back_kube_tool.core.manifest_parser import ManifestParser
from back_kube_tool.core.csv_mapper import CSVMapper
from back_kube_tool.core.mapping_engine import MappingEngine
from back_kube_tool.core.policy_inference import PolicyInference
from back_kube_tool.core.validator import Validator
from back_kube_tool.core.regex_validator import ContentPolicyValidator
from back_kube_tool.core.remediator_registry import RemediationRegistry
from back_kube_tool.core.reverse_mapper import ReverseMapper
from back_kube_tool.core.remediator import Remediator
from back_kube_tool.core.utils.context_filter import filter_context_aware_actions

VALID_YAMLS_DIR = ROOT / "resources" / "dataset_yamls" / "original_yamls02"
OUTPUT_CSV = ROOT / "resources" / "evaluation" / "remediation_benchmark_results05_z3.csv"
TMP_REMEDIATED_DIR = ROOT / "resources" / "evaluation" / "tmp_remediated05_z3"

# (Asegúrate de que estas rutas coinciden con tu entorno)
UVL_PATH = os.getenv("UVL_MODEL_PATH", str(ROOT / "back_kube_tool" / "models" / "HKFM.uvl"))
CSV_FEATURES = str(ROOT / "resources" / "mapping_csv" / "kubernetes_mapping_properties_features.csv")
CSV_KINDS = str(ROOT / "resources" / "mapping_csv" / "kubernetes_kinds_versions_detected.csv")

# ==========================================
# UTILIDADES DE MÉTRICAS (Igual que antes)
# ==========================================
def run_kubeconform(yaml_path: str) -> bool:
    try:
        result = subprocess.run(["kubeconform", "-strict", "-summary", yaml_path], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except FileNotFoundError:
        return True

def calculate_semantic_preservation(orig_path: str, rem_path: str):
    with open(orig_path, 'r') as f: orig_lines = f.readlines()
    with open(rem_path, 'r') as f: rem_lines = f.readlines()
    
    orig_comments = sum(1 for line in orig_lines if line.strip().startswith('#'))
    rem_comments = sum(1 for line in rem_lines if line.strip().startswith('#'))
    comment_retention = (rem_comments / orig_comments * 100) if orig_comments > 0 else 100.0

    diff = list(difflib.ndiff(orig_lines, rem_lines))
    lines_added = sum(1 for d in diff if d.startswith('+ '))
    lines_removed = sum(1 for d in diff if d.startswith('- '))
    
    return round(comment_retention, 2), lines_added, lines_removed

# ==========================================
# MOTOR PRINCIPAL DE BENCHMARKING
# ==========================================

def run_remediation_benchmark():
    print("[INFO] Inicializando Arquitectura Dual-Oracle (Clon de API)...")
    os.makedirs(TMP_REMEDIATED_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    
    # 1. CARGA EN MEMORIA O(1) (Equivalente al lifespan de FastAPI)
    loader = ModelLoader(UVL_PATH)
    regex_validator = ContentPolicyValidator()
    regex_policy_names = set(regex_validator.policy_map.keys())
    
    inference_engine = PolicyInference(loader.flat_fm, regex_policy_names)
    validator = Validator(loader.flat_fm, loader.z3_model)
    csv_mapper = CSVMapper(CSV_FEATURES, CSV_KINDS)
    reverse_mapper = ReverseMapper(CSV_KINDS)
    remediation_registry = RemediationRegistry(UVL_PATH)
    remediator = Remediator()
    
    yaml_files = [f for f in os.listdir(VALID_YAMLS_DIR) if f.endswith(('.yaml', '.yml'))]
    print(f"[INFO] Comenzando Benchmarking sobre {len(yaml_files)} manifiestos YAML...")

    with open(OUTPUT_CSV, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Filename", "Kind", "Orig_Z3_Alerts", "Orig_Regex_Alerts", 
            "Rem_Alerts", "T_Detection_ms", "T_AST_Remed_ms", 
            "Is_Fully_Secure", "AST_Lines_Added", ## "Is_K8s_Valid",
            "AST_Lines_Removed", "Comments_Retention_%"
        ])
        
        for filename in yaml_files:
            yaml_path = os.path.join(VALID_YAMLS_DIR, filename)
            tmp_remediated_path = os.path.join(TMP_REMEDIATED_DIR, f"rem_{filename}")
            
            try:
                with open(yaml_path, 'r') as file_in:
                    yaml_content_str = file_in.read()
                
                documents = ManifestParser.parse(yaml_content_str)
                if not documents: continue
                
                doc = documents[0] # Para la evaluación masiva nos centramos en el primer manifiesto del archivo
                kind = doc.get('kind', 'Unknown')
                
                # --- A. DETECCIÓN BASE (Espejo de api.py) ---
                t0_init = time.perf_counter()
                
                try:
                    mapped_json_dict = csv_mapper.transform_manifest(doc)
                except ValueError as ve:
                    print(f"[{filename}] Omitido (No soportado): {ve}")
                    writer.writerow([
                        filename, kind, 
                        "ERROR_MAP", "ERROR_MAP", "ERROR_MAP", # Alertas marcadas como error
                        0.0, 0.0, False, 0, 0, 0.0         # Tiempos a 0 y False en seguridad
                    ])
                    continue

                active_policies = inference_engine.get_policies_for_kind(kind)
                if not active_policies: continue
                
                configurations = MappingEngine.manifest_to_configurations(mapped_json_dict)
                if not configurations: continue
                target_config = configurations[0]
                print(f"[{filename}] Evaluando {len(active_policies)} políticas activas sobre {kind}...") # Log de progreso
                print(f"Config ejemplo: {target_config.elements}") # Log de ejemplo de configuración
                # A.1 Z3 Validation
                z3_policies = [p for p in active_policies if p not in regex_policy_names]
                z3_violations = validator.validate_configuration(target_config, z3_policies)
                
                # A.2 Regex Validation
                active_regex_policies = list(set(active_policies) & regex_policy_names)
                passed_regex, regex_report = regex_validator.validate_with_report(doc, target_config.elements, active_regex_policies)
                
                t_detection_ms = round((time.perf_counter() - t0_init) * 1000, 2)
                
                all_initial_violations = z3_violations + (regex_report if not passed_regex else [])
                initial_alerts_z3 = len(z3_violations)
                initial_alerts_regex = len(regex_report) if not passed_regex else 0

                if len(all_initial_violations) == 0:
                    writer.writerow([filename, kind, 0, 0, 0, t_detection_ms, 0.0, True, True, 0, 0, 100.0])
                    continue

                # --- B. MOTOR DE REMEDIACIÓN ---
                t0_rem = time.perf_counter()
                
                raw_actions = []
                for issue in all_initial_violations:
                    # Extraer del registro estático (que ahora está en el lifespan)
                    raw_actions.extend(remediation_registry.get_remediation_actions(issue["policy"]))
                
                # Filtro Semántico (Resuelve conflictos)
                smart_actions = filter_context_aware_actions(target_config.elements, raw_actions, strip_suffixes=True)
                
                # *CRÍTICO*: MAPEADO INVERSO (Lo que hace tu endpoint /remediate)
                all_patches = []
                for action in smart_actions:
                    yaml_path_list = reverse_mapper.get_yaml_path(action["feature_to_fix"], doc.get('apiVersion'), kind)
                    all_patches.append({
                        "path": yaml_path_list,
                        "value": action["safe_value"]
                    })
                
                # Aplicación en AST
                remediated_content = remediator.apply_batch_remediation(yaml_content_str, all_patches)
                
                with open(tmp_remediated_path, 'w') as file_out:
                    file_out.write(remediated_content)
                
                t_ast_remediation_ms = round((time.perf_counter() - t0_rem) * 1000, 2)

                # --- C. VALIDACIONES Y MÉTRICAS POST-REMEDIACIÓN ---
                #is_k8s_valid = run_kubeconform(tmp_remediated_path)
                comment_retention, lines_added, lines_removed = calculate_semantic_preservation(yaml_path, tmp_remediated_path)

                # --- D. RE-EVALUACIÓN DE SEGURIDAD (Idempotencia) ---
                with open(tmp_remediated_path, 'r') as file_in:
                    remediated_doc = ManifestParser.parse(file_in.read())[0]
                
                rem_mapped_dict = csv_mapper.transform_manifest(remediated_doc)
                rem_config = MappingEngine.manifest_to_configurations(rem_mapped_dict)[0]
                
                z3_violations_new = validator.validate_configuration(rem_config, z3_policies)
                passed_regex_new, regex_report_new = regex_validator.validate_with_report(remediated_doc, rem_config.elements, active_regex_policies)
                
                final_alerts = len(z3_violations_new) + (len(regex_report_new) if not passed_regex_new else 0)
                is_fully_secure = (final_alerts == 0)
                print(f"{filename}: final alerts {final_alerts} \n violations in rem: {z3_violations_new}")
                # --- E. REGISTRO CSV ---
                writer.writerow([
                    filename, kind, initial_alerts_z3, initial_alerts_regex, 
                    final_alerts, t_detection_ms, t_ast_remediation_ms, 
                    is_fully_secure, lines_added, ## is_k8s_valid
                    lines_removed, comment_retention
                ])

            except Exception as e:
                print(f"[ERROR] Fallo procesando {filename}: {e}")
                traceback.print_exc() 
                print("-" * 50)
    print(f"\n[OK] Benchmarking finalizado. Resultados en: {OUTPUT_CSV}")

if __name__ == '__main__':
    run_remediation_benchmark()