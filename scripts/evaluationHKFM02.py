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
from back_kube_tool.core.validator import Validator as Z3Validator
from back_kube_tool.core.validator02 import Validator as ASTValidator
from back_kube_tool.core.regex_validator import ContentPolicyValidator
from back_kube_tool.core.remediator_registry import RemediationRegistry
from back_kube_tool.core.reverse_mapper import ReverseMapper
from back_kube_tool.core.remediator import Remediator
from back_kube_tool.core.utils.context_filter import filter_context_aware_actions

VALID_YAMLS_DIR = ROOT / "resources" / "dataset_yamls" / "testing"
OUTPUT_CSV = ROOT / "resources" / "evaluation" / "remediation_testing_Z3_AST_02.csv"
TMP_REMEDIATED_DIR = ROOT / "resources" / "evaluation" / "tmp_remediateds_01"

# (Asegúrate de que estas rutas coinciden con tu entorno)
UVL_PATH = os.getenv("UVL_MODEL_PATH", str(ROOT / "back_kube_tool" / "models" / "HKFM.uvl"))
CSV_FEATURES = str(ROOT / "resources" / "mapping_csv" / "kubernetes_mapping_properties_features.csv")
CSV_KINDS = str(ROOT / "resources" / "mapping_csv" / "kubernetes_kinds_versions_detected.csv")

def run_kubeconform(yaml_path: str) -> tuple[bool, str]:
    """
    Ejecuta kubeconform. Devuelve una tupla: (Es_Valido, Mensaje_De_Error)
    """
    try:
        # capture_output=True hace que Python atrape el texto en result.stdout
        result = subprocess.run(
            ["kubeconform", "-strict", "-summary", yaml_path], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        
        is_valid = (result.returncode == 0)
        error_msg = ""
        
        # Si NO es válido, guardamos el texto del error
        if not is_valid:
            # Quitamos los saltos de línea para que no rompa el formato del CSV
            error_raw = result.stdout.strip() if result.stdout else result.stderr.strip()
            error_msg = error_raw.replace('\n', ' | ')
            
        return is_valid, error_msg

    except FileNotFoundError:
        print("[ERROR CRÍTICO] kubeconform not installed or not in PATH. Skipping Kubernetes structural validation.")
        return False, "Kubeconform_Not_Found_In_Path"
    except subprocess.TimeoutExpired:
        return False, "Timeout_Exceeded"

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


def run_remediation_benchmark():
    print("[INFO] Inicializando Arquitectura Dual-Oracle (Clon de API)...")
    os.makedirs(TMP_REMEDIATED_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    
    # 1. CARGA EN MEMORIA O(1) (Equivalente al lifespan de FastAPI)
    loader = ModelLoader(UVL_PATH)
    regex_validator = ContentPolicyValidator()
    regex_policy_names = set(regex_validator.policy_map.keys())
    
    inference_engine = PolicyInference(loader.flat_fm, regex_policy_names)
    z3_validator = Z3Validator(loader.flat_fm, loader.z3_model) # Validator with Z3 backend
    ast_validator = ASTValidator(loader.flat_fm, loader.z3_model) # Validator with AST-based heuristics
    
    csv_mapper = CSVMapper(CSV_FEATURES, CSV_KINDS)
    reverse_mapper = ReverseMapper(CSV_KINDS)
    remediation_registry = RemediationRegistry(UVL_PATH)
    remediator = Remediator()
    
    yaml_files = [f for f in os.listdir(VALID_YAMLS_DIR) if f.endswith(('.yaml', '.yml'))]
    print(f"[INFO] Comenzando Benchmarking sobre {len(yaml_files)} manifiestos YAML...")

    with open(OUTPUT_CSV, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Filename", "Kind", "Orig_Z3_Alerts", "Orig_AST_Alerts", "Orig_Regex_Alerts",
            "Rem_Alerts", "T_Detection_ms", "T_AST_Remed_ms",
            "Is_Fully_Secure", "Is_AST_100%_Accurate", "AST_Lines_Added", ## "Is_K8s_Valid",
            "AST_Lines_Removed", "Comments_Retention_%"
        ])
        
        for filename in yaml_files:
            yaml_path = os.path.join(VALID_YAMLS_DIR, filename)
            tmp_remediated_path = os.path.join(TMP_REMEDIATED_DIR, f"rem_{filename}")
            
            #· --- 0. Structural Check (FAIL-FAST) ---
            t0_kubeconform = time.perf_counter()
            is_valid_schema, kube_error_msg = run_kubeconform(yaml_path)
            t_kubeconform_ms = round((time.perf_counter() - t0_kubeconform) * 1000, 2)

            if not is_valid_schema:
                print(f"[{filename}] Rechazado: {kube_error_msg}.")
                # Registramos el rechazo en el CSV y saltamos al siguiente archivo
                writer.writerow([
                    filename, "Unknown",
                    "SCHEMA_ERROR", "SCHEMA_ERROR", "SCHEMA_ERROR",
                    "SCHEMA_ERROR",
                    t_kubeconform_ms, 0.0, # Anotamos el tiempo que tardó en rechazarlo
                    False, False, False,
                    0, 0, kube_error_msg
                ])
                continue
            
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
                z3_violations = z3_validator.validate_configuration(target_config, z3_policies)
                ast_violations = ast_validator.validate_configuration(target_config, z3_policies)
                ## Extract the names of failed policies
                z3_failed_set = {v["policy"] for v in z3_violations}
                ast_failed_set = {v["policy"] for v in ast_violations}

                is_differential_match = (z3_failed_set == ast_failed_set)


                if not is_differential_match:
                    print(f"\n[🚨 DISCREPANCY IN {filename}]")
                    false_positives = ast_failed_set - z3_failed_set
                    false_negatives = z3_failed_set - ast_failed_set
                    if false_positives: print(f"  -> AST reported extra (False Positives): {false_positives}")
                    if false_negatives: print(f"  -> AST ignored (False Negatives): {false_negatives}")
                
                # A.2 Regex Validation
                active_regex_policies = list(set(active_policies) & regex_policy_names)
                passed_regex, regex_report = regex_validator.validate_with_report(doc, target_config.elements, active_regex_policies)
                
                t_detection_ms = round((time.perf_counter() - t0_init) * 1000, 2)
                
                all_initial_violations = ast_violations + (regex_report if not passed_regex else [])
                initial_alerts_ast = len(ast_violations)
                initial_alerts_z3 = len(z3_violations)
                initial_alerts_regex = len(regex_report) if not passed_regex else 0

                if len(all_initial_violations) == 0:
                    writer.writerow([filename, kind, initial_alerts_z3, initial_alerts_ast, initial_alerts_regex, t_detection_ms, 0.0, True, True, 0, 0, 100.0])
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
                is_remediated_k8s_valid, error_string_empty = run_kubeconform(tmp_remediated_path)
                comment_retention, lines_added, lines_removed = calculate_semantic_preservation(yaml_path, tmp_remediated_path)

                # --- D. RE-EVALUACIÓN DE SEGURIDAD (Idempotencia) ---
                with open(tmp_remediated_path, 'r') as file_in:
                    remediated_doc = ManifestParser.parse(file_in.read())[0]
                
                rem_mapped_dict = csv_mapper.transform_manifest(remediated_doc)
                rem_config = MappingEngine.manifest_to_configurations(rem_mapped_dict)[0]
                
                #z3_violations_new = z3_validator.validate_configuration(rem_config, z3_policies)
                ast_violations_new = ast_validator.validate_configuration(rem_config, z3_policies)
                passed_regex_new, regex_report_new = regex_validator.validate_with_report(remediated_doc, rem_config.elements, active_regex_policies)
                
                final_alerts = len(ast_violations_new) + (len(regex_report_new) if not passed_regex_new else 0)
                is_fully_secure = (final_alerts == 0)
                print(f"{filename}: final alerts {final_alerts} \n violations in rem: {ast_violations_new}")
                ## If the remediation was applicated and the final alerts are 0, we check the structural preservation with Kubeconform. If it is not valid, we mark the remediation as not fully secure, because it broke the manifest.
                
                # --- E. REGISTRO CSV ---
                writer.writerow([
                    filename, kind, initial_alerts_z3, initial_alerts_ast, initial_alerts_regex, 
                    final_alerts, t_detection_ms, t_ast_remediation_ms,
                    is_fully_secure, is_differential_match, is_remediated_k8s_valid, lines_added, ## is_k8s_valid
                    lines_removed, comment_retention
                ])

            except Exception as e:
                print(f"[ERROR] Fallo procesando {filename}: {e}")
                traceback.print_exc()
                print("-" * 50)
    print(f"\n[OK] Benchmarking finalizado. Resultados en: {OUTPUT_CSV}")

if __name__ == '__main__':
    run_remediation_benchmark()