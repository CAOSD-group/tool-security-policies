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

#VALID_YAMLS_DIR = ROOT / "resources" / "dataset_yamls" / "original_yamls_10k"
VALID_YAMLS_DIR = ROOT / "resources" / "examples" / "testing"  # Para pruebas rápidas, puedes cambiar a un subdirectorio con menos archivos YAML
print(f"Root directory: {ROOT}")
OUTPUT_CSV = ROOT / "resources" / "evaluation" / "remediation_testing_Z3_AST_1_testing.csv"
TMP_REMEDIATED_DIR = ROOT / "resources" / "evaluation" / "tmp_remediateds_1_testing"

# (Asegúrate de que estas rutas coinciden con tu entorno)
UVL_PATH = os.getenv("UVL_MODEL_PATH", str(ROOT / "back_kube_tool" / "models" / "HKFM.uvl"))
CSV_FEATURES = str(ROOT / "back_kube_tool" / "resources" / "mapping_csv" / "kubernetes_mapping_properties_features.csv")
CSV_KINDS = str(ROOT / "back_kube_tool" / "resources" / "mapping_csv" / "kubernetes_kinds_versions_detected.csv")

#CSV_FEATURES = str(ROOT / "resources" / "mapping_csv" / "kubernetes_mapping_properties_features.csv")
#CSV_KINDS = str(ROOT / "resources" / "mapping_csv" / "kubernetes_kinds_versions_detected.csv")

def run_kubeconform(yaml_path: str) -> tuple[bool, str]:
    """
    Execute kubeconform against the given YAML file to validate its structure against Kubernetes schemas.
    Returns a tuple of (is_valid, error_message). If the YAML is valid, error_message will be an empty string.
    """
    try:
        # capture_output=True hace que Python atrape el texto en result.stdout
        result = subprocess.run(
            ["kubeconform", "-strict", "-summary", yaml_path],
            capture_output=True,
            text=True,
            timeout=7
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
    
    ## Absolute metric of how closely the remediated file matches the original (including both code and comments).
    #  A higher percentage means the remediated file is more similar to the original, which can be an indicator of better semantic preservation.
    matcher = difflib.SequenceMatcher(None, orig_lines, rem_lines)
    patch_similarity = round(matcher.ratio() * 100, 2)
    
    return round(comment_retention, 2), lines_added, lines_removed, patch_similarity


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
            "Filename", "Kind", "Policies_Evaluated", "Orig_Z3_Alerts", "Orig_AST_Alerts", "Orig_Regex_Alerts", "Total_Initial_Alerts",
            "Rem_Alerts", "N_Features", "N_Features_in_Policies_Complete", "N_Features_in_Policies_Failed", "N_Configurations", "T_Detection_ms", "T_AST_Remed_ms", "T_Total_Pipeline_ms",
            "Is_Fully_Secure", "Is_AST_100%_Accurate", "Is_K8s_Rem_Valid", "AST_Lines_Added", ## "Is_K8s_Valid",
            "AST_Lines_Removed", "Patch_Similarity_%", "Comments_Retention_%", "Kubeconform_Error" ## En caso de que la remediación rompa el manifiesto, registramos el error de kubeconform para análisis posterior
        ]) ## Pendent to add Nº Features, Nº Features in Policies, Nº Configurations
        
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
                    "SCHEMA_ERROR", # Policies_Evaluated
                    "", "", "", "", # Orig Z3, AST, Regex, Total Alerts
                    "", # Rem_Alerts
                    0, 0, 0, 0, t_kubeconform_ms, 0.0, t_kubeconform_ms, # Anotamos el tiempo que tardó en rechazarlo
                    "", "", "", # Is_Secure, Is_Accurate, Is_K8s_Rem_Valid
                    0, 0, 0.0, 0.0, kube_error_msg
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
                    t_detection_ms = round((time.perf_counter() - t0_init) * 1000, 2)
                    # 18 elementos exactos
                    writer.writerow([
                        filename, kind, 
                        "ERROR_MAP", # Policies_Evaluated
                        "", "", "", "", # Alerts
                        "", 0, 0, 0, 0, # Rem_Alerts, N_Features, N_Features_in_Policies, N_Configurations
                        t_detection_ms, 0.0, t_detection_ms, # Timers
                        "", "", "", # Is_Secure, Is_Accurate, Is_K8s_Rem_Valid
                        0, 0, 0.0, 0.0, 
                        str(ve) # Register the mapping error in the CSV for analysis (e.g., missing kind, unsupported features, etc.)
                    ])
                    continue

                active_policies = inference_engine.get_policies_for_kind(kind)
                if not active_policies: continue
                
                configurations = MappingEngine.manifest_to_configurations(mapped_json_dict)
                if not configurations: continue
                target_config = configurations[0]
                print("\n--- INICIO DE AUDITORÍA DE CONFIGURACIÓN ---")
                print(f"Número de configuraciones generadas: {len(configurations)}")
                protocolos_activos = {k: v for k, v in target_config.elements.items() if "protocol" in k and v is True}
                print(f"Protocolos activos en configs[0]: {list(protocolos_activos.keys())}")
                print("--- FIN DE AUDITORÍA ---\n")
                
                
                print(f"[{filename}] Evaluando {len(active_policies)} políticas activas sobre {kind}...") # Log de progreso
                print(f"Config ejemplo: {target_config.elements}") # Log de ejemplo de configuración
                # A.1 Z3 Validation
                z3_policies = [p for p in active_policies if p not in regex_policy_names]
                z3_violations = z3_validator.validate_configuration(target_config, z3_policies)
                ast_violations = ast_validator.validate_configuration(target_config, z3_policies)

                ## Extract the number of features involved in the policies for reporting
                num_features_in_config = len(target_config.elements)
                num_features_in_active_policies = len(inference_engine.get_features_for_policies(z3_policies))
                
                # 1. Extraemos solo los nombres de las políticas de las violaciones
                failed_policy_names = [v.get("policy") for v in z3_violations + ast_violations if v.get("policy")]
                # 2. Le pedimos a tu motor la lista de features implicadas (el blast radius)
                failed_features_set = inference_engine.get_features_for_policies(failed_policy_names)
                print(f"Failed policies: {failed_policy_names}  Failed features: {failed_features_set}")
                num_features_in_failed_policies = len(failed_features_set)
                ##num_features_in_failed_policies = len({feature for v in z3_violations + ast_violations for feature in v.get("features", [])})

                print(f"[{filename}] Features in config: {num_features_in_config}, Features in active policies: {num_features_in_active_policies}, Features in failed policies: {num_features_in_failed_policies}")
                num_configurations = len(configurations)

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

                total_initial_alerts = initial_alerts_ast + initial_alerts_regex
                num_policies = len(active_policies) if active_policies else 0
                
                if len(all_initial_violations) == 0:
                    writer.writerow([filename, kind, num_policies, initial_alerts_z3, initial_alerts_ast, initial_alerts_regex, total_initial_alerts, 0, num_features_in_config, num_features_in_active_policies, num_features_in_failed_policies, num_configurations, t_detection_ms, 0.0, t_detection_ms, True, True, True, 0, 0, 100.0, ""])
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
                comment_retention, lines_added, lines_removed, patch_similarity = calculate_semantic_preservation(yaml_path, tmp_remediated_path)

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
                t_total_pipeline_ms = round(t_detection_ms + t_ast_remediation_ms, 2) ## Total pipeline time (Detection + Remediation) - Not including kubeconform time, as it's a separate structural validation step.
                # --- E. REGISTRO CSV ---
                writer.writerow([
                    filename, kind, num_policies, initial_alerts_z3, initial_alerts_ast, initial_alerts_regex, total_initial_alerts,
                    final_alerts, num_features_in_config, num_features_in_active_policies, num_features_in_failed_policies, num_configurations, t_detection_ms, t_ast_remediation_ms, t_total_pipeline_ms,
                    is_fully_secure, is_differential_match, is_remediated_k8s_valid, lines_added, ## is_k8s_valid
                    lines_removed, patch_similarity, comment_retention, error_string_empty
                ])

            except Exception as e:
                print(f"[ERROR] Fallo procesando {filename}: {e}")
                traceback.print_exc()
                print("-" * 50)
    print(f"\n[OK] Benchmarking finalizado. Resultados en: {OUTPUT_CSV}")

if __name__ == '__main__':
    run_remediation_benchmark()