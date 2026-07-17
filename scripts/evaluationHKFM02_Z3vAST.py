import os
import csv
import time
import subprocess
import difflib
import yaml
import sys
import random
from pathlib import Path
import traceback
import copy
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
from back_kube_tool.core.utils.context_filter import filter_context_aware_actions,sanitize_k8s_manifest

#VALID_YAMLS_DIR = ROOT / "resources" / "dataset_yamls" / "original_yamls_10k"
#VALID_YAMLS_DIR = ROOT / "resources" / "examples" / "testing"  # Para pruebas rápidas, puedes cambiar a un subdirectorio con menos archivos YAML
print(f"Root directory: {ROOT}") ## tool-security-rules
DATASET_BASE = ROOT / "../scriptJsonToUvl" / "yamls_agrupation" ## c:\Users\CAOSD\projects\scriptJsonToUvl\yamls_agrupation
#DATASET_BASE = (ROOT / "../../investigacion/scriptJsonToUvl/yamls_agrupation").resolve()
## c:\projects\investigacion\scriptJsonToUvl
print(f"Ruta del dataset: {DATASET_BASE}")
CATEGORIES = ["tiny", "small", "medium", "large"]
OUTPUT_CSV = ROOT / "resources" / "evaluation" / "z3_vs_ast_comparison_03.csv"
#OUTPUT_CSV = ROOT / "resources" / "evaluation" / "remediation_benchmark_results01_Z3_AST_Complete.csv"

# (Asegúrate de que estas rutas coinciden con tu entorno)
UVL_PATH = os.getenv("UVL_MODEL_PATH", str(ROOT / "back_kube_tool" / "models" / "HKFM.uvl"))
CSV_FEATURES = str(ROOT / "back_kube_tool" / "resources" / "mapping_csv" / "kubernetes_mapping_properties_features.csv")
CSV_KINDS = str(ROOT / "back_kube_tool" / "resources" / "mapping_csv" / "kubernetes_kinds_versions_detected.csv")

#CSV_FEATURES = str(ROOT / "resources" / "mapping_csv" / "kubernetes_mapping_properties_features.csv")
#CSV_KINDS = str(ROOT / "resources" / "mapping_csv" / "kubernetes_kinds_versions_detected.csv")

def get_random_manifests(base_dir, categories, sample_size=10100):
    """
    Recorre las carpetas especificadas, recolecta todos los YAMLs,
    los mezcla y devuelve una muestra aleatoria del tamaño solicitado.
    """
    all_files = []
    for cat in categories:
        cat_dir = base_dir / cat
        if not cat_dir.exists():
            print(f"[WARN] La carpeta {cat_dir} no existe. Saltando...")
            continue
            
        files = [os.path.join(cat_dir, f) for f in os.listdir(cat_dir) if f.endswith(('.yaml', '.yml'))]
        # Guardamos una tupla (ruta_archivo, categoria) para el reporte CSV
        all_files.extend([(f, cat) for f in files])
    
    print(f"[INFO] Total de archivos encontrados en las categorías: {len(all_files)}")
    
    # Prevención por si hay menos de 10k archivos en total
    if len(all_files) < sample_size:
        print(f"[WARN] Solo se encontraron {len(all_files)} archivos. Evaluando todos.")
        sample_size = len(all_files)
        
    sampled_files = random.sample(all_files, sample_size)
    print(f"[INFO] Seleccionados {len(sampled_files)} archivos aleatoriamente.")
    
    return sampled_files


def run_comparison_benchmark():
    print("[INFO] Inicializando Arquitectura Dual-Oracle para Comparativa...")
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    
    # 1. Memory load of the UVL model and initialization of validators
    loader = ModelLoader(UVL_PATH)
    regex_validator = ContentPolicyValidator()
    regex_policy_names = set(regex_validator.policy_map.keys())
    
    inference_engine = PolicyInference(loader.flat_fm, regex_policy_names)
    z3_validator = Z3Validator(loader.flat_fm, loader.z3_model)
    ast_validator = ASTValidator(loader.flat_fm, loader.z3_model)
    csv_mapper = CSVMapper(CSV_FEATURES, CSV_KINDS)
    
    # 2 Obtain a random sample of manifests from the dataset
    sampled_files = get_random_manifests(DATASET_BASE, CATEGORIES, sample_size=10100)

    with open(OUTPUT_CSV, mode='w', newline='') as f:
        writer = csv.writer(f)
        # 1. Cabeceras con la nomenclatura exacta de tu evaluación anterior
        writer.writerow([
            "Filename", "Category", "Kind",
            "N_Features", "N_Features_in_Policies_Complete",
            "N_Features_in_Policies_Failed", "N_Configurations",
            "Z3_Policies_Evaluated", "Z3_Alerts", "AST_Alerts", "Is_Match",
            "T_Z3_ms", "T_AST_ms", "False_Positives_AST", "False_Negatives_AST", "Error_Mapping"
        ])
        
        for filepath, category in sampled_files:
            filename = os.path.basename(filepath)
            
            try:
                with open(filepath, 'r', encoding='utf-8') as file_in:
                    yaml_content_str = file_in.read()
                
                documents = ManifestParser.parse(yaml_content_str)
                if not documents: continue
                
                doc = documents[0]
                kind = doc.get('kind', 'Unknown')
                
                eval_doc = copy.deepcopy(doc)
                clean_eval_doc = sanitize_k8s_manifest(eval_doc)

                try:
                    mapped_json_dict = csv_mapper.transform_manifest(clean_eval_doc)
                except ValueError as ve:
                    writer.writerow([filename, category, kind, 0, 0, 0, 0, 0, 0, 0, "", 0.0, 0.0, "", "", str(ve)])
                    continue

                active_policies = inference_engine.get_policies_for_kind(kind)
                if not active_policies: continue
                
                configurations = MappingEngine.manifest_to_configurations(mapped_json_dict)
                if not configurations: continue
                target_config = configurations[0]
                
                # Excluded policies that are regex-based, as they are handled separately
                z3_policies = [p for p in active_policies if p not in regex_policy_names]
                
                n_configurations = len(configurations)
                n_features = len(target_config.elements)

                # --- Timing Z3 ---
                t0_z3 = time.perf_counter()
                z3_violations = z3_validator.validate_configuration(target_config, z3_policies)
                t_z3_ms = round((time.perf_counter() - t0_z3) * 1000, 2)
                # --- FILTRO FAIL-FAST BASADO EN LA RESPUESTA DEL CORE ---
                if z3_violations and z3_violations[0]["policy"] == "STRUCTURAL_UNSAT":
                    print(f"[{filename}] Saltado: Estructura base inválida (UNSAT en K8s UVL).")
                    
                    writer.writerow([
                        filename, kind, 
                        "STRUCTURAL_UNSAT", # Policies_Evaluated
                        "", "", "", "",     # Orig_Z3, Orig_AST, Orig_Regex, Total_Initial_Alerts
                        "",                 # Rem_Alerts
                        len(target_config.elements), 0, 0, len(configurations), 
                        t_z3_ms, 0.0, 0.0, 0.0, 0.0, # Timers
                        "", "", "",         # Is_Secure, Is_AST_Accurate, Is_K8s_Rem_Valid
                        0, 0, 0.0, 0.0,     # Métricas de remediación
                        "{'error': 'STRUCTURAL_UNSAT'}", "Estructura base del manifest inválida según modelo UVL"
                    ])
                    continue

                # --- Timing AST ---
                t0_ast = time.perf_counter()
                ast_violations = ast_validator.validate_configuration(target_config, z3_policies)
                t_ast_ms = round((time.perf_counter() - t0_ast) * 1000, 2)

                # --- ANÁLISIS DE RESULTADOS Y DISCREPANCIAS ---
                z3_failed_set = {v["policy"] for v in z3_violations}
                ast_failed_set = {v["policy"] for v in ast_violations}
                is_match = (z3_failed_set == ast_failed_set)
                
                # 3. Extracción de Métricas de Complejidad de Políticas (TU MÉTODO EXACTO)
                n_features_in_policies_complete = len(inference_engine.get_features_for_policies(z3_policies))
                
                # Extraemos los nombres de las políticas fallidas uniendo Z3 y AST
                failed_policy_names = [v.get("policy") for v in z3_violations + ast_violations if v.get("policy")]
                n_features_in_policies_failed = len(inference_engine.get_features_for_policies(failed_policy_names))

                # Qué reportó AST que Z3 no (Falso Positivo) / Qué ignoró (Falso Negativo)
                false_positives = list(ast_failed_set - z3_failed_set)
                false_negatives = list(z3_failed_set - ast_failed_set)
                
                print(f"[INFO] Archivo: {filename} false positives: {false_positives}, false negatives: {false_negatives}")

                if not is_match:
                    print(f"[DISCREPANCIA] Archivo: {filename} ({category})")

                # 4. Guardado en CSV con las columnas solicitadas
                writer.writerow([
                    filename, category, kind,
                    n_features, n_features_in_policies_complete,
                    n_features_in_policies_failed, n_configurations,
                    len(z3_policies), len(z3_failed_set), len(ast_failed_set), is_match,
                    t_z3_ms, t_ast_ms, str(false_positives), str(false_negatives), ""
                ])

            except Exception as e:
                print(f"[ERROR] Fallo crítico procesando {filename}: {e}")
                writer.writerow([filename, category, kind, 0, 0, 0, 0, 0, 0, 0, "", 0.0, 0.0, "", "", f"CRITICAL: {e}"])
    print(f"\n[OK] Comparativa finalizada. Resultados guardados en: {OUTPUT_CSV}")

if __name__ == '__main__':
    run_comparison_benchmark()