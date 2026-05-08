import os
import csv
import time
from pathlib import Path
from flamapy.metamodels.fm_metamodel.transformations import UVLReader, FlatFM
from flamapy.metamodels.z3_metamodel.transformations import FmToZ3
from flamapy.metamodels.configuration_metamodel.models import Configuration

# Importamos las funciones de tu script base
from scripts.configurationJSON import ConfigurationJSON
from scripts.valid_config import evaluate_config_security
from scripts._inference_policy import extract_policy_kinds_from_constraints, infer_policies_from_kind

# IMPORTANTE: Importamos tu nueva clase dinámica (ajusta la ruta si es necesario)
from core.remediator_registry import RemediationRegistry

# Configuración de Rutas
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FM_PATH = ROOT / "variability_model" / "model_policies02.uvl"
VALID_JSONS_DIR = ROOT.parent / "valid_jsons"
OUTPUT_CSV = ROOT / "evaluation" / "remediation_benchmark_results.csv"

def calculate_hamming_distance(original_elements: dict, remediated_elements: dict) -> int:
    """
    Calcula la Distancia de Hamming (Δ) sobre el conjunto de features.
    Cuenta cuántas features tienen valores diferentes (o no existen) entre la original y la reparada.
    """
    distance = 0
    all_keys = set(original_elements.keys()).union(set(remediated_elements.keys()))
    for k in all_keys:
        val_orig = original_elements.get(k, None)
        val_rem = remediated_elements.get(k, None)
        # Si el valor ha cambiado o se ha inyectado uno nuevo, aumentamos la distancia
        if val_orig != val_rem:
            distance += 1
    return distance

def run_remediation_benchmark():
    print("[INFO] Cargando Motor Z3, Feature Model y Registry...")
    fm_model = UVLReader(str(FM_PATH)).transform()
    flat_fm_op = FlatFM(fm_model)
    flat_fm_op.set_maintain_namespaces(False)
    flat_fm = flat_fm_op.transform()
    z3_model = FmToZ3(flat_fm).transform()
    constraint_kinds_map = extract_policy_kinds_from_constraints(str(FM_PATH))
    
    # Inicializamos tu Registry dinámico
    remediation_registry = RemediationRegistry(str(FM_PATH))
    
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    
    with open(OUTPUT_CSV, mode='w', newline='') as f:
        writer = csv.writer(f)
        # Añadimos la columna Hamming_Distance para el artículo Q1
        writer.writerow([
            "Filename", "Num_Features", 
            "Original_Score", "New_Score", "Score_Improvement",
            "Hamming_Distance", 
            "T_Initial_Val_ms", "T_Remediation_Val_ms", 
            "Is_Fully_Remediated"
        ])
        
        json_files = [f for f in os.listdir(VALID_JSONS_DIR) if f.endswith('.json')]
        print(f"[INFO] Iniciando Benchmarking de Auto-Remediación sobre {len(json_files)} archivos...")

        for filename in json_files:
            file_path = os.path.join(VALID_JSONS_DIR, filename)
            try:
                # 1. LECTURA Y PREPARACIÓN
                config_reader = ConfigurationJSON(file_path)
                configurations = config_reader.transform()
                if not configurations: continue
                
                base_config = configurations[0]
                auto_policies = infer_policies_from_kind(base_config.elements, constraint_kinds_map)
                if not auto_policies: continue

                # 2. VALIDACIÓN INICIAL (Z3)
                t0_init = time.perf_counter()
                secure_init, sec_score_init, _, report_init, _ = evaluate_config_security(
                    base_config, flat_fm, z3_model, constraint_kinds_map, auto_policies
                )
                t1_init = time.perf_counter()
                t_initial_ms = round((t1_init - t0_init) * 1000, 2)

                # Si ya es seguro de base, lo anotamos y pasamos al siguiente
                if secure_init:
                    writer.writerow([filename, len(base_config.elements), sec_score_init, sec_score_init, 0.0, 0, t_initial_ms, 0.0, True])
                    continue

                # 3. PROCESO DE AUTO-REMEDIACIÓN LÓGICA
                remediated_elements = dict(base_config.elements)
                
                # Para cada política que ha fallado, pedimos las acciones a tu Registry Dinámico
                for issue in report_init:
                    policy_name = issue["policy"]
                    actions = remediation_registry.get_remediation_actions(policy_name)
                    
                    for action in actions:
                        # Inyectamos el valor seguro
                        # Si el feature no aplica al JSON actual, Z3 lo ignorará gracias a tu modelo
                        remediated_elements[action["feature_to_fix"]] = action["safe_value"]
                
                remediated_config = Configuration(remediated_elements)

                # 4. CÁLCULO DE DISTANCIA DE HAMMING (Minimal Change)
                hamming_dist = calculate_hamming_distance(base_config.elements, remediated_elements)

                # 5. VALIDACIÓN POST-REMEDIACIÓN (Z3)
                t0_rem = time.perf_counter()
                secure_new, sec_score_new, _, _, _ = evaluate_config_security(
                    remediated_config, flat_fm, z3_model, constraint_kinds_map, auto_policies
                )
                t1_rem = time.perf_counter()
                t_remediation_ms = round((t1_rem - t0_rem) * 1000, 2)

                score_improvement = round(sec_score_new - sec_score_init, 4)

                writer.writerow([
                    filename, len(base_config.elements), 
                    round(sec_score_init, 4), round(sec_score_new, 4), score_improvement,
                    hamming_dist,
                    t_initial_ms, t_remediation_ms, 
                    secure_new
                ])

            except Exception as e:
                print(f"[ERROR] {filename}: {e}")

    print(f"\n[OK] Benchmarking finalizado. Resultados en {OUTPUT_CSV}")

if __name__ == '__main__':
    run_remediation_benchmark()