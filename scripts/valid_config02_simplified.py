# This script checks whether a configuration (given as a list of keys) is valid according to a feature model.

from flamapy.metamodels.configuration_metamodel.models import Configuration
from flamapy.metamodels.fm_metamodel.models import FeatureModel, Feature
from flamapy.metamodels.fm_metamodel.transformations import UVLReader, FlatFM
from flamapy.metamodels.pysat_metamodel.models import PySATModel
from flamapy.metamodels.pysat_metamodel.transformations import FmToPysat
from flamapy.metamodels.pysat_metamodel.operations import (PySATSatisfiable, PySATSatisfiableConfiguration)


from flamapy.metamodels.z3_metamodel.transformations import FmToZ3
from flamapy.metamodels.z3_metamodel.operations import (
    Z3Satisfiable,
    Z3Configurations,
    Z3ConfigurationsNumber,
    Z3CoreFeatures,
    Z3DeadFeatures,
    Z3FalseOptionalFeatures,
    Z3AttributeOptimization,
    Z3SatisfiableConfiguration,
)
from flamapy.metamodels.z3_metamodel.operations.interfaces import OptimizationGoal

from flamapy.metamodels.configuration_metamodel.transformations import ConfigurationJSONReader


from pathlib import Path
import os
import logging
import contextlib, io
from scripts.configurationJSON01 import ConfigurationJSON ## clase Reader JSON
from scripts._inference_policy import extract_policy_kinds_from_constraints, infer_policies_from_kind
import time  # Libreria para calcular los tiempos de procesamiento

from scripts.regex_validator import ContentPolicyValidator


logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


HERE   = Path(__file__).resolve().parent
ROOT   = HERE.parent
MODELS = ROOT / "variability_model" / "policies_template"
RES    = ROOT / "resources"

UVL_PATH = MODELS / "model_policies02.uvl"
# usar str(UVL_PATH) si la librería lo exige
path_json = RES / "valid_yamls" / "0-cluster-autoscaler_5.json" ##1-metallb5_2_Test01  1-metallb5_2_Test02-Invalid,test-require-run-as-nonroot_1.json,
VALIDATE_ONLY_FIRST_CONFIG = True ## Use unit or total validation version

def get_all_parents(feature: Feature) -> list[str]:
    parent = feature.get_parent()
    return [] if parent is None  else [parent.name] + get_all_parents(parent)


def get_all_mandatory_children(feature: Feature) -> list[str]:
    children = []
    for child in feature.get_children():
        if child.is_mandatory():
            children.append(child.name)
            children.extend(get_all_mandatory_children(child))
    return children


def complete_configuration(configuration: Configuration, fm_model: FeatureModel) -> Configuration:
    """Given a partial configuration completes it by adding the parent's features and
    children's features that must be included because of the tree relationships of the
    provided FM model."""
    configs_elements = dict(configuration.elements)
        
    for element in configuration.get_selected_elements():
        feature = fm_model.get_feature_by_name(element)
        if feature is None:
            raise Exception(f'Error: the element "{element}" is not present in the FM model.')
        
        # 1. Obtenemos listas de nombres de hijos obligatorios y padres
        children_names = get_all_mandatory_children(feature)
        parent_names = get_all_parents(feature)
        
        # Añadimos los hijos obligatorios de los padres
        for parent in parent_names:
            parent_feature = fm_model.get_feature_by_name(parent)
            children_names.extend(get_all_mandatory_children(parent_feature))
            
        # 2. Inyectamos los padres a True SOLO si no están ya en el diccionario
        for parent in parent_names:
            if parent not in configs_elements:
                configs_elements[parent] = True
                
        # 3. Inyectamos los hijos obligatorios a True SOLO si no están ya
        # (Esto evita sobrescribir 'Default' con True)
        for child in children_names:
            if child not in configs_elements: ## To avoid overwriting 'Default' with True, we only set to True if the child is not already in the config (which means it was not explicitly set to False or Default)
                configs_elements[child] = True
                
    return Configuration(configs_elements)


# --- NUEVA FUNCIÓN PARA EXTRAER METADATOS DEL UVL ---
def get_policy_remediation_info(flat_fm: FeatureModel, policy_name: str) -> dict:
    """Extrae los metadatos de la política (doc, RecommendedAction, severity) del modelo UVL."""
    feature = flat_fm.get_feature_by_name(policy_name)
    info = {
        "description": "No description available", 
        "remediation": "Review the manifest.", 
        "severity": "unknown"
    }
    
    if feature:
        for attr in feature.get_attributes():
            if attr.name == 'doc':
                info["description"] = attr.get_default_value()
            elif attr.name == 'RecommendedAction':
                info["remediation"] = attr.get_default_value()
            elif attr.name == 'severity':
                info["severity"] = attr.get_default_value()
    return info


# --- FUNCIÓN DE VALIDACIÓN MODIFICADA PARA EVALUACIÓN ITERATIVA ---
def valid_config_version_json_Z3(configuration_json: Configuration, flat_fm, z3_model, constraint_kinds_map):
    """
    Check if a configuration is valid (satisfiable) according to the Z3 model.
    Evaluates policies iteratively to isolate failures.
    """    
    print(f"[DEBUG MAIN] Tipo de datos pasado al validador: {type(configuration_json.elements)}")
    auto_policies = infer_policies_from_kind(configuration_json.elements, constraint_kinds_map)
    print(f"[INFO] Políticas activas para este archivo: {auto_policies}")

    validator = ContentPolicyValidator()
    #regex_passed = validator.validate(configuration_json.elements, auto_policies)
    regex_passed, regex_failures = validator.validate_with_report(configuration_json.elements, auto_policies)
    
    failed_policies_report = []
    passed_policies = []

    # Añadimos cada fallo regex como issue de SU policy (con metadata del UVL)
    for f in regex_failures:
        policy = f["policy"]
        meta = get_policy_metadata(flat_fm, policy)
        failed_policies_report.append({
            "policy": policy,
            "tool": meta.get("tool", "unknown"),
            "severity": meta.get("severity", "unknown"),
            "weight": meta.get("weight", ""),
            "kinds": meta.get("kinds", ""),
            "raw_source": meta.get("raw_source", ""),
            "description": meta.get("doc", ""),
            "regex_reason": f.get("reason", ""),
            "result": "FAILED_REGEX"
        })
    print("-> Entrando a diagnóstico Z3 iterativo...")


    # EVALUACIÓN ITERATIVA: Probamos cada política de forma independiente
    for policy in auto_policies:
        try: 
            # 1. Hacemos una copia limpia de los elementos base (el manifiesto original)
            temp_elements = configuration_json.elements.copy()
            
            # 2. Activamos SOLO la política actual que queremos auditar
            temp_elements[policy] = True
            
            # 3. Completamos la configuración para esta prueba
            temp_config = Configuration(temp_elements)
            temp_config_completed = complete_configuration(temp_config, flat_fm)
            temp_config_completed.set_full(True)
            
            # 4. Validamos con Z3
            sat_op = Z3SatisfiableConfiguration()
            sat_op.set_configuration(temp_config_completed)
            is_sat = sat_op.execute(z3_model).get_result()
            
            # 5. Si falla, registramos la vulnerabilidad
            if not is_sat:
                remediation_info = get_policy_remediation_info(flat_fm, policy)
                failed_policies_report.append({
                    "policy": policy,
                    "description": remediation_info.get("description"),
                    "remediation": remediation_info.get("remediation"),
                    "severity": remediation_info.get("severity")
                })
            else:
                passed_policies.append(policy)
        except Exception as e:
            # CLAVE: una policy puede estar mal “mapeada” o referenciar features que no existen,
            # o Z3/FlamaPy puede fallar con esa combinación -> no paramos, lo reportamos.
            failed_policies_report.append({
                "policy": policy,
                "severity": "error",
                "description": f"Error interno evaluando la política: {e}",
                "remediation": "Revisar mapeo de la policy / nombres de features / constraints."
            })
            # seguimos con la siguiente policy
            continue
    # El resultado global es válido solo si NINGUNA política ha fallado
    global_is_satisfiable = len(failed_policies_report) == 0

    # Construimos la config final solo con las políticas que pasaron 
    # (para no romper la ejecución de tu script original)
    final_elements = configuration_json.elements.copy()
    for p in passed_policies:
        final_elements[p] = True
    
    final_config = complete_configuration(Configuration(final_elements), flat_fm)

    return global_is_satisfiable, final_config.get_selected_elements(), failed_policies_report

def get_policy_metadata(flat_fm, policy_name: str) -> dict:
    feat = flat_fm.get_feature_by_name(policy_name)
    info = {
        "tool": "unknown",
        "severity": "unknown",
        "weight": "",
        "doc": "",
        "kinds": "",
        "raw_source": "",
        "name": "",
    }
    if not feat:
        return info

    for attr in feat.get_attributes():
        val = attr.get_default_value()
        if attr.name in info:
            info[attr.name] = val
        elif attr.name == "RecommendedAction":
            info["remediation"] = val

    return info

def inizialize_model(model_path):
    fm_model = UVLReader(model_path).transform()
    sat_model = FmToPysat(fm_model).transform()
    return fm_model, sat_model

def main(configuration, fm_model, sat_model, cardinality=False):
    error = ''
    report = []
    try:
        # Ajustado para recibir los 3 valores que ahora devuelve la función
        valid, complete_config, report = valid_config_version_json_Z3(configuration, fm_model, sat_model, None) 
        if not valid and cardinality == True:
            valid = True
    except Exception as e:
        valid = False
        error = str(e)
    return valid, error, complete_config, report


if __name__ == '__main__':
    # You need the model in SAT
    fm_model = UVLReader(str(UVL_PATH)).transform()
    start_startup_model = time.time()  # Start of validation time

    flat_fm_op = FlatFM(fm_model)
    flat_fm_op.set_maintain_namespaces(False)  # False para quitar el prefijo del import, con True se mantiene.
    flat_fm = flat_fm_op.transform()
    
    z3_model = FmToZ3(flat_fm).transform()
    result = Z3Satisfiable().execute(z3_model).get_result()
    print(f'Satisfiable: {result}')
    # Baja el nivel global
    logging.basicConfig(level=logging.ERROR)

    for name in (
        'flamapy',
        'flamapy.metamodels',
        'flamapy.metamodels.fm_metamodel',
        'flamapy.metamodels.pysat_metamodel',
    ):
        logging.getLogger(name).setLevel(logging.ERROR)

    print("== Constraints del FM ==")
    if hasattr(flat_fm, "constraints"):
        for c in flat_fm.constraints:
            print(c)
    elif hasattr(flat_fm, "get_constraints"):
        for c in flat_fm.get_constraints():
            print(c)
    else:
        print("No veo un atributo/método estándar de constraints en este objeto.")

    print("SE LLEGA HASTA AQUI")
    silent = io.StringIO()
    with contextlib.redirect_stdout(silent):
        sat_model = FmToPysat(flat_fm).transform()
    
    # 3) Precalcular set de features SAT
    SAT_FEATURES = set(sat_model.variables.keys())
    end_startup_model = time.time()  # End of validation time
    validation_time = round(end_startup_model - start_startup_model, 4)

    print(f"Tiempo de start config of FMs   {validation_time}")

    configuration_reader = ConfigurationJSON(str(path_json))
    configurations = configuration_reader.transform()
    print(f"Configuraciones que hay:    {len(configurations)}")
        
    print(f"#########     VALIDACION")
    
    print("FEATURES en SAT model:")
    out_path = os.path.join(os.path.dirname(__file__), "sat_features_dump.txt")
    with open(out_path, "w", encoding="utf-8") as f_out:
        f_out.write("FEATURES en SAT model:\n")
        for f in sat_model.variables.keys():
            f_out.write(f"- {f}\n")
            
    print(f"[INFO] Se ha guardado la lista completa de features en: {out_path}")

    # 1) EXTRAER constraints → mapa {policy: kinds}
    constraint_kinds_map = extract_policy_kinds_from_constraints(UVL_PATH)
    
    if VALIDATE_ONLY_FIRST_CONFIG:
        print(f"Validando solo la primera configuración Z3 )")
        print(f'Configuration from {path_json}: {configurations[0].elements}')
        config_Z3 = configurations[0]

        # --- AQUÍ OCURRE LA MAGIA ---
        start_validation_time = time.time()
        
        # Desempaquetamos los 3 valores: Booleano, Lista de features, y el Reporte de Errores
        valid, complete_config, report = valid_config_version_json_Z3(config_Z3, flat_fm, z3_model, constraint_kinds_map) 
        
        end_validation_time = time.time()  
        validation_time = round(end_validation_time - start_validation_time, 4)
        
        # --- IMPRESIÓN DEL REPORTE DE AUDITORÍA PARA EL USUARIO / DEMO ---
        print("\n" + "="*70)
        print(f" RESULTADO DE LA AUDITORÍA DE SEGURIDAD ({validation_time} seg)")
        print("="*70)
        print(f" Manifiesto Seguro (Z3): {valid}")
        
        if not valid:
            print(f"\n SE HAN DETECTADO {len(report)} VULNERABILIDADES EN EL MANIFIESTO:\n")
            for issue in report:
                severity = issue.get('severity', 'UNKNOWN')
                if severity: severity = str(severity).upper()
                
                print(f" POLÍTICA VIOLADA : {issue['policy']} [Severidad: {severity}]")
                print(f"   Motivo        : {issue['description']}")
                #print(f"   Recomendación : {issue['remediation']}")
                print("-" * 70)
        else:
            print("\n El manifiesto cumple con todas las políticas de seguridad activas.")
        print("="*70)