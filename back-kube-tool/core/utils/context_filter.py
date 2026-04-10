import json
import os

# 1. Cargamos el Oráculo en memoria
ORACLE_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'structural_oracle.json')
try:
    with open(ORACLE_PATH, 'r', encoding='utf-8') as f:
        oracle_data = json.load(f)
        # Separamos las dos secciones
        STRUCTURAL_DEPENDENCIES = oracle_data.get("dependencies", {})
        K8S_DYNAMIC_ARRAYS = set(oracle_data.get("arrays", []))
except FileNotFoundError:
    print("[WARNING] structural_oracle.json no encontrado.")
    STRUCTURAL_DEPENDENCIES = {}
    K8S_DYNAMIC_ARRAYS = set()

# INFERENCIA DINÁMICA DE MAPAS

K8S_DYNAMIC_MAPS = set()
for parent, children in STRUCTURAL_DEPENDENCIES.items():
    # Si alguna de las propiedades hijas contiene "KeyMap" o "ValueMap", 
    # inferimos automáticamente que el padre es un Mapa (Diccionario), no una Lista.
    if any("KeyMap" in child_feat or "ValueMap" in child_feat for child_feat in children.keys()):
        K8S_DYNAMIC_MAPS.add(parent)

def filter_context_aware_actions(original_config_elements: dict, actions_list: list, strip_suffixes: bool = False) -> list:
    """
    Filtro semántico basado en el Espacio de Configuración.
    Garantiza que solo se apliquen parches a jerarquías que realmente
    existan en el manifiesto instanciado.
    """
    if not original_config_elements:
        return []
        
    # 1. Encontrar el root del workload de forma segura (ej: 'io_k8s_api_apps_v1_Deployment')
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
        
        # --- REGLA 1: Coincidencia de Workload ---
        if workload_root and "io_k8s" in feat and not feat.startswith(workload_root):
            continue
        # --- REGLA 2: Evitar Recursos Fantasma ---
        if "initContainers" in feat and "initContainers" not in existing_keys_str:
            continue
        if "ephemeralContainers" in feat and "ephemeralContainers" not in existing_keys_str:
            continue
        # REGLA 3: ANDAMIAJE ESTRUCTURAL (Dual-Oracle Architecture)
        # Buscamos si la feature que vamos a arreglar necesita propiedades obligatorias
        # =================================================================
        parts = feat.split('_')
        for i in range(len(parts), 0, -1):
            possible_parent = "_".join(parts[:i])
            
            # USAMOS STRUCTURAL_DEPENDENCIES en lugar de STRUCTURAL_ORACLE
            if possible_parent in STRUCTURAL_DEPENDENCIES:
                mandatory_siblings = STRUCTURAL_DEPENDENCIES[possible_parent]
                
                for sibling_feat, default_val in mandatory_siblings.items():
                    if sibling_feat not in original_config_elements:
                        clean_sibling = sibling_feat
                        if strip_suffixes:
                            clean_sibling = clean_sibling.replace("_valueInt", "").replace("_StringValue", "").replace("_IntegerValue", "").replace("_Always", "")
                        
                        if not any(a["feature_to_fix"] == clean_sibling for a in valid_actions):
                            valid_actions.append({"feature_to_fix": clean_sibling, "safe_value": default_val})

        # --- REGLA 4: Limpieza de Sufijos y Traducción para la feature principal (Solo para inyección en AST/YAML)---
        
        if strip_suffixes:
            # A) Traducir Booleano de Z3 a Enum de K8s
            if "_Always" in feat and safe_val is True:
                feat = feat.replace("_Always", "")
                safe_val = "Always"
            # B) Traducir dominios del modelo a URLs reales
            if isinstance(safe_val, str):
                safe_val = safe_val.replace("eu_foo_io", "eu.foo.io").replace("bar_io", "bar.io")
            # C) Empaquetar escalares en listas para propiedades array de K8s
            if "supplementalGroups" in feat and not isinstance(safe_val, list):
                safe_val = [safe_val]
                
            # D) Limpieza final de sufijos
            feat = feat.replace("_valueInt", "") \
                    .replace("_StringValue", "") \
                    .replace("_IntegerValue", "") \
                    .replace("_Always", "")
        # --- RESOLUCIÓN DE CONFLICTOS (Merge con Prioridad) ---
        # Si el andamiaje estructural acaba de meter un valor por defecto para esta misma feature,
        # la regla de seguridad (safe_val) lo SOBREESCRIBE porque tiene prioridad.
        
        existing_action = next((a for a in valid_actions if a["feature_to_fix"] == feat), None)
        if existing_action:
            existing_action["safe_value"] = safe_val
        else:
            valid_actions.append({
                "feature_to_fix": feat,
                "safe_value": safe_val
            })
        
    return valid_actions

def enforce_k8s_object_arrays(data, current_path=""):
    """
    Post-procesador recursivo que envuelve diccionarios en listas.
    AHORA ES 100% DINÁMICO LEYENDO DE `K8S_DYNAMIC_ARRAYS`.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            new_path = f"{current_path}_{key}" if current_path else key
            
            # Comprobación Dinámica Universal (sirve para Mandatory y Optional)
            is_array = any(arr.endswith(new_path) for arr in K8S_DYNAMIC_ARRAYS)
            
            is_map = any(m.endswith(new_path) for m in K8S_DYNAMIC_MAPS)
            # Si el modelo dictó que es un Mapa, anulamos la conversión a Array
            if is_map:
                is_array = False
                
            if is_array and isinstance(value, dict):
                data[key] = [enforce_k8s_object_arrays(value, new_path)]
            else:
                data[key] = enforce_k8s_object_arrays(value, new_path)
                
    elif isinstance(data, list):
        return [enforce_k8s_object_arrays(item, current_path) for item in data]
        
    return data
