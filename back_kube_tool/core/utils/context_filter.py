import json
import os
from ruamel.yaml.comments import CommentedSeq

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
    if any("KeyMap" in child_feat or "ValueMap" in child_feat or "StringValueAdditional" in child_feat for child_feat in children.keys()):
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

    # 2. Pre-computar las rutas base para los sufijos dinámicos
    main_container_paths = set()
    init_container_paths = set()
    ephemeral_container_paths = set()
    pod_spec_base_paths = set()
    
    # Único recorrido sobre las keys del AST para clasificar alcances
    for k in original_config_elements.keys():
        k_str = str(k)
        
        # Scope: Contenedores Principales
        if "_containers" in k_str and "_initContainers" not in k_str and "_ephemeralContainers" not in k_str:
            main_container_paths.add(k_str.split("_containers")[0] + "_containers")
            
        # Scope: InitContainers
        if "_initContainers" in k_str:
            init_container_paths.add(k_str.split("_initContainers")[0] + "_initContainers")
            
        # Scope: EphemeralContainers
        if "_ephemeralContainers" in k_str:
            ephemeral_container_paths.add(k_str.split("_ephemeralContainers")[0] + "_ephemeralContainers")
            
        # Scope: Base del PodSpec
        if "_spec_containers" in k_str:
            pod_spec_base_paths.add(k_str.split("_spec_containers")[0] + "_spec")


    # Scope: Todos los contenedores (Unión de los 3 anteriores)
    all_container_paths = main_container_paths | init_container_paths | ephemeral_container_paths
    # Nuevo set específico para contenedores que pertenecen estrictamente a un Pod
    pod_container_paths = all_container_paths if workload_root == "io_k8s_api_core_v1_Pod" else set()


    existing_keys_str = " ".join(original_config_elements.keys())
    valid_actions = []
    
    for action in actions_list:
        feat = action["feature_to_fix"]
        safe_val = action["safe_value"]
        
        # --- EXPANSIÓN DE SUFIJOS DINÁMICOS ---
        # Convertimos 1 token abstracto en N rutas reales del manifiesto
        expanded_features = []
        
        if feat.startswith("DYNAMIC_ALL_CONTAINERS_"):
            suffix = feat.replace("DYNAMIC_ALL_CONTAINERS_", "")
            for base_path in all_container_paths:
                expanded_features.append(f"{base_path}_{suffix}")
                
        elif feat.startswith("DYNAMIC_MAIN_CONTAINERS_"):
            suffix = feat.replace("DYNAMIC_MAIN_CONTAINERS_", "")
            for base_path in main_container_paths:
                expanded_features.append(f"{base_path}_{suffix}")

        elif feat.startswith("DYNAMIC_POD_CONTAINERS_"):
            # Nuevo Scope: Sólo parchear contenedores si el recurso es explícitamente un Pod
            suffix = feat.replace("DYNAMIC_POD_CONTAINERS_", "")
            for base_path in pod_container_paths:
                expanded_features.append(f"{base_path}_{suffix}")
                
        elif feat.startswith("DYNAMIC_POD_SUFFIX_"):
            suffix = feat.replace("DYNAMIC_POD_SUFFIX_", "")
            for base_path in pod_spec_base_paths:
                expanded_features.append(f"{base_path}_{suffix}")
                
        elif feat.startswith("DYNAMIC_ROOT_SUFFIX_"):
            suffix = feat.replace("DYNAMIC_ROOT_SUFFIX_", "")
            if workload_root:
                expanded_features.append(f"{workload_root}_{suffix}")
                
        else:
            expanded_features.append(feat)

        # Ahora aplicamos tus Reglas 1-4 a las rutas ya expandidas y reales
        for current_feat in expanded_features:
            
            # --- REGLA 1: Coincidencia de Workload ---
            if workload_root and "io_k8s" in current_feat and not current_feat.startswith(workload_root):
                continue
                
            # --- REGLA 2: Evitar Recursos Fantasma ---
            if "initContainers" in current_feat and "initContainers" not in existing_keys_str:
                continue
            if "ephemeralContainers" in current_feat and "ephemeralContainers" not in existing_keys_str:
                continue
                
            # --- REGLA 3: ANDAMIAJE ESTRUCTURAL (Dual-Oracle Architecture) ---
            parts = current_feat.split('_')
            for i in range(len(parts), 0, -1):
                possible_parent = "_".join(parts[:i])
                
                if possible_parent in STRUCTURAL_DEPENDENCIES:
                    mandatory_siblings = STRUCTURAL_DEPENDENCIES[possible_parent]
                    
                    for sibling_feat, default_val in mandatory_siblings.items():
                        if sibling_feat not in original_config_elements:
                            clean_sibling = sibling_feat
                            if strip_suffixes:
                                clean_sibling = clean_sibling.replace("_valueInt", "").replace("_StringValue", "").replace("_IntegerValue", "").replace("_Always", "")
                            
                            if not any(a["feature_to_fix"] == clean_sibling for a in valid_actions):
                                valid_actions.append({"feature_to_fix": clean_sibling, "safe_value": default_val})

            # --- REGLA 4: Limpieza de Sufijos y Traducción ---
            final_feat = current_feat
            final_safe_val = safe_val
            
            if strip_suffixes:
                if "_Always" in final_feat and final_safe_val is True:
                    final_feat = final_feat.replace("_Always", "")
                    final_safe_val = "Always"
                if isinstance(final_safe_val, str):
                    final_safe_val = final_safe_val.replace("eu_foo_io", "eu.foo.io").replace("bar_io", "bar.io")
                if "supplementalGroups" in final_feat and not isinstance(final_safe_val, list):
                    final_safe_val = [final_safe_val]
                    
                final_feat = final_feat.replace("_valueInt", "") \
                                     .replace("_StringValue", "") \
                                     .replace("_IntegerValue", "") \
                                     .replace("_Always", "")

            # Este es el único caso donde necesitamos leer el AST para inferir la remediación
            if final_safe_val == "__MAKE_IMAGE_SECURE__":
                # Buscamos en el AST original (usando la clave antes o después del strip)
                original_image = original_config_elements.get(current_feat)
                if not original_image:
                    original_image = original_config_elements.get(current_feat + "_StringValue", "app-image:latest")
                
                original_image = str(original_image).strip()
                if original_image in ["True", "None", "", "unknown-image"]:
                    original_image = "app-image:latest"
                    
                image_basename = original_image.split("/")[-1]
                image_clean = image_basename.split(":")[0].split("@")[0]
                
                # Inyección respetando el nombre de imagen base con registro y digest
                final_safe_val = f"eu.foo.io/{image_clean}:secure-tag@sha256:0000000000000000000000000000000000000000000000000000000000000000"

            # --- RESOLUCIÓN DE CONFLICTOS (Merge con Prioridad) ---
            existing_action = next((a for a in valid_actions if a["feature_to_fix"] == final_feat), None)
            if existing_action:
                existing_action["safe_value"] = final_safe_val
            else:
                valid_actions.append({
                    "feature_to_fix": final_feat,
                    "safe_value": final_safe_val
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
            # Evita que limits y requests se conviertan en listas (guiones)
            if new_path.endswith("_resources_limits") or new_path.endswith("_resources_requests"):
                is_map = True

            if is_map:
                is_array = False
                
            if is_array and isinstance(value, dict):
                # Usar CommentedSeq en lugar de una lista estándar de Python []
                # para mantener viva la estructura de metadatos de ruamel
                data[key] = CommentedSeq([enforce_k8s_object_arrays(value, new_path)])
                
            elif isinstance(value, (dict, list)):
                data[key] = enforce_k8s_object_arrays(value, new_path)
                
    elif isinstance(data, list):
        for i in range(len(data)):
            # CRÍTICO: Solo aplicamos recursión y reasignamos si el hijo es complejo (dict/list).
            # Evitamos reasignar strings (data[i] = data[i]) para no destruir sus comentarios.
            if isinstance(data[i], (dict, list)):
                data[i] = enforce_k8s_object_arrays(data[i], current_path)
                        
    return data
