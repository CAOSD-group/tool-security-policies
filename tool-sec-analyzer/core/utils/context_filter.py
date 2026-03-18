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
        if workload_root and "io_k8s_api" in feat and not feat.startswith(workload_root):
            continue
            
        # --- REGLA 2: Evitar Recursos Fantasma ---
        if "initContainers" in feat and "initContainers" not in existing_keys_str:
            continue
        if "ephemeralContainers" in feat and "ephemeralContainers" not in existing_keys_str:
            continue
            
        # --- REGLA 3: Limpieza de Sufijos (Solo para inyección en AST/YAML) ---
        if strip_suffixes:
            feat = feat.replace("_valueInt", "") \
                       .replace("_StringValue", "") \
                       .replace("_IntegerValue", "") \
                       .replace("_Always", "")
                       
        valid_actions.append({
            "feature_to_fix": feat,
            "safe_value": safe_val
        })
        
    return valid_actions