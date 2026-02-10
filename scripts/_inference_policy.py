import re

def _has_image_recursive(data) -> bool:
    """
    Busca recursivamente si existe alguna clave que termine en '_image'.
    Retorna True a la primera coincidencia (Fail-fast).
    """
    target_suffix = "_image" # O la lista de sufijos si quieres ser más específico

    if isinstance(data, dict):
        for k, v in data.items():
            # Chequeo de clave
            if str(k).endswith(target_suffix):
                return True
            # Recursión
            if isinstance(v, (dict, list)):
                if _has_image_recursive(v):
                    return True
    
    elif isinstance(data, list):
        for item in data:
            if _has_image_recursive(item):
                return True
                
    return False


def extract_policy_kinds_from_constraints(uvl_path: str) -> dict:
    """
    Analiza SOLO el bloque 'constraints' del UVL final.
    Devuelve: { policy_name: {Kind1, Kind2, ...} }
    """
    policy_kinds = {}
    inside_constraints = False

    try:
        with open(uvl_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()

                if stripped.startswith("constraints"):
                    inside_constraints = True
                    continue

                if not inside_constraints:
                    continue
                
                if not stripped:
                    continue

                if "=>" not in stripped:
                    continue

                policy, expr = stripped.split("=>", 1)
                policy = policy.strip()
                expr = expr.strip()

                feature_names = re.findall(r"[A-Za-z0-9_.]+", expr)

                for ft in feature_names:
                    if "." in ft:
                        ft = ft.split(".", 1)[1]

                    if not ft.startswith("io_k8s_"):
                        continue

                    aux = re.search(r"[A-Z].*", ft)
                    if not aux:
                        continue
                    kind = aux.group(0).split("_")[0]

                    policy_kinds.setdefault(policy, set()).add(kind)
    except Exception as e:
        print(f"[ERROR] Al leer UVL: {e}")
        return {}

    return policy_kinds


def detect_kind_from_config(config_elements: dict) -> str | None:
    # Busca el kind en el nivel raíz del diccionario aplanado o jerárquico
    if isinstance(config_elements, dict):
        for k, v in config_elements.items():
            if k.endswith("_kind") and isinstance(v, str):
                return v
    return None


def infer_policies_from_kind(config_elements: dict, policy_kinds_map: dict) -> list:
    """
    Devuelve una LISTA de políticas aplicables combinando:
    1. Inferencia por Kind (desde el UVL)
    2. Inferencia por Contenido (Features detectadas en el JSON)
    """
    selected_policies = set() # Usamos set para evitar duplicados
    
    # --- 1. Inferencia basada en KIND (Estructural) ---
    kind = detect_kind_from_config(config_elements)
    
    if kind:
        for policy, kinds in policy_kinds_map.items():
            if kind in kinds:
                selected_policies.add(policy)

    # --- 2. Inferencia basada en CONTENIDO (Heurística) ---
    if _has_image_recursive(config_elements):
        #print("[Inferencia] Detectadas imágenes en la config -> Activando 'tagNotSpecified'")
        selected_policies.add('tagNotSpecified')
        
        # selected_policies.add('Restrict_Image_Registries') 

    return list(selected_policies)

# ---------------------------------------------------------
# MAIN PARA PRUEBAS
# ---------------------------------------------------------
if __name__ == "__main__":
    uvl = "../variability_model/policies_template/policy_structure03.uvl"

    print("Extrayendo políticas desde constraints...")
    policy_kinds = extract_policy_kinds_from_constraints(uvl)

    # Configuración de prueba (Simulando un Pod con imagen)
    config_test = {
        "io_k8s_api_core_v1_Pod_kind": "Pod",
        "io_k8s_api_core_v1_Pod_spec": {
             "containers": [
                 {"io_k8s_api_core_v1_Pod_spec_containers_image": "nginx"}
             ]
        }
    }

    detected = infer_policies_from_kind(config_test, policy_kinds)
    
    print(f"\nPolíticas aplicables: {len(detected)}")
    for p in detected:
        print(f" - {p}")
        
    if 'tagNotSpecified' in detected:
        print("\n[SUCCESS] La política 'tagNotSpecified' fue detectada correctamente por contenido.")