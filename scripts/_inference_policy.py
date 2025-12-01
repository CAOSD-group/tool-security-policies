import re

def extract_one_kind(config_elements: dict) -> str | None:
    """
    Extrae el primer kind encontrado en la configuración JSON.
    Devuelve un string: 'Pod', 'Deployment', 'Job', etc.
    """
    for k, v in config_elements.items():
        if k.endswith("_kind") and isinstance(v, str):
            return v
    return None


def infer_policies_from_kind(config_elements: dict, fm_model) -> dict:
    """
    Activa automáticamente todas las políticas cuyo campo 'kinds' 
    incluye el kind detectado en la configuración.
    
    Devuelve:
        dict -> { policy_name: True }
    """
    kind = extract_one_kind(config_elements)
    if not kind:
        return {}

    detected = kind.lower()

    auto_policies = {}

    # Revisar TODAS las features del FM
    for feat in fm_model.get_features():
        attrs = feat.get_attributes()

        if not attrs:
            continue

        kinds_attr = attrs.get("kinds")
        if not kinds_attr:
            continue

        # Normalizar
        feature_kinds = [k.strip().lower() for k in kinds_attr.split(",")]

        # Si coincide → activar política
        if detected in feature_kinds:
            auto_policies[feat.name] = True
    print(f"Politicas detectadas:   {auto_policies}")
    return auto_policies