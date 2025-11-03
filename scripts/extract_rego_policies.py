import csv
from collections import defaultdict

import re
import yaml

def build_field_map(csv_path):
    field_map = defaultdict(list)

    with open(csv_path) as f:
        reader = csv.DictReader(f)

        for row in reader:
            # Ex: Detect feature using the FM mapping
            semantic_key = row["feature_name"]  # p.ej.: securityContext.capabilities.add // We need to take account the rest of the part of the features using the comments Kinds
            field_map[semantic_key].append(row["feature_path"])

    return field_map

# Cargar CSV de mapeo Kubernetes → UVL
def load_field_map(csv_file="k8s_fields_map.csv"):
    mapping = {}
    with open(csv_file, newline="") as f:
        for field, uvl_path in csv.reader(f):
            mapping[field.strip()] = uvl_path.strip()
    return mapping

def extract_metadata_from_rego(rego_text):
    lines = rego_text.splitlines()
    capture = False
    meta_lines = []

    for line in lines:
        stripped = line.strip()

        # Start metadata
        if stripped.startswith("# METADATA"):
            capture = True
            continue

        # Stop when metadata ends
        if capture and not stripped.startswith("#"):
            break

        # Collect metadata commented lines preserving indentation
        if capture and line.lstrip().startswith("#"):
            # Find index of '#' in original line to preserve indent
            idx = line.index("#")
            yaml_part = line[idx+1:]   # drop '#' but *not* indentation after it
            meta_lines.append(yaml_part.rstrip())

    if not meta_lines:
        return {}

    # Join and remove first leading blank if present
    meta_text = "\n".join(meta_lines).lstrip("\n")

    try:
        meta_yaml = yaml.safe_load(meta_text)
        if not isinstance(meta_yaml, dict):
            return {}
    except Exception as e:
        print("YAML ERROR:", e)
        print("YAML TEXT:\n", meta_text)
        return {}

    # Handle custom nested or flattened
    custom = meta_yaml.get("custom") or {}
    print("Custom:", custom)
    if not isinstance(custom, dict):
        custom = {}

    # extract types
    kinds = []
    selectors = (
        custom.get("input", {}).get("selector", [])
        if "input" in custom
        else []
    )

    for sel in selectors:
        subtypes = sel.get("subtypes", [])
        for item in subtypes:
            if isinstance(item, dict) and "kind" in item:
                kinds.append(item["kind"].lower())

    return {
        "title": meta_yaml.get("title", ""),
        "description": meta_yaml.get("description", ""),
        "severity": custom.get("severity", ""),
        "id": custom.get("id", ""),
        "short_code": custom.get("short_code", ""),
        "recommended_action": custom.get("recommended_action", ""),
        "kinds": sorted(set(kinds)),
    }


def extract_conditions_from_rego(rego_text):
    # Example match: container.securityContext.capabilities.add[_] == "SYS_MODULE"
    pat = re.compile(r'(\S+?)\s*(==|!=)\s*"([^"]+)"')
    matches = pat.findall(rego_text)

    conditions = []
    for field, op, value in matches:
        # normalize container.securityContext.capabilities.add[_]
        field = field.replace("[_]", "")

        conditions.append({
            "field": field,
            "operator": op,
            "value": value
        })

    return conditions


def parse_rego_policy(path):
    with open(path, "r") as f:
        rego = f.read()

    metadata = extract_metadata_from_rego(rego)
    conds = extract_conditions_from_rego(rego)

    return {
        "metadata": metadata,
        "conditions": conds
    }


def rego_policy_to_uvl(policy, field_map):
    meta = policy["metadata"]
    cond = policy["conditions"][0]  # Asumimos 1 condición base por ahora

    field = cond["field"]
    operator = cond["operator"]
    value = cond["value"]

    # Convert Rego container path to canonical lookup key
    field_key = field.replace("container.", "containers.")

    # Buscar traducción en el CSV
    if field_key not in field_map:
        print(f"[WARNING] No UVL mapping for field: {field_key}")
        return None

    uvl_attr = field_map[field_key]

    # Convert operator (only simple == banned)
    if operator == "==":
        expr = f"!{uvl_attr}_{value}"
    elif operator == "!=":
        expr = f"{uvl_attr}_{value}"
    else:
        expr = f"UNSUPPORTED_OPERATOR({operator})"

    # Feature name sanitized
    feature_name = meta["id"] + "_" + meta["short_code"]

    feature_block = f"""
    {feature_name} {{
        doc '{meta['description']}',
        severity '{meta['severity']}',
        tool 'OPA',
        recommended '{meta['recommended_action']}'
    }}
"""

    constraint = f"{feature_name} => {expr}"

    return feature_block, constraint



# DEMO USAGE

## ../resources/kyverno_policies_yamls
data = parse_rego_policy("../resources/kyverno_policies_yamls/OPA_Policies/SYS_ADMIN_capability.rego")
print(data)
