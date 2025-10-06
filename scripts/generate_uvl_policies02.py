import os
import yaml
import re


### Special lists for features modified in Kubernetes FM
special_features_config = ['procMount'] ## Pod_spec_..._procMount was String but in FM k8s is Bool with a mandatory subfeature String Pod_spec_..._procMount_nameStr

"""special_feature_mapping = { ## Case 2
    "procMount": "_nameStr",
    "runAsUser": "_valueInt",
    "runAsGroup": "_valueInt"
}"""

def sanitize(name):
    return name.replace("-", "_").replace(".", "_").replace("/", "_").replace(" ", "_").replace("{{", "").replace("}}", "").replace("(", "").replace(")", "")

def clean_description(description: str) -> str:
    return description.replace('\n', ' ') \
                      .replace('`', '') \
                      .replace('´', '') \
                      .replace("'", "_") \
                      .replace('{', '') \
                      .replace('}', '') \
                      .replace('"', '') \
                      .replace("\\", "_") \
                      .replace(".", "") \
                      .replace("//", "_")

def extract_policy_info(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        policy = yaml.safe_load(f)

    metadata = policy.get("metadata", {})
    annotations = metadata.get("annotations", {})
    name = metadata.get("name", "")
    title = annotations.get("policies.kyverno.io/title", name)
    category = annotations.get("policies.kyverno.io/category", "Uncategorized")

    return {
        "name": name,
        "title": title,
        "category": category,
        "description": annotations.get("policies.kyverno.io/description", ""),
        "full_yaml": policy
    }

def extract_uvl_attributes_from_policy(policy: dict) -> str:
    annotations = policy.get("metadata", {}).get("annotations", {})
    spec = policy.get("spec", {})

    # Campos que queremos extraer
    doc = annotations.get("policies.kyverno.io/description", "").replace("'", "\\'")
    severity = annotations.get("policies.kyverno.io/severity", "")
    k8s_version = annotations.get("kyverno.io/kubernetes-version", "")
    action = spec.get("validationFailureAction", "")

    # Formateo en estilo UVL
    attributes = []
    if doc:
        attributes.append(f"doc '{clean_description(doc)}'")
    if severity:
        attributes.append(f"severity '{severity}'")
    if action:
        attributes.append(f"action '{action.lower()}'")
    if k8s_version:
        version_clean = k8s_version.replace(".", "_").replace("-", "‑")  # Usa guiones no separables
        attributes.append(f"k8sRange '{version_clean}'")

    if attributes:
        return f" {{{', '.join(attributes)}}}"
    return ""

def get_kind_prefixes_from_rule(rule: dict) -> list:
    """
    Extrae los prefijos de los kinds especificados en una regla Kyverno.
    Devuelve una lista de strings como: io_k8s_api_core_v1_Pod_
    """
    kinds = rule.get("match", {}).get("any", [{}])[0].get("resources", {}).get("kinds", [])
    return [f"io_k8s_api_core_v1_{sanitize(kind)}_" for kind in kinds]

def build_optional_clause(parent, allowed_values, kind_prefixes):
    """Build the constraint ref '!parent | (parent => val1 | val2 | …)'"""
    if not isinstance(kind_prefixes, list):
        kind_prefixes = [kind_prefixes]
    clauses = []
    #print(f"ALLOWED VALUES  {allowed_values}    {kind_prefixes}")

    for kind_prefix in kind_prefixes:
        allowed_full = [f"Kubernetes.{kind_prefix}{val}" for val in allowed_values]
        allowed_str = " | ".join(allowed_full)
        clause = f"(!Kubernetes.{kind_prefix}{parent} | (Kubernetes.{kind_prefix}{parent} => {allowed_str}))"
        clauses.append(clause)

    return clauses if len(clauses) > 1 else clauses[0]



def handle_annotation_with_wildcard(key: str, value: str, prefix: str):
    """
    Genera pares (feature_path, value) para anotaciones con wildcard (como AppArmor).
    Compatible con el flujo original de extract_constraints_from_policy().
    """
    clean_key = key.strip("=() ").replace("/*", "").replace(".", "_")
    key_feature = f"{prefix}_KeyMap"
    value_feature = f"{prefix}_ValueMap"

    # Dividir valores del patrón tipo "runtime/default | localhost/*"
    values = [v.strip().replace("/*", "").replace(".", "_") for v in value.split("|")]

    pairs = []
    for v in values:
        # Cada valor posible genera dos pares: uno para la clave, otro para el valor
        pairs.append((key_feature, f"'{clean_key}'"))
        pairs.append((value_feature, f"'{v}'"))

    print(f"[Wildcard] Generados {len(pairs)} pares para {clean_key}: {pairs}")
    return pairs


def extract_conditions_from_metadata(obj, prefix="metadata", kind_prefixes=None):
    conditions = []
    optional_clauses = []
    print(f"Kind Prefixes: {kind_prefixes}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            print(f"k y v:  {k} {v}")
            # Subnivel: metadata.annotations
            key = k.strip("=() ")
            new_prefix = f"{prefix}_{key}"
            if key == "annotations" and isinstance(v, dict):
                for subkey, subval in v.items():
                    if "*" in subkey:
                        print(f"If first cas3e:  {subkey}    {subval}")
                        # Caso de anotación con wildcard
                        print(f"Conditions antes  {conditions}")
                        conditions.extend(
                            handle_annotation_with_wildcard(subkey, subval, new_prefix)
                        )
                        print(f"Conditions despues  {conditions}")
                    else: 
                        # Anotación fija (sin wildcard)
                        key_feature = f"{new_prefix}{sanitize(subkey)}"
                        conditions.append((key_feature, f"'{subval}'"))
            else:
                # Otro tipo de clave bajo metadata (p. ej., name, labels)
                #key = k.strip("=() ")
                full_key = f"{prefix}_{sanitize(key)}"
                print(f"Full key else:  {full_key}")
                conditions.append((full_key, f"'{v}'"))
    return conditions, optional_clauses


def extract_constraints_from_policy(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        policy = yaml.safe_load(f)

    metadata = policy.get("metadata", {})
    annotations = metadata.get("annotations", {})
    title = annotations.get("policies.kyverno.io/title", metadata.get("name", ""))
    name = sanitize(title)

    grouped_conditions = {}  # policy_name → list of conditions
    opt_clauses = []
    rules = policy.get("spec", {}).get("rules", [])

    for rule in rules:
        kind_prefixes = get_kind_prefixes_from_rule(rule)
        pattern = rule.get("validate", {}).get("pattern", {})

        #if "spec" in pattern:
        #    conditions, optional_clauses_from_spec = extract_conditions_from_spec(pattern["spec"], prefix="spec", kind_prefixes= kind_prefixes)
        for section_key in pattern:
            clean_key = section_key.strip("=() ")
            if clean_key == "spec":
                extractor = extract_conditions_from_spec
            elif clean_key == "metadata":
                extractor = extract_conditions_from_metadata
            else:
                print(f"⚠️ Sección no soportada aún: {section_key}")
                continue

            conditions, optional_clauses_from_spec = extractor(
                pattern[section_key],
                prefix=clean_key,
                kind_prefixes=kind_prefixes
            )

            for path, expected in conditions:
                for kind_prefix in kind_prefixes:
                    full_feature = f"Kubernetes.{sanitize(kind_prefix + path)}" ## Deff of features from fm Kubernetes
                    if expected == "null":
                        expr = f"!{full_feature}"
                    elif expected in ("true", "false"):
                        expr = f"{full_feature} = {expected}"
                    else:
                        # Si es un número (int o float), usar un único '='
                        if re.match(r"^\d+(\.\d+)?$", str(expected).strip()):
                            expr = f"{full_feature} = {expected}"
                        else:
                            if optional_clauses_from_spec:
                                continue
                            expr = f"{full_feature} == {expected}"
                    grouped_conditions.setdefault(name, []).append(expr)
            # Add the constraints
            #for clause in opt_clauses:
            #    grouped_conditions.setdefault(name, []).append(clause)
            #print(f"Optional clauses {optional_clauses_from_spec}")
            opt_clauses.extend(optional_clauses_from_spec)

    return grouped_conditions, {name: opt_clauses}

def extract_constraints_from_deny_conditions(policy):
    constraints_by_policy = {}
    metadata = policy.get("metadata", {})
    annotations = metadata.get("annotations", {})
    title = annotations.get("policies.kyverno.io/title", metadata.get("name", ""))
    policy_feature = sanitize(title)

    rules = policy.get("spec", {}).get("rules", [])
    for rule in rules:
        deny = rule.get("validate", {}).get("deny", {})
        conditions_block = deny.get("conditions", {})

        if isinstance(conditions_block, dict) and "all" in conditions_block:
            conditions = conditions_block["all"]
        else:
            conditions = conditions_block

        kind_prefixes = get_kind_prefixes_from_rule(rule)

        exprs_by_feature = {}

        for cond in conditions:
            if not isinstance(cond, dict):
                continue

            key = cond.get("key", "")
            operator = cond.get("operator", "")
            values = cond.get("value", [])

            if isinstance(values, str):
                print(f"Valores del value:  {values}")
                values = [values]

            if "spec." in key:
                raw_path = key.split("request.object.")[-1]
                raw_path = raw_path.replace("{{", "").replace("}}", "").strip()
                expanded_paths = expand_path_brackets(raw_path)

                for kind_prefix in kind_prefixes:
                    for path in expanded_paths:
                        sanitized_path = sanitize(path)
                        feature_base = f"Kubernetes.{kind_prefix + sanitized_path}"
                        if feature_base.endswith("_"):
                            feature_base = feature_base[:-1]

                        for v in values:
                            if operator == "AnyNotIn":
                                if isinstance(v, str) and "-" in v:
                                    try:
                                        start, end = v.split("-")
                                        start = int(start) - 1
                                        end = int(end) + 1
                                        condition = f"({feature_base} > {start} & {feature_base} < {end})"
                                    except ValueError:
                                        continue
                                else:
                                    condition = f"{feature_base} = {v}"
                                exprs_by_feature.setdefault(feature_base, []).append(condition)

        # Agroup the expressions by features
        all_exprs = []
        for base, conds in exprs_by_feature.items():
            if len(conds) > 1:
                all_exprs.append(f"({' | '.join(conds)})")
            elif conds:
                all_exprs.append(conds[0])

        if all_exprs:
            if len(all_exprs) > 1:
                combined = f"({' & '.join(all_exprs)})"
            else:
                combined = all_exprs[0]
            constraints_by_policy.setdefault(policy_feature, []).append(combined)

    return constraints_by_policy

def expand_path_brackets(path):
    def expand(p):
        m = re.search(r'\[([^\]]+)\]', p)
        if not m:
            return [p.replace("[]", "")]
        pre = p[:m.start()]
        post = p[m.end():]
        options = [opt.strip() for opt in m.group(1).split(',')]
        expanded = []
        for opt in options:
            expanded += expand(pre + opt + post)
        return expanded

    return expand(path)

def extract_conditions_from_spec(obj, prefix="spec", kind_prefixes = None):
    conditions = []
    optional_clauses = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            #print(f"Key value   {k}   {v}")
            key = k.strip("=() ").replace("X(", "").replace(")", "")
            new_prefix = f"{prefix}_{key}"

            if key in special_features_config: ## Change the special features if procedure
                new_prefix = f"{new_prefix}_nameStr"
                #print(f"New Prefix: {new_prefix}")

            elif new_prefix.endswith('seccompProfile_type'):
                # Este bloque detecta claves como:
                # =(seccompProfile.type): "RuntimeDefault | Localhost"
                if k.startswith("=(") and v and "|" in v:
                    base_feature = new_prefix  # sin los valores
                    allowed_values = []
                    values = [val.strip() for val in v.split("|")]
                    for value in values:
                        clean_val = value.strip()
                        sub_feature = f"{base_feature}_{clean_val}"
                        allowed_values.append(sub_feature)
                        #print(f"ALLOWED VALUES  {allowed_values}")
                        #conditions.append((sub_feature, "true"))  # subfeatures activos

                    # registrar que el campo principal es opcional
                    #optional_clauses.append((base_feature, allowed_values))                  
                    clauses = build_optional_clause(base_feature, allowed_values, kind_prefixes)
                    if isinstance(clauses, list):
                        optional_clauses.extend(clauses)
                    else:
                        optional_clauses.append(clauses)                                     
            
            if isinstance(v, dict):
                #conditions.extend(extract_conditions_from_spec(v, new_prefix))
                child_conditions, child_optional_clauses = extract_conditions_from_spec(v, new_prefix, kind_prefixes)
                conditions.extend(child_conditions)
                optional_clauses.extend(child_optional_clauses)                
            elif isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
                #conditions.extend(extract_conditions_from_spec(v[0], new_prefix))
                child_conditions, child_optional_clauses = extract_conditions_from_spec(v[0], new_prefix, "io_k8s_api_core_v1_Pod_") ## Prevent
                conditions.extend(child_conditions)
                optional_clauses.extend(child_optional_clauses)                
            else:
                if isinstance(v, str):
                    if v.lower() == "false":
                        v = "false"
                    elif v.lower() == "true":
                        v = "true"
                    elif v.strip().lower() == "null":
                        v = "null"
                    elif v.isdigit():
                        v = v  # número como string, no cambiar
                elif isinstance(v, (int, float)):
                    # print(f"SE DETECTA AQUI:Caso Int")
                    v = str(v)
                else:
                    # fallback
                    v = f"'{str(v)}'"
                conditions.append((new_prefix, v))
    return conditions, optional_clauses

def generate_uvl_from_policies(directory, output_path):
    category_map = {}

    for filename in os.listdir(directory):
        if not filename.endswith(".yaml") and not filename.endswith(".yml"):
            continue

        filepath = os.path.join(directory, filename)
        policy = extract_policy_info(filepath)
        #print(f"This is the policy info: {policy}")

        cat = sanitize(policy["category"])
        title = sanitize(policy["title"])
        entry = {
            "name": title,
            "description": policy["description"],
            "raw_policy": policy["full_yaml"]
        }

        category_map.setdefault(cat, []).append(entry)

    #lines = ["namespace PoliciesKyverno", "features", "\tPolicies {abstract}", "\t\toptional"]
    lines = ["namespace Policies", "imports", "    k8s.Kubernetes as Kubernetes", "features", "\tPoliciesKyverno {abstract}", "\t\toptional"]

    for cat, entries in category_map.items():
        lines.append(f"\t\t\t{cat}")
        lines.append("\t\t\t\toptional")
        for e in entries:
            name = e["name"]
            policy = e.get("raw_policy")
            if policy:
                attrs = extract_uvl_attributes_from_policy(policy)
                lines.append(f"\t\t\t\t\t{name}{attrs}")
            else:
                lines.append(f"\t\t\t\t\t{name}")
            #name = e["name"]
            """doc = clean_description(e["description"])
            if doc:
                lines.append(f"\t\t\t\t\t{name} {{doc '{doc}'}}")
            else:
                lines.append(f"\t\t\t\t\t{name}")"""
            
    lines.append("constraints")
    for filename in os.listdir(directory):
        if not filename.endswith(".yaml") and not filename.endswith(".yml"):
            continue

        filepath = os.path.join(directory, filename)
        grouped, optional_clauses = extract_constraints_from_policy(filepath)
        grouped_deny = extract_constraints_from_deny_conditions(yaml.safe_load(open(filepath)))

        merged = {}

        optional_grouped = {}
        optional_grouped = optional_clauses  # ya es un dict con el nombre correcto
    
        for g in [grouped, grouped_deny, optional_grouped]:
            for policy_name, exprs in g.items():
                merged.setdefault(policy_name, []).extend(exprs)

        for policy_name, exprs in merged.items():
            # Reemplazar '= false' por negación
            normalized_exprs = []
            for expr in exprs:
                if expr.endswith("= false"):
                    normalized_exprs.append(f"!{expr.replace(' = false', '')}")
                else:
                    normalized_exprs.append(expr)

            # Concatenar en una sola línea, agrupando con & si es necesario
            if len(normalized_exprs) == 1:
                constraint = normalized_exprs[0]
            else:
                constraint = f"({' & '.join(normalized_exprs)})"

            lines.append(f"\t{policy_name} => {constraint}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"✅ UVL generado: {output_path}")

# Ejemplo de uso
if __name__ == "__main__":
    generate_uvl_from_policies(
        directory="../resources/kyverno_policies_yamls",
        output_path="../variability_model/policies_template/policy_structure02.uvl"
    )