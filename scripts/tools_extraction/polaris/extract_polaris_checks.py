# -*- coding: utf-8 -*-

import os
import csv
import yaml
import re

# =========================
# Carga de FM y Kinds
# =========================

def load_feature_dict(csv_file):
    """
    Carga Midle -> fila completa del CSV de mapping K8s.
    """
    feature_dict = {}
    with open(csv_file, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            feature_dict[row["Midle"]] = row
    return feature_dict


def load_kinds_prefix_mapping(csv_file):
    """
    Carga {Kind -> Prefix}. Ahora mismo no lo usamos mucho porque
    Feature ya viene con el prefijo completo, pero lo dejamos
    por si quieres hacer fallbacks o debug.
    """
    kind_map = {}
    with open(csv_file, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            prefix = row.get("Prefix") or row.get("Version") or ""
            kind_map[row["Kind"]] = prefix
    return kind_map

def resolve_ast_ref(ast, ref: str):
    """
    Resuelve un $ref del estilo "#/$defs/x/y/z" dentro del mismo AST.
    """
    if not ref.startswith("#/"):
        return None

    path = ref[2:].split("/")  # remove "#/"
    node = ast
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node
# =========================
# Helpers de Polaris
# =========================

def normalize_schema_string(schema_string: str) -> str:
    """
    Limpia plantillas Go {{ ... }} de schemaString y deja YAML lo más
    cercano posible a un JSON Schema válido.
    """
    # Elimina bloques de comentarios {{/* ... */}}
    cleaned = re.sub(r"\{\{/\*.*?\*/\}\}", "", schema_string, flags=re.DOTALL)

    # Elimina líneas/fragmentos con {{ ... }}
    cleaned = re.sub(r"\{\{.*?\}\}", "", cleaned, flags=re.DOTALL)

    # Limpia líneas vacías y espacios sobrantes
    cleaned = "\n".join(
        line.rstrip()
        for line in cleaned.splitlines()
        if line.strip()
    )
    return cleaned


def schema_string_to_ast(schema_string: str):
    """
    Convierte un schemaString Polaris (tras limpiar Go templates) en
    un AST (dict) de JSON Schema usando yaml.safe_load.
    """
    try:
        cleaned = normalize_schema_string(schema_string)
        if not cleaned.strip():
            return None
        ast = yaml.safe_load(cleaned)
        if not isinstance(ast, dict):
            return None
        return ast
    except Exception as e:
        print(f"[ERROR] No se pudo parsear schemaString: {e}")
        return None
    

def clean_cap_pattern(pattern: str) -> str:
    """
    Limpia patrones tipo '^(?i)NET_ADMIN$' -> 'NET_ADMIN'
    """
    return (
        pattern.replace("^(?i)", "")
               .replace("(?i)", "")
               .lstrip("^")
               .rstrip("$")
    )

def resolve_ref(root_schema: dict, ref: str):
    """
    Resuelve un $ref del estilo "#/$defs/goodSecurityContext" dentro del JSON Schema.
    """
    if not isinstance(root_schema, dict):
        return None
    if not ref.startswith("#/"):
        return None
    parts = ref[2:].split("/")
    node = root_schema
    for p in parts:
        if p in node:
            node = node[p]
        else:
            return None
    return node


def resolve_target_kinds(check: dict):
    """
    Devuelve lista de Kinds "reales" K8s sobre las que aplica el check.

    Reglas:
      - target: Controller + controllers.include -> los Kinds incluidos (Deployment, StatefulSet, ...)
      - target: PodSpec -> ["Pod"]
      - target: Container + schemaTarget: PodSpec -> ["Pod"]
      - target: Container sin schemaTarget -> ["Container"] (kind lógico abstracto)
      - target: apiGroup/Kind (rbac.authorization.k8s.io/ClusterRole) -> ["ClusterRole"]
      - target simple (Pod, Deployment, ...) -> [target]
    """
    target = check.get("target", "")
    controllers = check.get("controllers", {}) or {}
    schema_target = check.get("schemaTarget", "")

    # Caso especial: Controller
    if target == "Controller":
        include = controllers.get("include") or []
        if include:
            return include

    # PodSpec: se refiere al spec de un Pod
    if target == "PodSpec":
        return ["Pod"]

    # Container + PodSpec: containers dentro de PodSpec (Pod.spec.containers)
    if target == "Container" and schema_target == "PodSpec":
        return ["Pod"]

    # Container sin schemaTarget: lo tratamos como kind abstracto "Container"
    if target == "Container":
        return ["Container"]

    # apiGroup/Kind
    if "/" in target:
        return [target.split("/")[-1]]

    # target directo
    return [target]


def context_kind_for(real_kind: str, check: dict, prop_path: str) -> str:
    """
    Determina el contexto de FM (prefijo Midle) que usaremos para buscar en el CSV.

    Ejemplos:
      - runAsPrivileged (target=Container, schemaTarget=PodSpec) -> "Pod_spec_containers"
      - hostIPCSet       (target=PodSpec)                        -> "Pod_spec"
      - deploymentMissingReplicas (target=Controller + Deployment) -> "Deployment_spec"
      - readinessProbeMissing (target=Container sin schemaTarget)  -> "Container"
    """
    target = check.get("target", "")
    schema_target = check.get("schemaTarget", "")

    # Container + PodSpec → Pod_spec_containers_*
    if real_kind == "Pod" and target == "Container" and schema_target == "PodSpec":
        return f"{real_kind}_spec_containers"

    # PodSpec directo → Pod_spec_*
    if target == "PodSpec" and real_kind == "Pod":
        return f"{real_kind}_spec"

    # Controller + Deployment/StatefulSet/... → <Kind>_spec_*
    if target == "Controller" and real_kind in (
        "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"
    ):
        return f"{real_kind}_spec"

    # Recursos tipo Pod, Deployment,... si el path empieza por spec. → <Kind>_spec
    if prop_path.startswith("spec.") and real_kind in (
        "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"
    ):
        return f"{real_kind}_spec"

    # Container sin schemaTarget → Container_*
    if real_kind == "Container":
        return "Container"

    # ClusterRole, ClusterRoleBinding, Role, RoleBinding, ServiceAccount, etc.
    return real_kind


# =========================
# Extracción de condiciones desde JSON Schema Polaris
# =========================

def extract_conditions_from_schema(schema, prefix="", root_schema=None):
    """
    Extrae condiciones reales de un JSON Schema Polaris.

    Devuelve lista de (prop_path, op, val), p.ej.:
      - ("automountServiceAccountToken", "!=", True)
      - ("spec.replicas", ">=", 2)
      - ("securityContext.allowPrivilegeEscalation", "==", False)
    """
    if root_schema is None:
        root_schema = schema

    conds = []
    if not isinstance(schema, dict):
        return conds

    props = schema.get("properties", {})
    #print(f"Props extraction    {props}")
    # 1) Propiedades directas
    for name, rule in props.items():
        prop_path = f"{prefix}.{name}" if prefix else name
        # $ref → expandir
        if "oneOf" in rule and isinstance(rule["oneOf"], list):
            for option in rule["oneOf"]:
                # Opción simple: contains.pattern
                contains = option.get("contains")
                if isinstance(contains, dict) and "pattern" in contains:
                    literal = clean_cap_pattern(contains["pattern"])
                    conds.append((prop_path, "contains", literal))
                    print(f"Condition with oneOf    {prop_path} {literal}")

                # Opción compuesta: allOf con varios contains
                """if "allOf" in option and isinstance(option["allOf"], list): ## Uncomment if want to use the full insecureCapabilities Strs
                    for sub in option["allOf"]:
                        sub_contains = sub.get("contains")
                        if isinstance(sub_contains, dict) and "pattern" in sub_contains:
                            literal = clean_cap_pattern(sub_contains["pattern"])
                            conds.append((prop_path, "not_contains", literal))
                            print(f"Condition with allOf    {prop_path} {literal}")"""
        if "$ref" in rule:
            resolved = resolve_ref(root_schema, rule["$ref"])
            if resolved:
                conds.extend(
                    extract_conditions_from_schema(resolved, prefix=prop_path, root_schema=root_schema)
                )
            continue
        if "allOf" in rule and isinstance(rule["allOf"], list):
            for entry in rule["allOf"]:
                if (
                    isinstance(entry, dict)
                    and "not" in entry
                    and isinstance(entry["not"], dict)
                    and "contains" in entry["not"]
                ):
                    contains = entry["not"]["contains"]
                    if isinstance(contains, dict) and "pattern" in contains:
                        pattern = contains["pattern"]

                        # Convertir ^(?i)SYS_ADMIN$ → SYS_ADMIN
                        literal = (
                            pattern.replace("^(?i)", "")
                                   .replace("(?i)", "")
                                   .replace("^", "")
                                   .replace("$", "")
                        )

                        conds.append((prop_path, "not_contains", literal))
        # not.const → !=
        if "not" in rule and isinstance(rule["not"], dict) and "const" in rule["not"]:
            conds.append((prop_path, "!=", rule["not"]["const"]))

        # const → ==
        if "const" in rule:
            conds.append((prop_path, "==", rule["const"]))
        # Recursión en arrays: items.properties.hostPort.const
        if rule.get("type") == "array" and "items" in rule:
            conds.extend(
                extract_conditions_from_schema(
                    rule["items"], prefix=prop_path, root_schema=root_schema
                )
            )
        # pattern
        if "pattern" in rule:
            conds.append((prop_path, "matches", rule["pattern"]))

        # not.pattern
        if "not" in rule and isinstance(rule["not"], dict) and "pattern" in rule["not"]:
            conds.append((prop_path, "not matches", rule["not"]["pattern"]))

        # mínimo numérico (p.ej. replicas >= 2)
        if "minimum" in rule:
            conds.append((prop_path, ">=", rule["minimum"]))

        # Recursión en sub-propiedades
        if "properties" in rule:
            conds.extend(
                extract_conditions_from_schema(rule, prefix=prop_path, root_schema=root_schema)
            )

    # 2) required → != null
    """if "required" in schema and isinstance(schema["required"], list):
        for req in schema["required"] and not :
            prop_path = f"{prefix}.{req}" if prefix else req
            conds.append((prop_path, "!=", None))"""

    # 3) anyOf / allOf
    for key in ("anyOf", "allOf"):
        if key in schema and isinstance(schema[key], list):
            for block in schema[key]:
                conds.extend(
                    extract_conditions_from_schema(block, prefix=prefix, root_schema=root_schema)
                )
   
    return conds

def extract_semantic_conditions_from_ast(ast, prefix="", result=None, root_ast=None):
    """
    Extrae condiciones semánticas desde el AST de un schemaString.

    Devuelve una lista que puede contener:
      - Tuplas simples:   (prop_path, op, val)
      - Marcadores OR:    ("__OR__", [ [conds_branch1], [conds_branch2], ... ])

    Donde cada conds_branch es una lista de tuplas (prop_path, op, val).
    """
    if result is None:
        result = []
    if root_ast is None:
        root_ast = ast

    if not isinstance(ast, dict):
        return result
    if "$ref" in ast:
        resolved = resolve_ast_ref(root_ast, ast["$ref"])
        if resolved:
            extract_semantic_conditions_from_ast(resolved, prefix, result, root_ast=root_ast)
    # 1) PROPERTIES: recursión por subcampos
    if "properties" in ast and isinstance(ast["properties"], dict):
        for prop, rule in ast["properties"].items():
            new_prefix = f"{prefix}.{prop}" if prefix else prop
            extract_semantic_conditions_from_ast(rule, new_prefix, result, root_ast=root_ast)

    # 2) Const / not / pattern / contains / minimum en el nodo actual
    if "pattern" in ast:
        result.append((prefix, "matches", ast["pattern"]))

    if "const" in ast:
        result.append((prefix, "==", ast["const"]))

    if "minimum" in ast:
        result.append((prefix, ">=", ast["minimum"]))

    # contains (ej. array contains elementos que matchean un patrón)
    if "contains" in ast and isinstance(ast["contains"], dict):
        if "pattern" in ast["contains"]:
            result.append((prefix, "contains", ast["contains"]["pattern"]))

    # not con const / pattern / contains
    if "not" in ast and isinstance(ast["not"], dict):
        not_block = ast["not"]
        if "const" in not_block:
            result.append((prefix, "!=", not_block["const"]))
        if "pattern" in not_block:
            result.append((prefix, "not matches", not_block["pattern"]))
        if "contains" in not_block and isinstance(not_block["contains"], dict):
            if "pattern" in not_block["contains"]:
                result.append((prefix, "not_contains", not_block["contains"]["pattern"]))

    # 3) anyOf → lista de alternativas (OR)
    if "anyOf" in ast and isinstance(ast["anyOf"], list):
        branches = []
        for option in ast["anyOf"]:
            branch_conds = []
            extract_semantic_conditions_from_ast(option, prefix, branch_conds, root_ast=root_ast)
            if branch_conds:
                branches.append(branch_conds)
        if branches:
            result.append(("__OR__", branches))

    # 4) allOf → AND de bloques (simplemente recursión)
    if "allOf" in ast and isinstance(ast["allOf"], list):
        for block in ast["allOf"]:
            extract_semantic_conditions_from_ast(block, prefix, result, root_ast=root_ast)

    return result


# =========================
# Búsqueda de Feature en FM usando Midle
# =========================

def find_feature(context_kind: str, prop_path: str, feature_dict: dict):
    """
    Dado:
      - context_kind: 'Pod_spec', 'Pod_spec_containers', 'Container', 'Deployment_spec', ...
      - prop_path:    'hostIPC', 'automountServiceAccountToken',
                      'spec.replicas', 'securityContext.allowPrivilegeEscalation'

    construye un Midle candidato y lo busca en el FM.

    Estrategia:
      1) match exacto:  <context>_<prop_key>
      2) suffix igual
      3) suffix que termina en "_" + prop_key
      4) fallback: cualquier Midle de ese contexto que contenga prop_key
    """
    prop_key = prop_path.replace(".", "_")
    exact_midle = f"{context_kind}_{prop_key}"

    # 1) match exacto
    if exact_midle in feature_dict:
        return feature_dict[exact_midle]

    candidates_equal = []
    candidates_suffix = []
    fallback = []

    for midle, row in feature_dict.items():
        if not midle.startswith(context_kind + "_"):
            continue
        suffix = midle[len(context_kind) + 1 :]  # quitar "<context>_"

        if suffix == prop_key:
            candidates_equal.append(row)
        elif suffix.endswith("_" + prop_key):
            candidates_suffix.append(row)
        elif prop_key in suffix:
            fallback.append(row)

    if candidates_equal:
        # el más corto suele ser el más directo
        return min(candidates_equal, key=lambda r: len(r["Midle"]))

    if candidates_suffix:
        return min(candidates_suffix, key=lambda r: len(r["Midle"]))

    if fallback:
        return min(fallback, key=lambda r: len(r["Midle"]))

    return None


# =========================
# Parser de checks Polaris
# =========================

def parse_polaris_check(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        return None

    schema = data.get("schema") or {}
    if not schema and "schemaString" in data:
        try:
            schema = yaml.safe_load(data["schemaString"])
        except Exception:
            schema = {}

    return {
        "id": os.path.basename(path).replace(".yaml", ""),
        "category": data.get("category", ""),
        "target": data.get("target", ""),
        "schemaTarget": data.get("schemaTarget", ""),
        "controllers": data.get("controllers", {}),
        "schema": schema,
        "schemaString": data.get("schemaString", ""),
        "success": data.get("successMessage", ""),
        "failure": data.get("failureMessage", ""),
    }


# =========================
# Construcción de expresiones UVL
# =========================

def build_uvl_expr(kind_name: str, feature: str, op: str, val):
    full_feature = f"{kind_name}.{feature}"

    if op == "==":
        #print(f"full feature ===    {full_feature}  op  {op}    {kind_name}")
        if isinstance(val, bool):
            return full_feature if val else f"!{full_feature}"
        
        if isinstance(val, (int,float)):
            return f"{full_feature} == {val}"
        
        if val is None:
            return f"{full_feature} == null"
        if full_feature.endswith('securityContext_procMount'):
            return f"({full_feature}_StringValue == '{val}')"
        
        return f"{full_feature} == '{val}'"

    if op == "!=":
        print(f"full feature    {full_feature}  op  {op}    {kind_name} {val}")
        if isinstance(val, bool):
            return f"!{full_feature}" ## {str(val).lower()}
        elif isinstance(val, str) and val == 'null':
            return f"{full_feature} != null"""
        if val is None:
            return f"{full_feature}"
        if full_feature.endswith('securityContext_seccompProfile_type'):
                if val == 'Unconfined':
                    return f"{full_feature}_Unconfined"
                #return f"({full_feature}_StringValue == '{val}')"
    
    if op == ">=": ## differences between our modify model :: _valueInt **
        return f"{full_feature} > {val}"

    if op == "matches":
        return f"{full_feature} matches '{val}'"
    ##not_contains
    if op == "not matches":
            return f"!({full_feature} matches '{val}')"
    
    if op == "contains":
        # Convención: para arrays tipo capabilities_drop
        if full_feature.endswith("capabilities_drop"):
            return f"({full_feature}_StringValue == '{val}')"
        return f"({full_feature} == '{val}')"

    if op == "not_contains":
        if full_feature.endswith("capabilities_add"):
            return f"({full_feature}_StringValue != '{val}')"
        return f"({full_feature} != '{val}')"
    # Fallback genérico
    return f"{full_feature} {op} '{val}'"


def map_semantic_conds_to_uvl(check, semantic_conds, feature_dict, kind_map):
    """
    Convierte la lista de condiciones semánticas (incluyendo OR-groups)
    en una única expresión UVL para este check.

    Usa:
      - target del check para elegir contexto (Container, Pod, etc.)
      - find_feature(kind_context, prop_path, feature_dict)
      - build_uvl_expr(real_kind, fm_feature, op, val)
    """
    from collections import OrderedDict

    # Resolver Kind real (ej. "Container", "Pod", "ClusterRoleBinding"...)
    # Aquí usamos una aproximación simple y reutilizamos el target.
    real_kind = check["target"]
    if "/" in real_kind:
        # rbac.authorization.k8s.io/ClusterRoleBinding → ClusterRoleBinding
        real_kind = real_kind.split("/")[-1]

    kind_name = real_kind  # usado en la parte "Kind." de UVL
    context_kind = real_kind  # usado para buscar en el FM

    all_simple_exprs = []   # AND global (fuera de OR groups)
    all_or_groups = []      # cada OR group es algo tipo "(expr1 and expr2) or (expr3)"

    for cond in semantic_conds:
        # OR-group: ("__OR__", [ [ (path,op,val)... ], [ ... ] ])
        if isinstance(cond, tuple) and len(cond) == 2 and cond[0] == "__OR__":
            branches = cond[1]
            branch_exprs = []
            for branch in branches:
                local_exprs = []
                for path, op, val in branch:
                    row = find_feature(context_kind, path, feature_dict)
                    if not row:
                        print(f"    ⚠ No FM match for Context={context_kind}, prop={path}")
                        continue
                    fm_feature = row["Feature"]
                    uvlexpr = build_uvl_expr(kind_name, fm_feature, op, val)
                    if uvlexpr:
                        local_exprs.append(uvlexpr)
                if local_exprs:
                    # dentro de una rama OR, juntamos con AND
                    branch_exprs.append("(" + " & ".join(OrderedDict.fromkeys(local_exprs)) + ")")
            if branch_exprs:
                # OR entre ramas
                or_expr = " or ".join(branch_exprs)
                all_or_groups.append(or_expr)
            continue

        # Condición simple: (path, op, val)
        if isinstance(cond, tuple) and len(cond) == 3:
            path, op, val = cond
            row = find_feature(context_kind, path, feature_dict)
            if not row:
                print(f"No FM match for Context={context_kind}, prop={path}")
                continue
            fm_feature = row["Feature"]
            uvlexpr = build_uvl_expr(kind_name, fm_feature, op, val)
            if uvlexpr:
                all_simple_exprs.append(uvlexpr)
            continue

    # Eliminar duplicados preservando orden
    all_simple_exprs = list(OrderedDict.fromkeys(all_simple_exprs))
    all_or_groups = list(OrderedDict.fromkeys(all_or_groups))

    if not all_simple_exprs and not all_or_groups:
        return None

    # Construcción final de la constraint:
    #   (simple1 & simple2) & ( (branch1) or (branch2) )
    pieces = []
    if all_simple_exprs:
        pieces.append(" & ".join(all_simple_exprs))
    if all_or_groups:
        pieces.append(" & ".join(all_or_groups))

    if len(pieces) == 1:
        return pieces[0]
    return " & ".join(pieces)


# =========================
# Polaris → UVL usando FM
# =========================

def polaris_to_uvl(check, feature_dict, kind_map):
    #print(f"\nCheck: {check['id']}")
    #print(f"Doc {check['failure']}")
    # 0) Resolver Kinds reales sobre los que aplica
    real_kinds = resolve_target_kinds(check)

    # 1) Si hay schemaString → usar parser semántico nuevo
    if check.get("schemaString"):
        ast = schema_string_to_ast(check["schemaString"])
        if not ast:
            print("schemaString sin AST -> skip")
            return None

        semantic_conds = extract_semantic_conditions_from_ast(ast, prefix="", result=None, root_ast=ast)
        if not semantic_conds:
            print("schemaString sin condiciones semánticas -> skip")
            return None

        constraint_expr = map_semantic_conds_to_uvl(check, semantic_conds, feature_dict, kind_map)
        if not constraint_expr:
            print("No se pudo mapear semantic_conds a FM -> skip")
            return None
        
        feature_name = check["id"].replace("-", "_")
        feature_block = (
            f"{feature_name} {{"
            f"tool 'Polaris', "
            f"category '{check['category']}', "
            f"doc '{check['failure']}', "
            f"}}"
        )
        constraint = f"{feature_name} => {constraint_expr}"
        return feature_block, constraint

    # 2) Extraer condiciones del schema
    conds = extract_conditions_from_schema(check["schema"])
    if not conds:
        print("Sin condiciones mapeables → skip")
        return None

    feature_name = check["id"].replace("-", "_")
    feature_block = (
        f"{feature_name} {{doc '{check['failure']}', tool 'Polaris', category '{check['category']}'}}"
    )

    all_parts = []

    for real_kind in real_kinds:
        for prop_path, op, val in conds:
            print(f"  Prop path   {prop_path}  ({op} {val})   real_kind={real_kind}")
            context_kind = context_kind_for(real_kind, check, prop_path)
            fm_row = find_feature(context_kind, prop_path, feature_dict)

            if not fm_row:
                print(f"No FM match for Context={context_kind}, prop={prop_path}")
                continue

            feature = fm_row["Feature"]

            if feature.endswith("_runAsUser") and str(val).isdigit(): ## 
                #feature = f"{feature}_valueInt"
                print(f"CONTINUE, case invalid with feat const integer")
                continue
            expr = build_uvl_expr(real_kind, feature, op, val)
            
            print(f"Expresiones add {expr}  {val}")
            all_parts.append(expr)

    if not all_parts:
        print("Ninguna condición mapeada a FM, se omite este check.")
        return None

    # Opcional: aquí podrías quitar duplicados si quieres
    # all_parts = list(dict.fromkeys(all_parts))

    if feature_name == "runAsRootAllowed": ## Unnused
        # Caso especial: Usamos OR (|)
        joined_parts = " | ".join([f"{part}" for part in all_parts])
    else:
        # Caso por defecto: Usamos AND (&)
        joined_parts = " & ".join(all_parts)

    """if feature_name == "insecureCapabilities" and joined_parts.count(" & ") >= 1: ## Uncomment if want to use the full insecureCapabilities Strs
        joined_parts = joined_parts.replace(" & ", " | ", 1)"""

    constraint = f"{feature_name} => {joined_parts}"    
    #constraint = f"{feature_name} => " + " & ".join(all_parts)
    print(f"Constraint  {constraint}")
    return feature_block, constraint

# =========================
# MAIN de prueba
# =========================

if __name__ == "__main__":
    FEATURES_CSV = "../resources/mapping_csv/kubernetes_mapping_properties_features.csv"
    KINDS_CSV    = "../resources/mapping_csv/kubernetes_kinds_versions_detected.csv"
    POLARIS_DIR  = "../resources/Polaris-checks"

    feature_dict = load_feature_dict(FEATURES_CSV)
    kind_map = load_kinds_prefix_mapping(KINDS_CSV)

    results = []

    for root, _, files in os.walk(POLARIS_DIR):
        for f in files:
            if not f.endswith(".yaml"):
                continue
            full_path = os.path.join(root, f)
            check = parse_polaris_check(full_path)
            if not check:
                continue
            uv = polaris_to_uvl(check, feature_dict, kind_map)
            if uv:
                results.append(uv)

    print("\n\n### FINAL RESULTS ###\n")
    for fb, cons in results:
        print(fb)
        print(cons)
        print("-" * 80)