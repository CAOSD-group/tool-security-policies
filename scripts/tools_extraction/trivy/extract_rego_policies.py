import csv
from collections import defaultdict

import re
import yaml

from tools_extraction.extract_policies_general import (
    clean_description,
    get_base_prefix,
    load_feature_dict,
    load_kinds_prefix_mapping,
    normalize_kind_name
)

def build_field_map(csv_path):
    field_map = defaultdict(list)

    with open(csv_path) as f:
        reader = csv.DictReader(f)

        for row in reader:
            # Ex: Detect feature using the FM mapping
            semantic_key = row["feature_name"]  # p.ej.: securityContext.capabilities.add // We need to take account the rest of the part of the features using the comments Kinds
            field_map[semantic_key].append(row["feature_path"])

    return field_map

def normalize_rego_path(rego_path):
    # Eliminamos prefijos comunes en Trivy y Kyverno
    prefixes = ["allContainers.", "kubernetes.containers.", "kubernetes.object.", "container.", "kubernetes."]
    for p in prefixes:
        if rego_path.startswith(p):
            print(f"Normalizing Rego path: Removing prefix  {rego_path}  from prefix {p}")
            rego_path = rego_path.replace(p, "")
            
    # También limpiamos el índice [_] si llega hasta aquí
    rego_path = rego_path.replace("[_]", "")
    return rego_path

def severity_to_weight(sev: str) -> float:
    """Convierte una severidad de Kyverno a un peso numérico."""
    sev = (sev or "").strip().lower()
    if sev == "high":
        return 1.0
    if sev == "medium":
        return 0.7
    return 0.5  # default o cualquier otro valor

def find_uvl_path_for_rego(kind, rego_path, feature_dict, kind_map, operator=None, expected_value=None): ## feature_dictç
    #print(f"Features dictss {feature_dict}")
    #kind_cap = kind.capitalize()
    real_kind = normalize_kind_name(kind, kind_map)
    #rego_key = rego_path.replace(".", "_")  # container.securityContext.capabilities.add
    rego_key = normalize_rego_path(rego_path).replace(".", "_")

    # Buscar las coincidencias en el diccionario
    candidates = []

    # 1. Definimos los "ámbitos" que nos interesan buscar
    # 'default' es para propiedades del Pod (hostPID, etc.)
    # Los otros son para propiedades de contenedores
    scope_buckets = {
        "default": [],
        "containers": [],
        "initContainers": [],
        "ephemeralContainers": []
    }

    markers = {
        "containers": "_containers_",
        "initContainers": "_initContainers_",
        "ephemeralContainers": "_ephemeralContainers_"
    }
    found_any = False
# 2. Búsqueda y Clasificación
    for midle, row in feature_dict.items():
        # Filtro básico: Debe ser del Kind correcto y contener la clave Rego
        if midle.startswith(real_kind + "_") and rego_key in midle:
            found_any = True
            
            # Clasificamos en el bucket correcto
            assigned_scope = "default"
            for scope, marker in markers.items():
                if marker in midle:
                    assigned_scope = scope
                    break
            
            scope_buckets[assigned_scope].append(row)

    if not found_any:
        return [] # Devolvemos lista vacía en lugar de None

    results = []

    ### New aux function to select the best candidate within a bucket based on specificity
    def select_best_candidate(candidates_list, key, op, val):
        """
        Selecciona el mejor candidato basándose en el valor esperado:
        - Si es existencia o booleano -> Prioriza el nodo exacto (Padre).
        - Si es un número -> Prioriza _valueInt.
        - Si es un string específico -> Prioriza _StringValue.
        """
        val_str = str(val).strip().lower()

        # ESTRATEGIA 1: Comprobación de existencia (EXISTS) o booleanos puros.
        # Queremos prohibir/requerir el bloque completo, no sus hojas.
        if op == "EXISTS" or val_str in ["true", "false", "null", ""]:
            exact_matches = [c for c in candidates_list if c["Midle"].endswith(key) or c["Midle"].endswith(f"_{key}")]
            if exact_matches:
                return min(exact_matches, key=lambda r: len(r["Midle"]))
            return min(candidates_list, key=lambda r: len(r["Midle"]))

        # ESTRATEGIA 2: Comparación contra un valor específico.
        # Determinamos qué sufijo primitivo buscar.
        target_suffixes = []
        if val_str.isdigit():
            target_suffixes.append(f"{key}_valueInt")
        else:
            target_suffixes.append(f"{key}_StringValue")

        # Prioridad 2A: Buscar la hoja del tipo específico
        type_matches = [c for c in candidates_list if any(c["Midle"].endswith(suffix) for suffix in target_suffixes)]
        if type_matches:
            return min(type_matches, key=lambda r: len(r["Midle"]))

        # Prioridad 2B: Fallback a la coincidencia exacta si no existe la hoja tipada
        exact_matches = [c for c in candidates_list if c["Midle"].endswith(key) or c["Midle"].endswith(f"_{key}")]
        if exact_matches:
            return min(exact_matches, key=lambda r: len(r["Midle"]))

        # Prioridad 2C: Fallback de seguridad al más corto
        return min(candidates_list, key=lambda r: len(r["Midle"]))
    # ----------------------------------------------------

    # 3. Selección de Ganadores (Fan-Out)
    # Verificamos si encontramos propiedades de contenedores
    container_matches = any(scope_buckets[k] for k in markers)

    if container_matches:
        # CASO A: Es una propiedad de contenedor (ej: securityContext, image, env)
        # Devolvemos el mejor candidato de CADA tipo de contenedor que exista
        for scope in markers:
            candidates = scope_buckets[scope]
            if candidates:
                # Elegimos la más específica (path más largo) dentro de su categoría
                #best = max(candidates, key=lambda r: len(r["Midle"]))
                best = select_best_candidate(candidates, rego_key, operator, expected_value)
                is_list = (best["Value"] == "-")
                results.append((best["Feature"], is_list, best["Value"]))
    else:
        # CASO B: Es una propiedad global del Pod (ej: hostPID, restartPolicy)
        # Solo miramos el bucket default
        candidates = scope_buckets["default"]
        if candidates:
            #best = max(candidates, key=lambda r: len(r["Midle"]))
            best = select_best_candidate(candidates, rego_key , operator, expected_value)
            is_list = (best["Value"] == "-")
            results.append((best["Feature"], is_list, best["Value"]))

    return results
    

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
    #print("Custom:", custom)
    if not isinstance(custom, dict):
        custom = {}

    # extract types
    kinds = []
    has_kubernetes_type = False

    selectors = (
        custom.get("input", {}).get("selector", [])
        if "input" in custom
        else []
    )

    for sel in selectors:
        # Detectamos si es una regla genérica de Kubernetes
        if sel.get("type") == "kubernetes":
            has_kubernetes_type = True

        subtypes = sel.get("subtypes", [])
        for item in subtypes:
            if isinstance(item, dict) and "kind" in item:
                kinds.append(item["kind"].lower())
    # Si es de tipo kubernetes pero no definió kinds explícitos se asume el subconjunto de Workloads estándar
    if has_kubernetes_type and not kinds:
        kinds = [ "pod", "replicaset", "replicationcontroller", 
            "deployment", "deploymentconfig", "statefulset", 
            "daemonset", "cronjob", "job"]
    return {
        "title": meta_yaml.get("title", ""),
        "description": meta_yaml.get("description", ""),
        "severity": custom.get("severity", ""),
        "id": custom.get("id", ""),
        "short_code": custom.get("short_code", custom.get("long_id", "no_short_code")),
        "recommended_action": custom.get("recommended_action", ""),
        "kinds": sorted(set(kinds)),
    }


def extract_conditions_from_rego(rego_text, recommended_action="", field_map=None):
    #print(f"MATCHES NONE {matches_str}")
    conditions = []
    cond_text = recommended_action.replace('"', "'")

    # Regex 1: Cadenas de texto con comillas (ej: == "SYS_MODULE")
    #pat_str = re.compile(r'(\S+?)\s*(==|!=)\s*"([^"]+)"')
    pat_str = re.compile(r'(\S+?)\s*(==|!=)\s*"([^"]+)"')
    for field, op, value in pat_str.findall(rego_text):
        #field = field.replace("[_]", "")
        field = re.sub(r'\[.*?\]', '', field) # Limpiamos cualquier índice [_], [*], []
        # IGNORAR campos de metadatos que no son features de la arquitectura
        if "kubernetes.kind" in field or "kubernetes.api_version" in field:
            continue
        conditions.append({"field": field, "operator": op, "value": value})
        
    # Regex 2: Booleanos y null sin comillas (ej: == false, == true)
    #pat_bool = re.compile(r'(\S+?)\s*(==|!=)\s*(true|false|null)\b')
    pat_bool = re.compile(r'(\S+?)\s*(==|!=)\s*(true|false|null)\b')
    for field, op, value in pat_bool.findall(rego_text):
        field = re.sub(r'\[.*?\]', '', field) #field = field.replace("[_]", "")
        if "kubernetes.kind" in field:
            continue
        conditions.append({"field": field, "operator": op, "value": value})
    
    # Regex 3: Números (enteros) directamente en el código Rego (ej: runAsGroup == 0)
    pat_num = re.compile(r'([a-zA-Z0-9_\.\[\]]+)\s*(==|!=|<=|>=|<|>)\s*(\d+)') 
    for field, op, value in pat_num.findall(rego_text):
        # Filtramos variables locales aisladas (ej. 'gid'). Las rutas reales de K8s suelen tener puntos.
        if "." in field:
            field = field.replace("[_]", "").replace("[*]", "")
            print(f"Numeric condition found - Field: {field}, Operator: {op}, Value: {value}")
            if value.isdigit() and op == "==": ## to a non-zero integer or leave undefined.
                # Interpretamos "field == 0" como "field > 0" para evitar falsos positivos de igualdad a cero
                op = ">"
            conditions.append({"field": field, "operator": op, "value": value})
            print(f"Added numeric condition: {conditions[-1]}")
    
    # Regex 4: Detección semántica de 'utils.has_key'
    # Trivy lo usa muchísimo para ver si una propiedad existe (ej: volumes, hostPath)
    has_key_pat = re.findall(r'has_key\(([^,]+),\s*"([^"]+)"\)', rego_text)
    for obj, prop in has_key_pat:
        obj_clean = re.sub(r'\[.*?\]', '', obj).split('.')[-1]
        # Solo consideramos objetos raíz conocidos para evitar ruido de variables locales
        if obj_clean in ["container", "containers", "spec", "volumes", "securityContext", "template", "capabilities"]:
            conditions.append({"field": f"{obj_clean}.{prop}", "operator": "EXISTS", "value": "true"})
    
    # Regex 5: Detección de Conjuntos y operador 'in' (RBAC y Listas Negras como KSV-0122/0123)
    set_vars = {}
    for var_name, values in re.findall(r'([a-zA-Z0-9_]+)\s*:=\s*\{([^}]+)\}', rego_text):
        clean_values = [v.strip().strip('\'" \n\t') for v in values.split(',')]
        set_vars[var_name] = clean_values

    in_patterns = re.findall(r'([a-zA-Z0-9_\.\[\]]+)\s+in\s+([a-zA-Z0-9_]+)', rego_text)
    for field_match, var_name in in_patterns:
        # Añade esta línea para ignorar la variable del bucle de KSV-0039
        if var_name == "required_fields":
            continue
        if var_name in set_vars:
            field_clean = re.sub(r'\[.*?\]', '', field_match)
            if "kubernetes.kind" not in field_clean: 
                for val in set_vars[var_name]:
                    # Para UVL, estar en una lista negra significa que debe ser distinto (!=) a cada valor
                    #if 'capabilities.drop' in field_clean:
                    #    conditions.append({"field": field_clean, "operator": "!=", "value": val})
                    #else:
                    conditions.append({"field": field_clean, "operator": "==", "value": val})
                    print(f"Added RBAC/Set condition: {conditions[-1]}")

    # Regex 6: Detección de bucles sobre 'required_fields' (Caso LimitRange KSV-0039)
    req_fields_match = re.search(r'required_fields\s*:=\s*\{([^}]+)\}', rego_text)
    if req_fields_match and 'kubernetes.has_field' in rego_text:
        fields = [f.strip().strip('\'" \n\t') for f in req_fields_match.group(1).split(',')]
        for f in fields:
            if f:
                conditions.append({"field": f"limits.{f}", "operator": "EXISTS", "value": "true"})
                print(f"Added LimitRange condition: {conditions[-1]}")
    
    # Regex 7: Detección de Arrays multidilínea (Caso Volúmenes KSV-0028)
    # Busca bloques como: disallowed_volume_types := [ "nfs", "iscsi", ... ]
    array_blocks = re.findall(r'([a-zA-Z0-9_]+)\s*:=\s*\[(.*?)\]', rego_text, re.DOTALL)
    for var_name, values in array_blocks:
        # Limpiamos saltos de línea, comillas y comas
        clean_values = [v.strip().strip('\'" \n\t,') for v in values.split('\n') if v.strip() and not v.strip().startswith("#")]
        clean_values = [v for v in clean_values if v]
        
        # Si el array se usa para iterar claves prohibidas (ej. has_key(volume, type))
        if 'has_key' in rego_text and ('disallowed' in var_name.lower() or 'volume' in var_name.lower()):
            for val in clean_values:
                # Añadimos cada volumen a la lista. El intent (PROHIBITION) se encargará de ponerles el '!' a todos.
                conditions.append({"field": f"volumes.{val}", "operator": "EXISTS", "value": "true"})
    
    # Extraer propiedades desde texto si no hay condiciones detectadas
    if not conditions and recommended_action:
        #print(f"reccomended {recommended_action}")
        # Esta regex atrapa rutas completas anidadas, permitiendo puntos, asteriscos y corchetes.
        # Capturará perfectamente: "spec.containers[*].ports[*].hostPort"
        prop_pat = re.findall(r'\b(?:spec|containers|initContainers|ephemeralContainers|volumes)(?:\.[a-zA-Z0-9_\[\]\*]+)+\b', cond_text)
        
        rego_prop_pat = re.findall(r'kubernetes\.object\.(spec(?:\.[a-zA-Z0-9_\[\]\*]+)+)', rego_text)
        
        all_props = set(prop_pat + rego_prop_pat)
        
        for prop in all_props:
            # Limpiamos todos los [*] y [_] para que quede un path limpio: 'spec.containers.ports.hostPort'
            prop_clean = re.sub(r'\[.*?\]', '', prop)
            
            # Lo marcamos con EXISTS y "true" para que el 'intent' detecte la prohibición
            conditions.append({"field": prop_clean, "operator": "EXISTS", "value": "true"})
    
    # Salvavidas de seguridad específico para puertos host si todo lo demás falla
    """if not any("hostPort" in c["field"] for c in conditions):
        if re.search(r'\bports\[.*?\]\.hostPort\b', rego_text):
            conditions.append({"field": "ports.hostPort", "operator": "EXISTS", "value": "true"})
        
        prop_pat_container = re.findall(r"'(containers[.\w\[\]]+)'", cond_text)
        #prop_pat_container = re.findall(r"['\"](containers(?:\[\]\.|[\w\.\[\]]+)*)['\"]", cond_text)
        #print(f"Prop pat  DUPLICADO EN RECCOMENDED  {prop_pat_container}")
        if prop_pat_container and ('>' not in cond_text and '<' not in cond_text):
            for prop01 in prop_pat_container:
                # Si el texto dice "to true" => interpretamos que queremos != true
                val = "true" if "true" in cond_text.lower() else "false"
                field_name = prop01.replace("containers[].","").replace("containers[*].","")
                conditions.append({"field": field_name, "operator": "==", "value": val}) """
    # Regex para números enteros (ej: ... <= 10000)
    # \d+ captura uno o más dígitos
    #pat_num = re.compile(r'(\S+?)\s*(==|!=|<=|>=|<|>)\s*(\d+)\b')
    pat_num = re.compile(r"'(containers[.\w\[\]\*]+)'[^<>=]+(==|!=|<=|>=|<|>)\s*(\d+)")
    matches_num = pat_num.findall(cond_text)
    if matches_num:
        for field, op, value in matches_num:
                val = ">" if ">" in cond_text.lower() else "<"
                field_name = field.replace("containers[].","").replace("containers[*].","")
                conditions.append({"field": field_name, "operator": val, "value": value, # El valor es un string '10000'
                })

    # Si aún no hay condiciones, buscar rutas de 'msg' en el código
    if not conditions:
        msg_pat = re.findall(r"'(spec[.\w\[\]]+)'", rego_text)
        print(f"Prop pat    {msg_pat}")
        for prop in msg_pat:
            conditions.append({"field": prop, "operator": "==", "value": "true"})

    # Detect hostPort usage: ports[_].hostPort
    hostport_pat = re.compile(r'\bports\[_?\]\.hostPort\b|\bports\[\*\]\.hostPort\b')

    if hostport_pat.search(rego_text):
        conditions.append({
            "field": "container.ports.hostPort",
            "operator": "EXISTS",
            "value": ""  # not needed
        })

    # ==================================================================================
    # NUEVO: OVERRIDE VALIDADO CON AUTO-EXPANSIÓN DE CONTENEDORES (FAN-OUT INTELIGENTE)
    # ==================================================================================
    
    clean_cond_text = re.sub(r'\[.*?\]', '', cond_text)
    canon_props = re.findall(r'\b(?:spec|containers|initContainers|ephemeralContainers|volumes|securityContext)(?:\.[a-zA-Z0-9_]+)+\b', clean_cond_text)

    valid_paths = set() # Usamos un Set para evitar duplicados
    
    if canon_props and field_map:
        for raw_path in canon_props:
            proposed_uvl_path = raw_path.replace('.', '_')
            
            # Comprobamos si la ruta original existe en el modelo
            if any(proposed_uvl_path in model_key for model_key in field_map.keys()):
                valid_paths.add(proposed_uvl_path)
                print(f"[MODEL MATCH] Confirmado: La ruta '{proposed_uvl_path}' existe.")
                
                # EL TRUCO DEL FAN-OUT: Si la política menciona 'containers' pero el humano 
                # se olvidó de los demás, clonamos la ruta y preguntamos al modelo si existen.
                if "containers_" in proposed_uvl_path or proposed_uvl_path.startswith("containers_"):
                    
                    # Generamos los clones sintácticos
                    init_path = proposed_uvl_path.replace("_containers_", "_initContainers_")
                    if init_path == proposed_uvl_path: # Por si empezaba directamente por containers_
                        init_path = proposed_uvl_path.replace("containers_", "initContainers_")
                        
                    eph_path = proposed_uvl_path.replace("_containers_", "_ephemeralContainers_")
                    if eph_path == proposed_uvl_path:
                        eph_path = proposed_uvl_path.replace("containers_", "ephemeralContainers_")

                    # Validamos los clones contra el Oráculo (HKFM)
                    if any(init_path in model_key for model_key in field_map.keys()):
                        valid_paths.add(init_path)
                        print(f"[FAN-OUT AUTO] Añadida ruta clonada para InitContainers: '{init_path}'")
                        
                    if any(eph_path in model_key for model_key in field_map.keys()):
                        valid_paths.add(eph_path)
                        print(f"[FAN-OUT AUTO] Añadida ruta clonada para EphemeralContainers: '{eph_path}'")

    # 3. Reescribimos las condiciones, expandiendo si hay múltiples rutas válidas
    # 3. REESCRITURA CON ESCUDO SEMÁNTICO DINÁMICO (Sin listas estáticas)
    # ==================================================================================
    new_conditions = []
    
    # Preparamos un "vocabulario" dinámico extrayendo las palabras de las rutas validadas
    # Ej: de ['spec_containers_ports'] extrae {'spec', 'containers', 'ports'}
    paths_string = "_".join(valid_paths).lower()
    paths_words = set(re.findall(r'[a-zA-Z]+', paths_string))

    for c in conditions:

        norm_field = normalize_rego_path(c["field"]) ## Normalizes before checking existence in the model, to increase chances of matching
        field_as_uvl = norm_field.replace('.', '_')
        # Check if exists with the field normalized as UVL path
        field_exists = any(field_as_uvl in model_key for model_key in field_map.keys())
        
        # --- EL PUNTO MEDIO: ¿Es un alias legítimo? ---
        
        # Criterio A: Tiene jerarquía de objetos (un punto). Ej: kubernetes.algo, input.algo
        is_hierarchy = "." in c["field"]
        
        # Criterio B: Comparte vocabulario con la acción recomendada.
        # Extraemos las palabras del alias de Rego (Ej: 'allContainers' -> {'all', 'containers'})
        alias_words = set(re.findall(r'[a-zA-Z]+', c["field"].lower()))
        
        # Intersectamos los dos vocabularios y vemos si comparten palabras significativas (> 2 letras)
        shared_words = alias_words.intersection(paths_words)
        has_semantic_overlap = any(len(w) > 2 for w in shared_words)
        
        # Es legítimo si cumple cualquiera de las dos heurísticas
        is_legit_alias = is_hierarchy or has_semantic_overlap

        # --- APLICACIÓN DE LA REGLA ---
        if field_exists:
            # Si el campo ya era perfecto, lo limpiamos y lo guardamos
            #if c["field"].startswith("kubernetes.object."):
            #   c["field"] = c["field"].replace("kubernetes.object.", "")
            c["field"] = norm_field
            new_conditions.append(c)
            
        elif not field_exists and valid_paths and is_legit_alias:
            # ¡OVERRIDE SEGURO! 
            # Sabemos que no es 'msg' o 'res' porque pasó la heurística dinámica.
            print(f"[OVERRIDE SEGURO] Expandiendo alias dinámico '{c['field']}' a {len(valid_paths)} rutas.")
            for vp in valid_paths:
                new_conditions.append({
                    "field": vp,
                    "operator": c["operator"],
                    "value": c["value"]
                })
        else:
            # Es ruido de Rego (ej: 'msg', 'output'). Lo descartamos sutilmente.
            print(f"[NOISE FILTER] Descartada la variable local o ruido: '{c['field']}'")
            new_conditions.append(c)

    # 4. Limpiamos posibles duplicados exactos generados
    unique_conditions = []
    seen = set()
    # Primero, identificamos todos los campos que tienen operaciones matemáticas
    strong_fields = set()
    for nc in new_conditions:
        val_str = str(nc["value"]).lower()
        if nc["operator"] in ("<", ">", "<=", ">="):
            strong_fields.add(nc["field"])
        # Si es un string específico (ej. 'SYS_ADMIN', 'NET_RAW')
        elif nc["operator"] in ("==", "!=") and val_str not in ("true", "false", "") and not str(nc["value"]).isdigit():
            strong_fields.add(nc["field"])
    
    for nc in new_conditions:
        val_str = str(nc["value"]).lower()
        # Comprobamos si el campo actual es un "prefijo" (padre) de algún campo fuerte.
        # Usamos + "." (por si sigue en formato Rego) y + "_" (por si el escudo ya lo expandió a formato UVL)
        is_redundant_parent = any(
            sf.startswith(nc["field"] + ".") or sf.startswith(nc["field"] + "_")
            for sf in strong_fields
        )
        
        # Si es un padre redundante y su operador era solo de existencia (EXISTS o == true), ¡lo borramos!
        if is_redundant_parent and nc["operator"] in ("EXISTS", "==") and val_str in ("true", "false", ""):
            print(f"[LOGIC CLEANUP] Eliminando fallback genérico padre redundante: {nc['field']}")
            continue
        # Si el campo tiene una condición fuerte, BLOQUEAMOS las condiciones booleanas
        # o de existencia (EXISTS) que haya generado el fallback por error.
        if nc["field"] in strong_fields and nc["operator"] in ("EXISTS", "==") and val_str in ("true", "false", ""):
            print(f"[LOGIC CLEANUP] Eliminando fallback genérico redundante para: {nc['field']}")
            continue
        
        tup = (nc["field"], nc["operator"], nc["value"])
        if tup not in seen:
            seen.add(tup)
            unique_conditions.append(nc)

    return unique_conditions
    #return conditions

def parse_rego_policy(path, field_map=None):
    with open(path, "r", encoding="utf-8") as f:
        rego = f.read()

    metadata = extract_metadata_from_rego(rego)
    conds = extract_conditions_from_rego(rego, metadata["recommended_action"], field_map)

    return {
        "metadata": metadata,
        "conditions": conds
    }


def detect_intent(recommended_action, value):
    """
    Intenta adivinar si es una Prohibición (Forbidden) o un Requerimiento (Required)
    basado en el texto para desempatar casos dudosos.
    """
    #text = (meta.get("recommended_action", "") + " " + meta.get("short_code", "")).lower()
    
    text = recommended_action.lower()

    if any(x in text for x in ["do not set", "do not enable", "false", "disallow", "no-", "to 'false'", "remove"]): ## "drop"
        return "PROHIBITION" # !Feature
    
    if any(x in text for x in ["to true", "to 'true'", "require", "must be", "enable", "create", "configure", "add ", "specify at least"]):
        return "REQUIREMENT" # Feature
    
    return "UNKNOWN"

def rego_policy_to_uvl(policy, field_map, kind_map):

    # Campos que queremos extraer
    meta = policy["metadata"]
    
    if not policy["conditions"]:
        print(f"[ERROR] No se pudieron extraer condiciones para la política: {meta.get('short_code')}")
        return None, None
    print(f"Policy in process {meta.get('short_code')} conditions: {policy['conditions']}")
    first_cond = policy["conditions"][0]  # Asumimos 1 condición base por ahora
    recommended_action = meta['recommended_action']
    print(f"conditions extracted: {first_cond} from recommended_action: {recommended_action}")
    # --- tool ---
    tool = "trivy"
    # --- feature name ---
    feature_name = meta["short_code"].replace("-", "_")
    # --- severity ---
    severity = meta.get("severity", "").lower()
    # --- severity weight ---
    severity_weight = severity_to_weight(severity)
    # --- nombre original ---
    name = meta.get("short_code", meta.get("id", "no_short_code")) # Original name from the policy, can be used for traceability. Could use id if short_code is missing. (Ex id: KSV-0001)
    # --- Descripcion ---
    doc = clean_description(meta.get("description", "")).replace("'", "")
    # --- Kinds de la politica ---
    kinds_list = sorted(set(k for k in meta.get("kinds", [])))
    kinds_value = ", ".join(kinds_list)
    # # --- Source of implementation ---
    raw_source = 'OPA-Rego'
    # --- Extraer campo canonical desde conditions ---
    rego_field = first_cond["field"].replace(".", "_")
    rego_field_key = normalize_rego_path(rego_field)
    # # --- Accion recomendada ---
    clean_recommended_action_rego = recommended_action.replace("'", "").replace("\"", "")
    # --- Construcción del bloque UVL ---
    attrs = []
    attrs.append(f"tool '{tool}'")
    if severity:
        attrs.append(f"severity '{severity}'")
    attrs.append(f"weight '{severity_weight}'")
    if name:
        attrs.append(f"name '{name}'")
    if rego_field_key:
        attrs.append(f"fields '{rego_field_key}'")
    if kinds_value:
        attrs.append(f"kinds '{kinds_value}'")
    #if category:
    #    attrs.append(f"category '{category}'")
    if doc:
        attrs.append(f"doc '{doc}'")
    if clean_recommended_action_rego:
        attrs.append(f"RecommendedAction '{clean_recommended_action_rego}'")
    if raw_source:
        attrs.append(f"raw_source '{raw_source}'")

    feature_block = f"{feature_name} {{" + ", ".join(attrs) + "}"
    #feature_block = f"""{feature_name} {{doc '{clean_description_rego}', severity '{meta['severity'].lower()}', tool 'OPA', recommended '{clean_recommended_action_rego}'}}"""
    constraint_parts = [] ## Added only candidate crossed
    kinds = meta.get("kinds", [])
    #for cond in policy["conditions"]:
    #print(f"Processing condition: {cond}")

    for cond in policy["conditions"]:
        field = cond["field"]
        operator = cond["operator"]
        value = cond["value"]
        #field = cond["field"]
        #operator = cond["operator"]
        #value = cond["value"]
        
        if '.' in value and '.' in value:
            value = value.replace('.', '_') 
        # Convert Rego container path to canonical lookup key

        field_key = normalize_rego_path(field)
        intent = detect_intent(recommended_action, value)
        print(f"Policy in process 22 {meta.get('short_code')} {intent} conditions: {policy['conditions']}")

        if kinds:
            for kind in meta["kinds"]:
                #print(f"Kind    {kind}")
                found_features = find_uvl_path_for_rego(kind, field_key, field_map, kind_map, operator, value) ## Added operator and value for better matching and intent detection
        
                if not found_features:
                    print(f"[WARNING] No UVL mapping for field '{field_key}' in kind '{kind}'")
                    continue
                kind_cap = get_base_prefix(kind.capitalize()) ### Import of objects, adjust like the generate_uvl_policies -- If 

                # Operador UVL traducido
                #print(f"operator    {operator}  {value}")
                for feature, is_list, value_field in found_features:
                    value_str = str(value).lower()
                    expr = ""
                    
                    is_specific_string = isinstance(value, str) and value_str not in ["true", "false", ""] and not str(value).isdigit()
                    
                    # 2. PROTECCIÓN DEL NODO PADRE: 
                    # Si buscamos 'NET_RAW', no queremos hacer "!capabilities_add" (el array entero).
                    # Solo queremos aplicar la regla al nodo hijo (_StringValue).
                    if is_specific_string and not feature.endswith('StringValue'):
                        has_string_child = any(f[0].endswith('StringValue') for f in found_features)
                        if has_string_child:
                            # Saltamos el nodo padre y dejamos que en la siguiente iteración
                            # lo gestione el nodo _StringValue
                            continue
                            
                    # 3. CONSTRUCCIÓN DE LA EXPRESIÓN (Prioridad Matemática)
                    if is_specific_string:
                        final_val = value.upper() if value.lower() == "all" else value
                        # Si es un string específico, IGNORAMOS el 'intent'.
                        # Si Rego dice (== 'NET_RAW') en una regla Deny, la constraint segura es (!=)
                        if intent == "REQUIREMENT":
                            # Si DEBE TENER este string (Caso KSV-0003: Add 'ALL')
                            if operator == "==":
                                expr = f"{kind_cap}.{feature} == '{final_val}'"
                            elif operator == "!=":
                                expr = f"{kind_cap}.{feature} != '{final_val}'"
                            else:
                                expr = f"{kind_cap}.{feature} == '{final_val}'"
                        else:
                            # Si es PROHIBICIÓN (o desconocido), mantenemos la lógica de bloqueo
                            if operator == "==":
                                expr = f"{kind_cap}.{feature} != '{final_val}'"
                            elif operator == "!=":
                                expr = f"{kind_cap}.{feature} == '{final_val}'"
                            else:
                                expr = f"{kind_cap}.{feature} != '{final_val}'"
                    else:
                        # Prioridad 1: Tenemos claro el intent (por el texto de recomendación)
                        if intent == "PROHIBITION":
                            expr = f"!{kind_cap}.{feature}"
                            print(f"Intent detected as PROHIBITION based on recommended action text. Generated expression: {expr}")
                        elif intent == "REQUIREMENT":
                            expr = f"{kind_cap}.{feature}"
                        #elif operator == "EXISTS":
                        #    expr = f"!{kind_cap}.{feature}" if intent == "PROHIBITION" else f"{kind_cap}.{feature}"
                        # Prioridad 2: Operadores de comparación estándar contra Strings
                        elif operator == "==" and value_str not in ["true", "false"]:
                            #if value is not None and value.isdigit():  # Si no es un número, tratamos como string: 
                            #    expr = f"{kind_cap}.{feature} > {value}"
                            expr = f"{kind_cap}.{feature} != '{value}'"
                        elif operator == "!=" and value_str not in ["true", "false"]:
                            expr = f"{kind_cap}.{feature} == '{value}'"
                        elif operator == ">":
                            expr = f"{kind_cap}.{feature} > {value}"
                        elif operator == "<=": ## Case runs_with_UID_le_10000
                            expr = f"{kind_cap}.{feature} > {value}"                              
                        # Prioridad 3: Fallback explícito para Booleanos si el intent falló
                        else:
                            if value_str == "true":
                                expr = f"{kind_cap}.{feature}" if operator == "==" else f"!{kind_cap}.{feature}"
                            elif value_str == "false":
                                expr = f"!{kind_cap}.{feature}" if operator == "==" else f"{kind_cap}.{feature}"
                            else:
                                expr = f"UNSUPPORTED_OPERATOR({operator})"
                    # --- Lógica de Dependencia del Padre (!Padre | Hijo) --- Para constraints con operadores de comparación numéricos o booleanos, asumimos que la condición solo tiene sentido si el nodo padre existe. Por ejemplo, "containers.securityContext.capabilities.add == 'SYS_MODULE'"
                    #  solo es relevante si "containers.securityContext.capabilities.add" existe. En UVL, esto se puede modelar como una implicación: "(!containers.securityContext.capabilities.add | containers.securityContext.capabilities.add == 'SYS_MODULE')". Esto evita falsos positivos en casos donde el nodo no existe.
                    if expr and "UNSUPPORTED" not in expr and intent == "REQUIREMENT" and not expr.startswith('!') or value.isdigit():
                        parent_feature = None
                        # Buscamos el nodo padre (hasta containers, initContainers, o ephemeralContainers)
                        match = re.search(r'(.*(?:containers|initContainers|ephemeralContainers|limits))', feature, re.IGNORECASE)
                        #print(f"Intent detected as PROHIBITION based on recommended action text. Generated expression: {expr}")

                        if match:
                            parent_feature = f"{kind_cap}.{match.group(1)}"
                            # Convertimos la expresión simple en una implicación
                            expr = f"(!{parent_feature} | {expr})"
                            
                    if expr:
                        constraint_parts.append(expr)                        
                        #if intent == "PROHIBITION":
                            #sorted(list(set(constraint_parts)))
                            
        # --- Case 2: No kinds → buscar por feature global --- Se asigna Pod por defecto
        else:
            print("[INFO] Policy without explicit kinds. Searching by property only...")
            matches = []
            kind = 'Pod' ## Kind por defecto asignado para automountServiceAccountToken
            for midle, row in field_map.items():
                # Buscar coincidencias con el nombre de la propiedad
                if field_key.replace(".", "_") in midle and midle.startswith(kind):
                    matches.append(row)
            print(f"MATCHES {matches}")
            if not matches:
                print(f"[WARNING] No features matched for property '{field_key}'")
                return None

            for row in matches:
                feature = row["Feature"]
                aux = re.search(r"[A-Z].*", feature)
                kind = aux.group(0).split("_")[0]
                kind_cap = get_base_prefix(kind.capitalize()) ## Added the matching Kind
                if operator == "==" and value.lower() in ("true", "false"):
                    expr = f"!{kind}.{feature}" if value.lower() == "true" else f"{feature}"
                elif operator == "==" and value not in ("true", "false"):
                    expr = f"{kind}.{feature} != '{value}'"
                elif operator == "!=" and value.lower() == "true":
                    expr = f"{kind}.{feature}"
                elif operator == ">":
                    expr = f"{kind}.{feature} > {value}"
                else:
                    expr = f"UNSUPPORTED_OPERATOR({operator})"

                constraint_parts.append(expr)

        #print(f"Const parts {constraint_parts}")
        if not constraint_parts:
            print("[ERROR] No constraints generated, skipping policy")
            return None

    # Delete duplicates using a set list and order the list
    #unique_constraints = sorted(list(set(constraint_parts)))
    unique_constraints = sorted(list(set(constraint_parts)))
    
    constraint = f"{feature_name} => " + " & ".join(unique_constraints)
    #print(f"CONSTRAINT: {constraint}")
    return feature_block, constraint


# DEMO USAGE
if __name__ == "__main__":
    ## ../resources/kyverno_policies_yamls
    field_map = load_feature_dict("../resources/mapping_csv/kubernetes_mapping_properties_features.csv")
    #data = parse_rego_policy("../resources/kyverno_policies_yamls/OPA_Policies/SYS_ADMIN_capability.rego")
    data = parse_rego_policy("../resources/trivy_OPA_Policies/capabilities_no_drop_at_least_one.rego", field_map)

    kind_map = load_kinds_prefix_mapping("../resources/mapping_csv/kubernetes_kinds_versions_detected.csv")

    # Generate UVL feature block and constraint
    feature_block, constraint = rego_policy_to_uvl(data, field_map, kind_map)

    print(f"######PRUEBAS")

    if feature_block and constraint:
        print("\nFeature Block:\n", feature_block)
        print("\nConstraint:\n", constraint)
    else:
        print("No valid UVL mapping found.")