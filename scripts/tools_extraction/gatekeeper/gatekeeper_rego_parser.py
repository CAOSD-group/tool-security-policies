import re

# ------------------------------------------------------------
# PARSER GATEKEEPER REGO – versión robusta v3
# ------------------------------------------------------------

VIOLATION_PATTERN = re.compile(
    r"violation\s*\[[^\]]*\]\s*\{(?P<body>.*?)\}",
    re.DOTALL
)

FUNC_CALL_PATTERN = re.compile(
    r"(?P<func>\w+)\s*\((?P<arg>[^\)]+)\)"
)

FUNC_DEF_PATTERN = re.compile(
    r"(?P<func>\w+)\s*\(\s*(?P<param>\w+)\s*\)\s*\{(?P<body>.*?)\}",
    re.DOTALL
)

ATTR_PATTERN = re.compile(
    r"(?P<var>\w+)\.(?P<attr>[A-Za-z_][A-Za-z0-9_\.]*)"
)


HOSTPORT_PATTERN = re.compile(
    r"hostPort\s*:=\s*input_containers\[_\]\.ports\[_\]\.hostPort"
)

INVALID_LAST = {
    "name","image","images",
    "securitycontext","containers",
    "initcontainers","ephemeralcontainers",
    "metadata","spec","namespace"
}


def extract_gatekeeper_conditions_from_rego(rego_text):
    """
    Extrae condiciones REALES de Gatekeeper, incluso si aparecen
    dentro de funciones auxiliares, como hostPID/hostIPC.
    """
    results = []

    # 1. Extraer bloque violation
    m = VIOLATION_PATTERN.search(rego_text)
    if not m:
        return []
    violation_body = m.group("body")

    # 2. Detectar llamadas a funciones dentro de violation
    calls = FUNC_CALL_PATTERN.findall(violation_body)
    called_funcs = {f for (f, arg) in calls}

    # 3. Extraer definiciones de funciones
    funcs = []
    for m in FUNC_DEF_PATTERN.finditer(rego_text):
        funcs.append({
            "name": m.group("func"),
            "param": m.group("param"),
            "body": m.group("body")
        })

    # 4. Condiciones directas dentro de violation
    results += extract_direct_conditions(violation_body)

    # 5. Condiciones dentro de funciones auxiliares
    for f in funcs:
        if f["name"] not in called_funcs:
            continue

        # ejemplo: o.spec.hostPID
        conds = extract_direct_conditions(f["body"])
        # expandir o → spec
        expanded = []
        for var, attr in conds:
            param = f["param"]
            if var != param:
                continue
            expanded.append(("spec", attr))
        results += expanded
    
    # 6. Detectar reglas de hostPort (rangos min/max)
    if HOSTPORT_PATTERN.search(rego_text):
        results.append(("c", "ports.hostPort"))

    # 7. Expandir variable a rutas K8s correctas
    final = []
    for var, attr in results:
        if var == "c":
            final.append(f"spec.containers[*].{attr}")
            final.append(f"spec.initContainers[*].{attr}")
            final.append(f"spec.ephemeralContainers[*].{attr}")
        elif var == "spec":
            final.append(f"spec.{attr}")

    # Dedup
    uniq = []
    seen = set()
    for r in final:
        if r not in seen:
            uniq.append(r)
            seen.add(r)

    return uniq


def extract_direct_conditions(body):
    """
    Extrae condiciones directas del tipo:
       c.securityContext.privileged
       o.spec.hostPID
    """
    conds = []
    for m in ATTR_PATTERN.finditer(body):
        var = m.group("var")
        attr = m.group("attr")

        # solo condiciones reales
        last = attr.split(".")[-1].lower()
        if last in INVALID_LAST:
            continue

        conds.append((var, attr))
    return conds