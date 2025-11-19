# gatekeeper_rego_parser.py
import re

# ============================================================
#   PARSER GATEKEEPER REGO (Heurístico - opción A)
# ============================================================

VAR_ASSIGN_PATTERN = re.compile(
    r'(?P<var>\w+)\s*:=\s*(?P<expr>[\w\.]+)(?:\[_\])?'
)

ATTRIBUTE_PATTERN = re.compile(
    r'(?P<var>\w+)\.(?P<attr>[A-Za-z0-9_.]+)'
)


def extract_variable_assignments(rego_text):
    """
    Detecta asignaciones tipo:
        c := input_containers[_]
        x := input.review.object.spec.containers[_]
    y devuelve:
        {"c": "input_containers", "x": "input.review.object.spec.containers"}
    """
    assignments = {}
    for m in VAR_ASSIGN_PATTERN.finditer(rego_text):
        var = m.group('var')
        expr = m.group('expr')
        assignments[var] = expr
    return assignments


def expand_base_path(expr):
    """
    Expande expresiones 'base' a rutas K8s relativas.
    - input_containers -> spec.containers / initContainers / ephemeralContainers
    - input.review.object.spec.xxx -> spec.xxx
    """
    expr = expr.strip()

    if expr == "input_containers":
        return [
            "spec.containers[*]",
            "spec.initContainers[*]",
            "spec.ephemeralContainers[*]"
        ]

    if expr.startswith("input.review.object."):
        cleaned = expr.replace("input.review.object.", "")
        return [cleaned]

    if expr.startswith("input."):
        # fallback genérico
        cleaned = expr.replace("input.", "")
        return [cleaned]

    return [expr]


def extract_attribute_conditions(rego_text, assignments):
    """
    Extrae expresiones tipo:
        c.securityContext.privileged
        c.image
    y las combina con su base (ej: 'c' -> input_containers).
    Devuelve rutas K8s del estilo:
        spec.containers[*].securityContext.privileged
    """
    results = []

    for match in ATTRIBUTE_PATTERN.finditer(rego_text):
        var = match.group('var')
        attr = match.group('attr')

        # ignorar cosas triviales
        if var in ("msg", "details"):
            continue

        # Caso directo input.review.object...
        if var == "input":
            full = f"input.{attr}"
            for bp in expand_base_path(full):
                results.append(bp)
            continue

        # var asignada previamente
        if var in assignments:
            base_expr = assignments[var]
            for bp in expand_base_path(base_expr):
                full = f"{bp}.{attr}"
                results.append(full)

    # deduplicar manteniendo orden
    seen = set()
    uniq = []
    for r in results:
        if r not in seen:
            uniq.append(r)
            seen.add(r)
    return uniq


def extract_gatekeeper_conditions_from_rego(rego_text):
    """
    Punto de entrada: dada la policy Rego del template,
    devuelve una lista de rutas K8s que forman parte de las condiciones.
    """
    assigns = extract_variable_assignments(rego_text)
    attrs = extract_attribute_conditions(rego_text, assigns)
    return attrs