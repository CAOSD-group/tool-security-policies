from flamapy.metamodels.configuration_metamodel.models import Configuration
from flamapy.metamodels.fm_metamodel.transformations import UVLReader, FlatFM
from flamapy.metamodels.z3_metamodel.transformations import FmToZ3
from flamapy.metamodels.z3_metamodel.operations import Z3Satisfiable, Z3SatisfiableConfiguration

from scripts.configurationJSON import ConfigurationJSON
import os
import csv
import time
from pathlib import Path

from scripts._inference_policy import extract_policy_kinds_from_constraints, infer_policies_from_kind
from scripts.regex_validator import ContentPolicyValidator


HERE = Path(__file__).resolve().parent  # scripts/
ROOT = HERE.parent                      # fm-security-rules/
ROOT_PARENT = ROOT.parent               # under folder root/
FM_PATH = ROOT / "variability_model" / "model_policies02.uvl"
VALID_JSONS_DIR = ROOT_PARENT / "valid_jsons"

OUTPUT_CSV = ROOT / "evaluation" / "validation_results_valid_jsons_model_policies02_Z3_1.csv"
VALIDATE_ONLY_FIRST_CONFIG = True


# --------------------------------------------------
# Weight / metadata (cache)
# --------------------------------------------------

def severity_to_weight_fallback(sev: str) -> float:
    sev = (sev or "").strip().lower()
    if sev in {"critical", "danger", "high"}:
        return 1.0
    if sev in {"medium", "warning"}:
        return 0.7
    if sev in {"low", "info"}:
        return 0.5
    return 0.5


_POLICY_META_CACHE: dict[str, dict] = {}

def get_policy_metadata(flat_fm, policy_name: str) -> dict:
    """Read tool/severity/weight/doc/raw_source/etc. from the UVL (with cache)."""
    if policy_name in _POLICY_META_CACHE:
        return _POLICY_META_CACHE[policy_name]

    feat = flat_fm.get_feature_by_name(policy_name)
    info = {
        "tool": "unknown",
        "severity": "unknown",
        "weight": None,     # float
        "doc": "",
        "kinds": "",
        "raw_source": "",
        "name": policy_name,
    }
    if not feat:
        info["weight"] = 0.5
        _POLICY_META_CACHE[policy_name] = info
        return info

    sev_val = None
    weight_val = None

    for attr in feat.get_attributes():
        val = attr.get_default_value()
        if attr.name == "severity":
            sev_val = val
            info["severity"] = val
        elif attr.name == "weight":
            weight_val = val
        elif attr.name in info:
            info[attr.name] = val
        elif attr.name == "RecommendedAction":
            info["remediation"] = val

    if weight_val is not None and str(weight_val).strip() != "":
        try:
            info["weight"] = float(weight_val)
        except Exception:
            info["weight"] = severity_to_weight_fallback(sev_val)
    else:
        info["weight"] = severity_to_weight_fallback(sev_val)

    _POLICY_META_CACHE[policy_name] = info
    return info


# --------------------------------------------------
# CSV helpers
# --------------------------------------------------

def load_processed_files(csv_file_path):
    processed = set()
    if os.path.exists(csv_file_path):
        with open(csv_file_path, mode="r", newline="") as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if row and row[0].endswith(".json"):
                    processed.add(row[0])
    return processed


# --------------------------------------------------
# FAST closure for tree constraints (parents + mandatory)
# --------------------------------------------------

_PARENT_CACHE: dict[str, list[str]] = {}
_MAND_DESC_CACHE: dict[str, list[str]] = {}

def _parents_of(feature) -> list[str]:
    """List of parent names (cache)."""
    n = feature.name
    if n in _PARENT_CACHE:
        return _PARENT_CACHE[n]
    p = feature.get_parent()
    if p is None:
        res = []
    else:
        res = [p.name] + _parents_of(p)
    _PARENT_CACHE[n] = res
    return res


def _mandatory_descendants(feature) -> list[str]:
    """List of mandatory descendants (cache)."""
    n = feature.name
    if n in _MAND_DESC_CACHE:
        return _MAND_DESC_CACHE[n]
    res = []
    for child in feature.get_children():
        if child.is_mandatory():
            res.append(child.name)
            res.extend(_mandatory_descendants(child))
    _MAND_DESC_CACHE[n] = res
    return res


def add_feature_closure(config_elements: dict, fm_model, feature_name: str) -> dict:
    """
    Inject:
      - parents of the feature
      - mandatory children of the feature and its parents
    without overwriting existing values (e.g., strings 'Default', 'v1', etc.).
    """
    feat = fm_model.get_feature_by_name(feature_name)
    if not feat:
        return config_elements

    # mandatory of this feature
    for ch in _mandatory_descendants(feat):
        if ch not in config_elements:
            config_elements[ch] = True

    # parents + mandatory of each parent
    for parent_name in _parents_of(feat):
        if parent_name not in config_elements:
            config_elements[parent_name] = True

        parent_feat = fm_model.get_feature_by_name(parent_name)
        if parent_feat:
            for ch in _mandatory_descendants(parent_feat):
                if ch not in config_elements:
                    config_elements[ch] = True

    return config_elements


def complete_configuration_fast(configuration: Configuration, fm_model) -> Configuration:
    """
    Complete the configuration by adding parents and mandatory features of all selected features (closure).
    """
    elems = dict(configuration.elements)
    for selected in configuration.get_selected_elements():
        elems = add_feature_closure(elems, fm_model, selected)
    return Configuration(elems)


# --------------------------------------------------
# Core: complete evaluation (Regex + Z3 + score)
# --------------------------------------------------

_VALIDATOR = ContentPolicyValidator()
_REGEX_APPLICABLE_SET = set(_VALIDATOR.policy_map.keys())

def evaluate_config_security(config: Configuration, flat_fm, z3_model, constraint_kinds_map, auto_policies):
    """
    - Regex: solo si policy está en policy_map del validator
    - Z3: solo si policy aparece en constraint_kinds_map (tiene constraint)
    - Score: ponderado por weight
    """
    z3_applicable_set = set(constraint_kinds_map.keys())

    # Base completion UNA vez
    base_completed = complete_configuration_fast(Configuration(dict(config.elements)), flat_fm)

    # Regex una vez
    _, regex_failures = _VALIDATOR.validate_with_report(config.elements, auto_policies)
    regex_failed_set = {f["policy"] for f in regex_failures}
    regex_reason_map = {f["policy"]: f.get("reason", "") for f in regex_failures}

    sat_op = Z3SatisfiableConfiguration()

    report = []
    total_weight = 0.0
    passed_weight = 0.0

    failed_set = set()

    for policy in auto_policies:
        meta = get_policy_metadata(flat_fm, policy)
        w = float(meta.get("weight", 0.5) or 0.5)

        # Solo cuenta en el score si es evaluable por al menos 1 vía
        regex_applies = policy in _REGEX_APPLICABLE_SET
        z3_applies = policy in z3_applicable_set
        evaluable = regex_applies or z3_applies
        if not evaluable:
            continue

        total_weight += w

        # 1) Regex (si aplica)
        if regex_applies and policy in regex_failed_set:
            failed_set.add(policy)
            report.append({
                "policy": policy,
                "result": "FAILED_REGEX",
                "tool": meta.get("tool", "unknown"),
                "severity": meta.get("severity", "unknown"),
                "weight": w,
                "reason": regex_reason_map.get(policy, "Regex/content validation failed.")
            })
            # optimización: si ya falló regex, NO hacemos Z3
            continue

        # 2) Z3 (si aplica)
        if z3_applies:
            try:
                temp_elements = dict(base_completed.elements)
                temp_elements[policy] = True
                # closure SOLO para esta policy
                temp_elements = add_feature_closure(temp_elements, flat_fm, policy)

                temp_config = Configuration(temp_elements)
                temp_config.set_full(True)

                sat_op.set_configuration(temp_config)
                z3_ok = sat_op.execute(z3_model).get_result()

                if not z3_ok:
                    failed_set.add(policy)
                    report.append({
                        "policy": policy,
                        "result": "FAILED_Z3",
                        "tool": meta.get("tool", "unknown"),
                        "severity": meta.get("severity", "unknown"),
                        "weight": w,
                        "reason": "Z3 constraint violated (UNSAT for this policy)."
                    })
                    continue

            except Exception as e:
                failed_set.add(policy)
                report.append({
                    "policy": policy,
                    "result": "ERROR_Z3",
                    "tool": meta.get("tool", "unknown"),
                    "severity": meta.get("severity", "unknown"),
                    "weight": w,
                    "reason": f"Z3 evaluation error: {e}"
                })
                continue

        # Si llega aquí: pasa regex (si aplicaba) y pasa z3 (si aplicaba)
        passed_weight += w

    security_score = 1.0 if total_weight <= 0 else (passed_weight / total_weight)
    risk_score = 1.0 - security_score
    secure_bool = (len(failed_set) == 0)

    stats = {
        "total_weight": total_weight,
        "passed_weight": passed_weight,
        "failed_policies": len(failed_set)
    }
    return secure_bool, security_score, risk_score, report, stats


# --------------------------------------------------
# VALIDACIÓN POR ARCHIVO (CORRIGE filas Skip/Error)
# --------------------------------------------------

def validate_single_json(json_file, flat_fm, z3_model, constraint_kinds_map):
    try:
        print(f"Procesando archivo: {json_file}")

        start_conf_time = time.time()
        config_reader = ConfigurationJSON(json_file)
        configurations = config_reader.transform()
        conf_time = round(time.time() - start_conf_time, 5)

        if not configurations:
            # 13 columnas SIEMPRE
            return [
                os.path.basename(json_file), "Error", "-", conf_time, "-", "-", "-", "-", "-", "-", "-", "-", "No configurations parsed"
            ]

        num_confs = len(configurations)
        num_features = len(configurations[0].elements)

        config0 = configurations[0]
        auto_policies = infer_policies_from_kind(config0.elements, constraint_kinds_map)

        if not auto_policies:
            # 13 columnas SIEMPRE
            return [
                os.path.basename(json_file), "Skip", "-", conf_time,
                "-", "-", "-", "-", "-", num_features, num_confs, "-", "Configuracion sin politicas que verificar"
            ]

        start_validation_time = time.time()

        if VALIDATE_ONLY_FIRST_CONFIG:
            secure, sec_score, risk_score, report, stats = evaluate_config_security(
                config0, flat_fm, z3_model, constraint_kinds_map, auto_policies
            )
        else:
            # agregación simple: peor score (min) y secure solo si todas secure
            secure = True
            sec_score = 1.0
            risk_score = 0.0
            report = []
            stats = {"passed_weight": 0.0, "total_weight": 0.0, "failed_policies": 0}

            for conf in configurations:
                ap = infer_policies_from_kind(conf.elements, constraint_kinds_map)
                if not ap:
                    continue
                s, sc, rc, rep, st = evaluate_config_security(conf, flat_fm, z3_model, constraint_kinds_map, ap)
                secure = secure and s
                sec_score = min(sec_score, sc)
                risk_score = max(risk_score, rc)
                report.extend(rep)
                # usar el peor caso de pesos para consistencia
                stats["total_weight"] = max(stats["total_weight"], st["total_weight"])
                stats["passed_weight"] = min(stats["passed_weight"] if stats["passed_weight"] else st["passed_weight"], st["passed_weight"])
                stats["failed_policies"] = max(stats["failed_policies"], st["failed_policies"])

        validation_time = round(time.time() - start_validation_time, 5)

        policies_applied_str = ";".join(sorted(auto_policies))
        failed_str = ";".join(sorted({r["policy"] for r in report})) if report else ""

        return [
            os.path.basename(json_file),
            str(secure),
            validation_time,
            conf_time,
            policies_applied_str,
            f"{sec_score*100:.2f}",
            f"{risk_score*100:.2f}",
            f"{stats['passed_weight']:.3f}",
            f"{stats['total_weight']:.3f}",
            num_features,
            num_confs,
            failed_str,
            "OK" if secure else "Security/Regex issues detected"
        ]

    except Exception as e:
        print(f"[ERROR] {json_file}: {e}")
        # 13 columnas SIEMPRE
        return [
            os.path.basename(json_file), "Error", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", str(e)
        ]


# --------------------------------------------------
# VALIDAR CARPETA
# --------------------------------------------------

def validate_all_configs(flat_fm, z3_model, processed_files):
    print(f"Procesando carpeta de JSONs: {VALID_JSONS_DIR.resolve()}")

    constraint_kinds_map = extract_policy_kinds_from_constraints(str(FM_PATH))

    file_exists = os.path.exists(OUTPUT_CSV) and os.path.getsize(OUTPUT_CSV) > 0

    with open(OUTPUT_CSV, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "Filename",
                "Secure",
                "TimeVal",
                "TimeConf",
                "PoliciesApplied",
                "SecurityScore(0-100)",
                "RiskScore(0-100)",
                "PassedWeight",
                "TotalWeight",
                "Features",
                "Configurations",
                "FailedPolicies",
                "Description"
            ])

        valid_count = invalid_count = skip_or_error_count = 0
        
        for filename in os.listdir(VALID_JSONS_DIR): ## my_files:
            if not filename.endswith(".json"):
                continue

            if filename in processed_files:
                print(f"Saltando (ya procesado): {filename}")
                continue

            json_path = os.path.join(VALID_JSONS_DIR, filename)
            result = validate_single_json(json_path, flat_fm, z3_model, constraint_kinds_map)
            writer.writerow(result)
            processed_files.add(filename)

            state = str(result[1]).lower()
            if state == "true":
                valid_count += 1
            elif state == "false":
                invalid_count += 1
            else:
                skip_or_error_count += 1

    print("\n=== RESUMEN FINAL ===")
    print(f"Archivos válidos:   {valid_count}")
    print(f"Archivos inválidos: {invalid_count}")
    print(f"Archivos skip/error: {skip_or_error_count}")
    print(f"Resultados guardados en: {OUTPUT_CSV}")


# --------------------------------------------------
# MAIN
# --------------------------------------------------

if __name__ == '__main__':
    print("Cargando y procesando el modelo")
    start_startup_model = time.time()

    fm_model = UVLReader(str(FM_PATH)).transform()
    flat_fm_op = FlatFM(fm_model)
    flat_fm_op.set_maintain_namespaces(False)
    flat_fm = flat_fm_op.transform()

    z3_model = FmToZ3(flat_fm).transform()
    result = Z3Satisfiable().execute(z3_model).get_result()
    print(f"Satisfiable: {result}")

    startup_time = round(time.time() - start_startup_model, 4)
    print(f"Tiempo de start config of FMs: {startup_time}")

    processed = load_processed_files(OUTPUT_CSV)
    print(f"Validando JSONs desde: {VALID_JSONS_DIR.resolve()}")
    validate_all_configs(flat_fm, z3_model, processed)