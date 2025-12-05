import os
import csv
import time

from flamapy.metamodels.fm_metamodel.transformations import UVLReader
from flamapy.metamodels.pysat_metamodel.transformations import FmToPysat

from scripts.configurationJSON01 import ConfigurationJSON   # Tu reader JSON
from scripts.valid_config import valid_config_version_json  # Tu lógica de validación JSON

from pathlib import Path

# --------------------------------------------------
# CONFIGURACIÓN
# --------------------------------------------------

HERE = Path(__file__).resolve().parent     # scripts/
ROOT = HERE.parent                         # fm-security-policies/

FM_PATH = ROOT / "variability_model" / "policies_template" / "policy_structure03.uvl"
VALID_JSONS_DIR = ROOT / "resources" / "valid_jsons"
OUTPUT_CSV = HERE / "validation_results_valid_jsons.csv"

VALIDATE_ONLY_FIRST_CONFIG = True

def validate_single_json(json_file, fm_model, sat_model):

    """Valida un archivo JSON concreto y devuelve métricas para el CSV.

    Returns:
        _type_: _description_
    """
    try:
        print(f"Validando archivo: {json_file}")

        start_conf_time = time.time()
        config_reader = ConfigurationJSON(json_file)
        configurations = config_reader.transform()
        end_conf_time = time.time()

        conf_time = round(end_conf_time - start_conf_time, 5)
        num_confs = len(configurations)
        num_features = len(configurations[0].elements) if configurations else 0

        if VALIDATE_ONLY_FIRST_CONFIG:
            config = configurations[0]

            start_validation_time = time.time()
            valid, complete_conf = valid_config_version_json(config, fm_model, sat_model)
            end_validation_time = time.time()

            validation_time = round(end_validation_time - start_validation_time, 5)

        else:
            valid = True
            start_validation_time = time.time()
            for conf in configurations:
                ok, _ = valid_config_version_json(conf, fm_model, sat_model)
                if not ok:
                    valid = False
                    break
            end_validation_time = time.time()
            validation_time = round(end_validation_time - start_validation_time, 5)

        return [
            os.path.basename(json_file),
            valid,
            num_features,
            num_confs,
            conf_time,
            validation_time,
            "Archivo válido" if valid else "Archivo inválido"
        ]

    except Exception as e:
        print(f"[ERROR] {json_file}: {e}")
        return [
            os.path.basename(json_file),
            "Error",
            "-",
            "-",
            "-",
            "-",
            str(e)
        ]

def validate_all_valid_jsons():
    """
    Recorre la carpeta valid_jsons y valida cada archivo.
    """

    fm_model = UVLReader(str(FM_PATH)).transform()
    sat_model = FmToPysat(fm_model).transform()

    print("Modelo cargado correctamente.")
    print(f"Procesando carpeta: {VALID_JSONS_DIR}")

    files = sorted([f for f in os.listdir(VALID_JSONS_DIR) if f.endswith(".json")])

    with open(OUTPUT_CSV, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Filename", "Valid", "Features", "Configurations", "TimeConf", "TimeVal", "Description"])

        valid_count = 0
        invalid_count = 0
        error_count = 0

        for filename in files:
            json_path = os.path.join(VALID_JSONS_DIR, filename)
            result = validate_single_json(json_path, fm_model, sat_model)
            writer.writerow(result)

            # Contadores
            state = str(result[1]).lower()
            if state == "true":
                valid_count += 1
            elif state == "false":
                invalid_count += 1
            else:
                error_count += 1

    print("\n=== RESUMEN FINAL ===")
    print(f"Archivos válidos:   {valid_count}")
    print(f"Archivos inválidos: {invalid_count}")
    print(f"Errores:            {error_count}")
    print(f"Resultados guardados en: {OUTPUT_CSV}")


# --------------------------------------------------
# MAIN
# --------------------------------------------------

if __name__ == '__main__':
    validate_all_valid_jsons()