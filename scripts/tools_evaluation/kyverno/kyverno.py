from pathlib import Path
from collections import defaultdict
import csv
import re

input_dir = Path("../../../resources/results_data_tools/results_kyverno") ##C:\projects\investigacion\scriptJsonToUvl\yamls_agrupation
yaml_dir = Path("C:/Users/CAOSD/projects/scriptJsonToUvl/yamls_agrupation/tiny") #C:\Users\CAOSD\projects\scriptJsonToUvl\yamls_agrupation
csv_output = '../../../evaluation/validation_results_kyverno_final.csv'
timing_file = input_dir / "batch_times.txt"

results = defaultdict(lambda: {"valid": True, "fail_count": 0, "failures": [], "avg_time": 0.0})

file_marker = re.compile(r"^##### FILE: (.+) #####")
summary_re = re.compile(r"pass:\s*(\d+),\s*fail:\s*(\d+),\s*warn:\s*(\d+),\s*error:\s*(\d+),\s*skip:\s*(\d+)", re.IGNORECASE)

batch_times = {}
file_to_batch = {}

try:
    # --- FASE DE LECTURA DE DATOS ---
    if timing_file.exists():
        with open(timing_file, encoding="utf-8") as f:
            for line in f:
                batch_id, time_str = line.strip().split(",")
                batch_times[batch_id] = int(time_str)

    for result_file in input_dir.rglob("batch_*.txt"):
        batch_id = result_file.stem
        with open(result_file, encoding="utf-8", errors="replace") as f:
            current_file = None
            for line in f:
                line = line.strip()
                match = file_marker.match(line)
                if match:
                    current_file = match.group(1)
                    file_to_batch[current_file] = batch_id
                    continue

                if current_file is None:
                    continue

                if "validation error" in line.lower() or "validation failure" in line.lower():
                    results[current_file]["failures"].append(line)

                summary = summary_re.search(line)
                if summary:
                    fails = int(summary.group(2))
                    errors = int(summary.group(4))
                    total_issues = fails + errors
                    if total_issues > 0:
                        results[current_file]["valid"] = False
                        results[current_file]["fail_count"] += total_issues

    # Rellenar archivos faltantes
    all_yaml_files = {file.name for file in yaml_dir.rglob("*.yaml")}
    for yaml_file in all_yaml_files:
        if yaml_file not in file_to_batch:
            file_to_batch[yaml_file] = None

except KeyboardInterrupt:
    print("\n[WARNING] Ejecución detenida manualmente por el usuario. Guardando resultados parciales...")
except Exception as e:
    print(f"\n[ERROR] Fallo inesperado durante el procesamiento: {e}. Guardando resultados parciales...")

finally:
    # --- FASE DE CÁLCULO Y GUARDADO (Se ejecuta SIEMPRE) ---
    print("\n[INFO] Consolidando datos y generando CSV...")
    
    batch_file_counts = defaultdict(int)
    for fname, batch in file_to_batch.items():
        if batch:
            batch_file_counts[batch] += 1

    for fname, batch in file_to_batch.items():
        if batch and batch in batch_times and batch_file_counts[batch] > 0:
            avg = round(batch_times[batch] / batch_file_counts[batch], 2)
            results[fname]["avg_time"] = avg

    # Generar CSV con el formato extendido
    Path(csv_output).parent.mkdir(parents=True, exist_ok=True)
    with open(csv_output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # Cabecera con ambas métricas
        writer.writerow(["file", "valid", "avg_validation_time_ms", "misconfiguration_count", "issues"])

        for fname in sorted(results.keys()):
            is_valid = results[fname]["valid"]
            avg_time = results[fname]["avg_time"]
            issues_count = results[fname]["fail_count"]
            # Unimos la lista de fallos con un punto y coma para no romper el CSV
            issues_text = "; ".join(results[fname]["failures"])
            
            writer.writerow([fname, str(is_valid).lower(), avg_time, issues_count, issues_text])

    print(f"[OK] Resultados guardados exitosamente en: {csv_output}")