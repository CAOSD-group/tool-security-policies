#!/bin/bash

#c:\projects\investigacion\scriptJsonToUvl\yamls_agrupation

INPUT_DIR="C:/Users/CAOSD/projects/scriptJsonToUvl/yamls_agrupation/tiny" ## C:/projects/investigacion/scriptJsonToUvl/yamls_agrupation/tiny# c:/../../resources/yamls_agrupation/yamls-tools-files
# C:/Users/CAOSD/projects/scriptJsonToUvl/yamls_agrupation/tiny
RESULTS_DIR="../../../resources/results_data_tools/results_kyverno"
POLICIES_DIR="../../../resources/policies_tools/policies_kyverno/active_policies"
##DESTINATION_DIR = Path("../../../resources/policies_tools/policies_kyverno/active_policies")
BATCH_SIZE=300
TIMING_FILE="$RESULTS_DIR/batch_times.txt"

mkdir -p "$RESULTS_DIR"
rm -f "$TIMING_FILE"

find "$INPUT_DIR" -type f -name '*.yaml' > all_yaml_files.txt
split -l "$BATCH_SIZE" all_yaml_files.txt batch_

for batch_file in batch_*; do
  batch_id=$(basename "$batch_file")
  output_file="$RESULTS_DIR/$batch_id.txt"

  echo "Procesando lote: $batch_id"
  start_time=$(date +%s%3N)

  echo "" > "$output_file"
  while IFS= read -r yaml_path; do
    fname=$(basename "$yaml_path")
    echo "→ Validando $yaml_path"
    echo "##### FILE: $fname #####" >> "$output_file"
    ./kyverno apply "$POLICIES_DIR" --resource "$yaml_path" >> "$output_file" 2>&1
    echo "" >> "$output_file"
  done < "$batch_file"

  end_time=$(date +%s%3N)
  duration_ms=$((end_time - start_time))
  echo "$batch_id,$duration_ms" >> "$TIMING_FILE"

  echo " Lote $batch_id completado → Resultado en: $output_file"
done

python kyverno.py
rm batch_* all_yaml_files.txt