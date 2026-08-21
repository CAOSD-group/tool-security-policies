import yaml
import shutil
import re
from pathlib import Path

UVL_FILE_PATH = Path("../../../back_kube_tool/models/HKFM.uvl") # Ajusta a la ruta real de tu modelo
REPO_KYVERNO_DIR = Path("../../../policies") # Donde clonaste github.com/kyverno/policies
DESTINATION_DIR = Path("../../../resources/policies_tools/policies_kyverno/active_policies")

def extract_kyverno_policies_from_uvl(uvl_path: Path) -> set:
    """
    Lee el archivo UVL y extrae el atributo 'name' de las características
    que pertenecen a la herramienta 'kyverno'.
    """
    active_policies = set()
    # Expresión regular que busca: tool 'kyverno' y captura el valor de name '...'
    regex_pattern = re.compile(r"tool\s+'kyverno'.*?name\s+'([^']+)'")
    
    try:
        with open(uvl_path, 'r', encoding='utf-8') as f:
            for line in f:
                match = regex_pattern.search(line)
                if match:
                    active_policies.add(match.group(1))
    except FileNotFoundError:
        print(f"[ERROR CRÍTICO] No se encontró el archivo UVL en: {uvl_path}")
        exit(1)
        
    return active_policies

def sync_policies():
    # 2. Obtener la lista dinámica desde el Feature Model
    active_policies_in_fm = extract_kyverno_policies_from_uvl(UVL_FILE_PATH)
    
    if not active_policies_in_fm:
        print("[WARNING] No se encontraron políticas de Kyverno en el modelo UVL.")
        return

    print(f"[INFO] Se han extraído {len(active_policies_in_fm)} políticas de Kyverno desde el Feature Model.")
    
    # 3. Preparar directorio de destino (limpiarlo si ya existía para evitar residuos)
    if DESTINATION_DIR.exists():
        shutil.rmtree(DESTINATION_DIR)
    DESTINATION_DIR.mkdir(parents=True, exist_ok=True)
    
    copied_count = 0

    print(f"[INFO] Buscando coincidencias en el repositorio descargado: {REPO_KYVERNO_DIR}...")

    # 4. Recorrer todos los YAMLs del repositorio oficial
    for yaml_file in REPO_KYVERNO_DIR.rglob("*.yaml"):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                docs = yaml.safe_load_all(f)
                for doc in docs:
                    if not doc or not isinstance(doc, dict):
                        continue
                    
                    # Extraer el nombre de la política (ej. 'require-aws-node-irsa')
                    policy_name = doc.get("metadata", {}).get("name")
                    
                    if policy_name in active_policies_in_fm:
                        dest_path = DESTINATION_DIR / yaml_file.name
                        shutil.copy2(yaml_file, dest_path)
                        print(f"  -> [COPIADO] {policy_name} ({yaml_file.name})")
                        copied_count += 1
                        # Removemos la política del set para saber si nos faltó alguna al final
                        active_policies_in_fm.remove(policy_name)
                        break
        except Exception:
            pass # Ignoramos archivos que no sean políticas válidas

    print(f"\n[OK] Sincronización completada. Se han copiado {copied_count} archivos YAML.")
    
    # 5. Comprobación de integridad (Aviso si falta algo en el repo oficial)
    if active_policies_in_fm:
        print(f"\n[WARNING] Las siguientes {len(active_policies_in_fm)} políticas están en tu UVL pero NO se encontraron en los YAMLs descargados:")
        for missing in active_policies_in_fm:
            print(f"  - {missing}")

if __name__ == "__main__":
    sync_policies()