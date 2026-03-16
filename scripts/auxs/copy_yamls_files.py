import os
import shutil

def copiar_archivo_exacto(directorio_origen, directorio_destino, nombre_exacto):
    """
    Copia un archivo específico usando su nombre exacto de un directorio a otro.
    """
    # 1. Construir las rutas completas
    ruta_origen = os.path.join(directorio_origen, nombre_exacto)
    ruta_destino = os.path.join(directorio_destino, nombre_exacto)

    # 2. Verificar que el archivo origen existe y es un archivo (no una carpeta)
    if not os.path.isfile(ruta_origen):
        print(f"❌ Error: El archivo '{nombre_exacto}' no se encuentra en el directorio de origen.")
        return False

    # 3. Asegurar que el directorio de destino exista (lo crea si no existe)
    os.makedirs(directorio_destino, exist_ok=True)

    # 4. Intentar copiar el archivo
    try:
        # copy2 es ideal porque copia el contenido y también preserva metadatos (fechas, permisos)
        shutil.copy2(ruta_origen, ruta_destino)
        print(f"✅ Éxito: El archivo ha sido copiado a '{ruta_destino}'")
        return True
        
    except PermissionError:
        print("❌ Error: No tienes permisos para leer el archivo de origen o escribir en el destino.")
    except Exception as e:
        print(f"❌ Error inesperado al copiar: {e}")
        
    return False

# ==========================================
# CONFIGURACIÓN DE RUTAS (Modifica esto)
# ==========================================
DIRECTORIO_ORIGEN = "C:\projects\kubernetes_fm\scripts\download_manifests\YAMLs02" ## C:\projects\kubernetes_fm\scripts\download_manifests
DIRECTORIO_DESTINO = "../../resources/examples/original_yamls" ##'../evaluation/validation_results_valid_jsons03_Z3.csv' 
NOMBRE_ARCHIVO = "019-securityContext1.yaml" 

# Ejecución
if __name__ == "__main__":
    copiar_archivo_exacto(DIRECTORIO_ORIGEN, DIRECTORIO_DESTINO, NOMBRE_ARCHIVO)