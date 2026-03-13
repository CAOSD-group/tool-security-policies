import csv
import re

class ReverseMapper:
    """
    Traduce las 'Features' de UVL de vuelta a las rutas estructurales de Kubernetes.
    Utiliza el CSV de correspondencias exactas para asegurar precisión absoluta.
    """
    
    def __init__(self, csv_kinds_path: str):
        # Diccionario: { (version, kind): prefix }
        # Ej: { ('v1', 'Pod'): 'io_k8s_api_core_v1_Pod' }
        self.prefix_map = self._load_prefixes_from_csv(csv_kinds_path)
        
        # Una lista de todos los prefijos ordenados de mayor a menor longitud
        # (útil por si no nos pasan el contexto de version/kind)
        self.all_prefixes = sorted(list(self.prefix_map.values()), key=len, reverse=True)

    def _load_prefixes_from_csv(self, csv_path: str) -> dict:
        mapping = {}
        with open(csv_path, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                version = row['Version'].strip()
                kind = row['Kind'].strip()
                # Construimos el prefijo completo. Ej: Prefix + "_" + Kind
                prefix_base = row['Prefix'].strip()
                full_prefix = f"{prefix_base}_{kind}_"
                mapping[(version, kind)] = full_prefix
        return mapping

    def get_yaml_path(self, feature_name: str, api_version: str = None, kind: str = None) -> list:
        """
        Toma el nombre de la feature y lo convierte en una ruta de YAML.
        
        Args:
            feature_name (str): Ej. "io_k8s_api_core_v1_Pod_spec_hostNetwork"
            api_version (str, optional): Versión del recurso (ej. 'v1').
            kind (str, optional): Tipo de recurso (ej. 'Pod').
            
        Returns:
            list: Ej. ["spec", "hostNetwork"]
        """
        path_str = feature_name
        
        # 1. Recortar el prefijo exacto si tenemos el contexto (Versión y Kind)
        prefix_to_remove = None
        if api_version and kind:
            # Normalizar api_version si viene con grupo (ej. apps/v1 -> v1)
            clean_version = api_version.split('/')[-1] if '/' in api_version else api_version
            prefix_to_remove = self.prefix_map.get((clean_version, kind))

        # 2. Si encontramos el prefijo exacto, lo recortamos
        if prefix_to_remove and path_str.startswith(prefix_to_remove):
            path_str = path_str[len(prefix_to_remove):]
        else:
            # 3. Fuerza bruta (Fallback): Si no hay contexto o el prefijo falló, probamos todos
            for p in self.all_prefixes:
                if path_str.startswith(p):
                    path_str = path_str[len(p):]
                    break
        
        # 4. Limpieza de sufijos heurísticos de tu csv_mapper
        suffixes_to_clean = ["_asString", "_asInteger", "_asNumber", "_StringValue", "_KeyMap", "_ValueMap"]
        for suffix in suffixes_to_clean:
            if path_str.endswith(suffix):
                # Cortamos solo el final
                path_str = path_str[:-len(suffix)]
        
        # 5. Convertir a ruta de lista
        return path_str.split("_")