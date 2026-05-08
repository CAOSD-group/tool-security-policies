from copy import deepcopy
from itertools import product
from typing import List, Dict, Any
from flamapy.metamodels.configuration_metamodel.models.configuration import Configuration

class MappingEngine:
    @staticmethod
    def qualify(fid: str, namespace: str = "") -> str:
        if not namespace:
            return fid
        return fid if fid.startswith(namespace) else f"{namespace}{fid}"

    @classmethod
    def manifest_to_configurations(cls, mapped_json_dict: Dict[str, Any], namespace: str = "") -> List[Configuration]:
        """
        Recibe el diccionario procesado por CSVMapper (con estructura "config": {...})
        y devuelve una lista de objetos Configuration de FlamaPy.
        """
        base_config = {}
        blocks = []

        # Extraemos de forma segura el nodo 'config'
        config_node = mapped_json_dict.get('config', mapped_json_dict)

        # Extrae features y combinaciones para FlamaPy
        cls._extract_features(config_node, base_config, blocks, namespace)
        
        return cls._generate_combinations(base_config, blocks)

    @classmethod
    def _extract_features(cls, data: Any, base_config: Dict, blocks: List, namespace: str = ""):
        if isinstance(data, dict):
            for key, value in data.items():
                qkey = cls.qualify(key, namespace)

                if isinstance(value, (str, int, float, bool)):
                    base_config[qkey] = value
                elif isinstance(value, dict):
                    base_config[qkey] = True
                    cls._extract_features(value, base_config, blocks, namespace)
                elif isinstance(value, list):
                    if not value:
                        base_config[qkey] = True
                        continue
                    
                    combined_block = []
                    for item in value:
                        # Ampliado para atrapar tanto diccionarios como listas anidadas
                        if isinstance(item, (dict, list)):
                            flat_item = cls._flatten_primitive_kv(item, namespace)
                            combined_block.append(flat_item)
                        elif isinstance(item, (str, int, float, bool)):
                            # Mantenemos el soporte combinatorio pero no perdemos la pista
                            combined_block.append({cls.qualify(str(item), namespace): True})
                    
                    if combined_block:
                        blocks.append(combined_block)
                    base_config[qkey] = True

    @classmethod
    def _flatten_primitive_kv(cls, d: Any, namespace: str = "") -> dict:
        """
        Versión mejorada: Extrae recursivamente los valores primitivos 
        incluso si están enterrados dentro de listas de diccionarios.
        """
        flat = {}
        if isinstance(d, dict):
            for k, v in d.items():
                qk = cls.qualify(k, namespace)
                if isinstance(v, (str, int, float, bool)):
                    flat[qk] = v
                elif isinstance(v, dict):
                    flat[qk] = True
                    flat.update(cls._flatten_primitive_kv(v, namespace))
                elif isinstance(v, list):
                    # ESTA ES LA CLAVE QUE FALTABA: Navegar dentro de las listas
                    flat[qk] = True
                    for item in v:
                        flat.update(cls._flatten_primitive_kv(item, namespace))
        elif isinstance(d, list):
            for item in d:
                flat.update(cls._flatten_primitive_kv(item, namespace))
        return flat

    @classmethod
    def _generate_combinations(cls, base_config: Dict, blocks: List, max_combinations: int = 10000) -> List[Configuration]:
        result = []
        def backtrack(index, current):
            if len(result) >= max_combinations:
                return
            if index == len(blocks):
                merged = deepcopy(base_config)
                for partial in current:
                    merged.update(partial)
                result.append(Configuration(merged))
                return

            for option in blocks[index]:
                current.append(option)
                backtrack(index + 1, current)
                current.pop()

        backtrack(0, [])
        if not result:
            result.append(Configuration(base_config))
        return result