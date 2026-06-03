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
                            #flat_item = cls._flatten_primitive_kv(item, namespace)
                            #combined_block.append(flat_item)
                            flat_items_list = cls._flatten_primitive_kv(item, namespace)
                            for flat_item in flat_items_list:
                                combined_block.append(flat_item)
                                
                        elif isinstance(item, (str, int, float, bool)):
                            # Mantenemos el soporte combinatorio pero no perdemos la pista
                            combined_block.append({cls.qualify(str(item), namespace): True})
                    
                    if combined_block:
                        blocks.append(combined_block)
                    base_config[qkey] = True

    @classmethod
    def _flatten_primitive_kv(cls, d: Any, namespace: str = "") -> List[dict]:
        """
        Extrae los valores primitivos.
        Si encuentra un diccionario, acumula.
        Si encuentra una lista anidada, MULTIPLICA las configuraciones (Unrolling).
        Retorna siempre una Lista de Diccionarios.
        """
        # Si recibimos un primitivo (caso base extraño pero posible)
        if not isinstance(d, (dict, list)):
            return [{}]

        if isinstance(d, dict):
            # Empezamos con una sola configuración base vacía
            configs_acumuladas = [{}]
            
            for k, v in d.items():
                qk = cls.qualify(k, namespace)
                
                if isinstance(v, (str, int, float, bool)):
                    # A todas las configuraciones actuales, les añadimos este valor primitivo
                    for cfg in configs_acumuladas:
                        cfg[qk] = v
                        
                elif isinstance(v, dict):
                    # Inyectamos True por la presencia de la clave
                    for cfg in configs_acumuladas:
                        cfg[qk] = True
                    
                    # Llamada recursiva (devuelve una lista de configuraciones hijas)
                    hijos_configs = cls._flatten_primitive_kv(v, namespace)
                    
                    # Multiplicamos: Para cada config actual, añadimos cada config hija
                    nuevas_configs = []
                    for base_cfg in configs_acumuladas:
                        for hijo_cfg in hijos_configs:
                            nueva_combinacion = deepcopy(base_cfg)
                            nueva_combinacion.update(hijo_cfg)
                            nuevas_configs.append(nueva_combinacion)
                    configs_acumuladas = nuevas_configs
                    
                elif isinstance(v, list):
                    # Inyectamos True por la presencia de la clave de la lista
                    for cfg in configs_acumuladas:
                        cfg[qk] = True
                        
                    if len(v) == 0:
                        continue
                    
                    # --- EL NÚCLEO DE LA SOLUCIÓN ---
                    # Para cada elemento de la lista, obtenemos sus sub-configuraciones
                    todas_las_ramas_de_la_lista = []
                    for item in v:
                        ramas_del_item = cls._flatten_primitive_kv(item, namespace)
                        todas_las_ramas_de_la_lista.extend(ramas_del_item)
                    
                    # Multiplicamos el estado actual por todas las ramas posibles de esta lista
                    nuevas_configs = []
                    for base_cfg in configs_acumuladas:
                        for rama_lista in todas_las_ramas_de_la_lista:
                            nueva_combinacion = deepcopy(base_cfg)
                            nueva_combinacion.update(rama_lista)
                            nuevas_configs.append(nueva_combinacion)
                    configs_acumuladas = nuevas_configs
                    
            return configs_acumuladas

        elif isinstance(d, list):
            # Si el punto de entrada a la función es directamente una lista
            configs_acumuladas = []
            for item in d:
                configs_acumuladas.extend(cls._flatten_primitive_kv(item, namespace))
            return configs_acumuladas if configs_acumuladas else [{}]

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