import io
import math
from ruamel.yaml import YAML
from .utils.context_filter import enforce_k8s_object_arrays
from ruamel.yaml.comments import CommentedMap

class Remediator:
    """
    Motor encargado de inyectar soluciones de seguridad directamente
    en el manifiesto YAML original, preservando comentarios y formato.
    """
    
    def __init__(self):
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        # FORZAR EL ESTILO KUBERNETES:
        # mapping=2: Los diccionarios se indentan 2 espacios.
        # sequence=4: Las listas se indentan 4 espacios desde la raíz.
        # offset=2: El guion (-) se desplaza 2 espacios a la derecha.
        self.yaml.width = math.inf
        self.yaml.indent(mapping=2, sequence=4, offset=2)
        # PUNTO 2: Evita saltos de línea automáticos en cadenas largas
        
        # NOTA: Se elimina self.yaml.indent para que ruamel infiera el estilo original

    def apply_batch_remediation(self, yaml_content: str, patches: list) -> str:
        """
        PUNTO 3: Unifica todo el proceso en una sola lectura y escritura.
        'patches' es una lista de: {'path': list, 'value': any}
        """
        try:
            # 1. Cargar el documento una sola vez
            data = self.yaml.load(yaml_content)
            if not data:
                return yaml_content

            # 2. Aplicar todos los cambios recursivos en memoria
            for patch in patches:
                self._apply_recursive(data, patch['path'], patch['value'])
            
            # 3. Aplicar post-procesamiento de arrays del oráculo en el mismo objeto
            data = enforce_k8s_object_arrays(data)
            
            # 4. Volcar a string una sola vez al final
            output = io.StringIO()
            self.yaml.dump(data, output)
            return output.getvalue()
            
        except Exception as e:
            print(f"Error crítico en apply_batch_remediation: {e}")
            return yaml_content

    def _apply_recursive(self, current_node, path: list, value):
        if not path:
            return

        key = path[0]
        is_last = (len(path) == 1)

        # Manejo de listas (Containers en K8s)
        if isinstance(current_node, list):
            for item in current_node:
                self._apply_recursive(item, path, value)
            return

        if isinstance(current_node, dict):
            # Limpieza de índices numéricos en strings
            if isinstance(key, str) and key.isdigit():
                key = int(key)

            if is_last:
                #current_node[key] = value
                # If the value is a removal instruction, we need to handle it differently
                if isinstance(value, dict) and "$delete" in value:
                    if key in current_node:
                        del current_node[key]
                
                # 2. Operador para borrar un ELEMENTO de una lista (Ej: SYS_ADMIN en capabilities)
                elif isinstance(value, dict) and "$remove" in value:
                    item_to_remove = value["$remove"]
                    # Verificamos si el nodo actual contiene una lista en esa clave
                    if key in current_node and isinstance(current_node[key], list):
                        current_node[key] = [x for x in current_node[key] if x != item_to_remove]
                else:
                    # Normal write operation
                    # Si intentamos inyectar un diccionario y ya existe uno en esa posición:
                    if key in current_node and isinstance(current_node[key], dict) and isinstance(value, dict):
                        for k, v in value.items():
                            # SOLO inyectamos la propiedad si el usuario no la había definido previamente
                            if k not in current_node[key]:
                                current_node[key][k] = v
                    else:
                        # Comportamiento estándar (sobrescribe o crea de cero)
                        current_node[key] = value
                    ##current_node[key] = value
            else:
                if key not in current_node:
                    current_node[key] = CommentedMap() ##{} # Inject a native object to preserve comments
                self._apply_recursive(current_node[key], path[1:], value)