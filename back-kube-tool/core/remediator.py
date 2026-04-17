from ruamel.yaml import YAML
import io
from core.utils.context_filter import enforce_k8s_object_arrays

class Remediator:
    """
    Motor encargado de inyectar soluciones de seguridad directamente
    en el manifiesto YAML original, preservando comentarios y formato.
    """
    
    def __init__(self):
        self.yaml = YAML()
        self.yaml.width = 1000 ## Evite the line break for long lines, common in Kubernetes manifests
        self.yaml.preserve_quotes = True
        self.yaml.indent(mapping=2, sequence=2, offset=0) ## sequence=4, offset=2 para alinear con el estilo de Kubernetes  

    def apply_patch(self, yaml_content: str, yaml_path: list, new_value) -> str:
        """Aplica la corrección, manejando correctamente las listas de Kubernetes."""
        try:
            data = self.yaml.load(yaml_content)
            if not data: 
                return yaml_content

            # Usamos un algoritmo recursivo para navegar y modificar
            self._apply_recursive(data, yaml_path, new_value)
            
            output = io.StringIO()
            self.yaml.dump(data, output)
            return output.getvalue()
            
        except Exception as e:
            print(f"Error en Remediator al aplicar parche en {yaml_path}: {e}")
            return yaml_content

    def _apply_recursive(self, current_node, path: list, value):
        if not path:
            return

        key = path[0]
        is_last = (len(path) == 1)

        # 1. SI ES UNA LISTA: Iteramos sobre cada elemento
        # (Ideal para Kubernetes: si hay 3 'containers', le aplica el parche a los 3)
        if isinstance(current_node, list):
            for item in current_node:
                self._apply_recursive(item, path, value)
            return

        # 2. SI ES UN DICCIONARIO: Navegamos de forma normal
        if isinstance(current_node, dict):
            # Limpiamos si hay algún índice en formato string
            if isinstance(key, str) and key.isdigit():
                key = int(key)

            if is_last:
                # Llegamos al destino, inyectamos el valor seguro
                current_node[key] = value
            else:
                # Bajamos un nivel. Si la clave no existe, la creamos (Auto-completado)
                if key not in current_node:
                    current_node[key] = {}
                self._apply_recursive(current_node[key], path[1:], value)
                
    def post_process_arrays(self, yaml_content: str) -> str:
            """
            Lee el YAML final, envuelve los diccionarios en arrays según 
            el Feature Model (Oráculo), y devuelve el YAML corregido.
            """
            try:
                data = self.yaml.load(yaml_content)
                if not data:
                    return yaml_content
                
                # Pasamos los datos por nuestra función del Oráculo
                data = enforce_k8s_object_arrays(data)
                
                output = io.StringIO()
                self.yaml.dump(data, output)
                return output.getvalue()
                
            except Exception as e:
                print(f"Error en Remediator al post-procesar arrays: {e}")
                return yaml_content