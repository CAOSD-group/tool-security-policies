from ruamel.yaml import YAML
import io

class Remediator:
    """
    Motor encargado de inyectar soluciones de seguridad directamente
    en el manifiesto YAML original, preservando comentarios y formato.
    """
    
    def __init__(self):
        # Configuramos ruamel para preservar el formato (Round-Trip)
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.indent(mapping=2, sequence=4, offset=2)

    def apply_patch(self, yaml_content: str, yaml_path: list, new_value) -> str:
        """
        Aplica una corrección en un YAML.
        
        Args:
            yaml_content (str): El texto del YAML original (con comentarios).
            yaml_path (list): La ruta obtenida del ReverseMapper. Ej: ['spec', 'hostNetwork']
            new_value: El valor seguro calculado por Z3. Ej: False
            
        Returns:
            str: El nuevo texto del YAML con la corrección aplicada.
        """
        try:
            # 1. Cargamos el YAML en un AST (Abstract Syntax Tree)
            data = self.yaml.load(yaml_content)
            
            # 2. Navegamos por el árbol hasta el penúltimo nodo
            current_node = data
            for i, key in enumerate(yaml_path[:-1]):
                # Si en la ruta hay un número como string (ej. '0'), es un índice de lista
                if key.isdigit():
                    key = int(key)
                
                # Si la ruta no existe, la creamos al vuelo (Auto-completado estructural)
                if isinstance(current_node, dict) and key not in current_node:
                    current_node[key] = {}
                    
                current_node = current_node[key]
            
            # 3. Aplicamos el cambio en la última clave
            last_key = yaml_path[-1]
            if last_key.isdigit():
                last_key = int(last_key)
                
            current_node[last_key] = new_value
            
            # 4. Volvemos a generar el texto
            output = io.StringIO()
            self.yaml.dump(data, output)
            return output.getvalue()
            
        except Exception as e:
            # Si el parcheado falla (YAML malformado), devolvemos el original
            print(f"Error en Remediator al aplicar parche en {yaml_path}: {e}")
            return yaml_content