import re

class RegexPolicyValidator:
    """
    Validador de políticas basado en Regex y recorrido recursivo del JSON.
    """

    def __init__(self):
        self.policy_map = {
            'tagNotSpecified': self._validate_tag_specified_and_not_latest,
        }
        
        # Definimos los sufijos que identifican a una imagen en tu modelo generado.
        # Esto cubre Pods, Deployments, DaemonSets, etc., ya que el final de la clave
        # siempre mantiene la semántica del campo.
        self.TARGET_IMAGE_SUFFIXES = [
            "_containers_image",           # Caso estándar
            "_initContainers_image",       # Caso inicialización
            "_ephemeralContainers_image",  # Caso efímero
            # "_image"                     # <-- Descomentar si quieres ser ultra-permisivo
        ]

    def validate(self, config_elements, active_policies):
        """
        Punto de entrada.
        Args:
            config_elements: El objeto JSON/Diccionario completo (configuration_json.elements).
            active_policies: Lista de strings con los nombres de las políticas activas.
        """
        for policy in active_policies:
            if policy in self.policy_map:
                # Ejecutamos la validación específica
                is_valid = self.policy_map[policy](config_elements)
                if not is_valid:
                    return False
        return True

    def _find_image_values_recursive(self, data):
        """
        Recorre recursivamente diccionarios y listas buscando claves que
        terminen en alguno de los TARGET_IMAGE_SUFFIXES.
        Retorna una lista de los valores (nombres de las imágenes) encontrados.
        """
        found_values = []

        if isinstance(data, dict):
            for key, value in data.items():
                # 1. Comprobamos si la CLAVE actual coincide con nuestros objetivos
                key_str = str(key)
                for suffix in self.TARGET_IMAGE_SUFFIXES:
                    if key_str.endswith(suffix):
                        # Encontrado! Guardamos el valor (ej: "busybox:1.28")
                        if isinstance(value, str):
                            found_values.append(value)
                
                # 2. Independientemente de si encontramos algo, seguimos bajando
                #    porque podría haber anidamiento (aunque en tu modelo aplanado 
                #    las claves suelen ser hojas, en listas no lo son).
                if isinstance(value, (dict, list)):
                    found_values.extend(self._find_image_values_recursive(value))
        
        elif isinstance(data, list):
            for item in data:
                found_values.extend(self._find_image_values_recursive(item))

        return found_values

    def _validate_tag_specified_and_not_latest(self, config_elements):
        """
        Implementación de la política 'tagNotSpecified':
        - Schema: pattern: ^.+:.+$ (Debe tener tag)
        - Schema: not pattern: ^.+:latest$ (No debe ser latest)
        """
        
        # 1. Extracción profunda de todas las imágenes en el JSON
        images = self._find_image_values_recursive(config_elements)
        
        # Debug para ver qué está encontrando (puedes quitarlo luego)
        # print(f"DEBUG Regex: Imágenes encontradas: {images}")

        if not images:
            # Si no hay imágenes, no hay violación de política de imágenes.
            return True

        # 2. Compilación de Regex
        regex_has_tag = re.compile(r'^.+:.+$')       # Debe tener "algo:algo"
        regex_is_latest = re.compile(r'^.+:latest$') # No debe terminar en ":latest"

        # 3. Validación
        all_ok = True
        for img in images:
            # Check A: ¿Tiene tag?
            if not regex_has_tag.match(img):
                print(f"[Regex Failure] tagNotSpecified: La imagen '{img}' no especifica una versión/tag.")
                all_ok = False
                break # Fallo inmediato (o quitar break para reportar todos)

            # Check B: ¿Es latest?
            if regex_is_latest.match(img):
                print(f"[Regex Failure] tagNotSpecified: La imagen '{img}' usa el tag prohibido 'latest'.")
                all_ok = False
                break
        
        return all_ok