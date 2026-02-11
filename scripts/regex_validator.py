import re

class ContentPolicyValidator:
    """
    Validador de políticas basado en Regex y recorrido recursivo del JSON.
    """

    def __init__(self):
        self.policy_map = {
            'tagNotSpecified': self._validate_tag_specified_and_not_latest,
            'Require_Run_As_ContainerUser_Windows': self._validate_run_as_container_user_windows,
            'Require_Annotations': self._validate_require_annotations,
            'Restrict_AppArmor': self._validate_restrict_apparmor,
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
                        print(f"[DEBUG HIT] ¡Encontrada clave de imagen!: {key_str} {value}")
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
    
    # --- HELPER GENÉRICO RECURSIVO ---
    def _find_values_by_suffix_recursive(self, data, target_suffixes):
        """
        Busca valores recursivamente para claves que terminen en ALGUNO de los sufijos.
        target_suffixes puede ser un string único o una lista.
        """
        if isinstance(target_suffixes, str):
            target_suffixes = [target_suffixes]
            
        found_values = []
        
        if isinstance(data, dict):
            for k, v in data.items():
                k_str = str(k)
                for suffix in target_suffixes:
                    if k_str.endswith(suffix):
                        # Si es un valor primitivo, lo guardamos
                        if isinstance(v, (str, int, bool)):
                            found_values.append(v)
                
                # Recursión
                if isinstance(v, (dict, list)):
                    found_values.extend(self._find_values_by_suffix_recursive(v, target_suffixes))
                    
        elif isinstance(data, list):
            for item in data:
                found_values.extend(self._find_values_by_suffix_recursive(item, target_suffixes))
                
        return found_values


    # HELPER: Extracción de Anotaciones
    def _find_all_annotations_recursive(self, data):
        """
        Busca recursivamente todos los bloques 'annotations' y devuelve un 
        diccionario unificado con todas las anotaciones encontradas en el archivo.
        """
        found_annotations = {}

        if isinstance(data, dict):
            for k, v in data.items():
                # Si encontramos la clave "annotations" (o "metadata_annotations" según tu parser)
                # y el valor es un diccionario, lo capturamos.
                # Nota: Ajusta "annotations" si tu parser aplanado usa "io_k8s...metadata_annotations"
                if str(k).endswith("metadata_annotations") and isinstance(v, dict):
                    found_annotations.update(v)
                
                # Recursión
                elif isinstance(v, (dict, list)):
                    found_annotations.update(self._find_all_annotations_recursive(v))
        
        elif isinstance(data, list):
            for item in data:
                found_annotations.update(self._find_all_annotations_recursive(item))
                
        return found_annotations
    
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
        print(f"[DEBUG VALIDATOR] Lista final de imágenes encontradas: {images}")

        if not images:
            # Si no hay imágenes, no hay violación de política de imágenes.
            print("[ALERTA] No se encontraron imágenes. ¿Es esto correcto o falló la búsqueda?")
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
    
    def _validate_run_as_container_user_windows(self, config):
        # Sufijo clave: busca el campo runAsUserName dentro de bloque windowsOptions
        # Ajusta "_windowsOptions_runAsUserName" según cómo aplane tu modelo las claves
        users = self._find_values_by_suffix_recursive(config, "windowsOptions_runAsUserName")
        
        if not users:
            return True # Correcto: Si no está definido (Linux), pasa.

        for user in users:
            if user != 'ContainerUser':
                print(f"[Fail] Require_Run_As_ContainerUser_Windows: Usuario '{user}' no permitido.")
                return False
        return True
    
    # POLÍTICA: Require Annotations (corp.org/department)
    def _validate_require_annotations(self, config_elements):
        """
        Verifica que exista la clave 'corp.org/department' y que no esté vacía.
        """
        annotations = self._find_all_annotations_recursive(config_elements)
        target_key = "corp.org/department"

        # 1. Comprobar existencia de la clave
        if target_key not in annotations:
            print(f"[Policy Failure] Require_Annotations: Falta la anotación obligatoria '{target_key}'.")
            return False

        # 2. Comprobar valor (Pattern: ?*) -> Significa que no sea null ni vacío
        value = annotations[target_key]
        if not value or str(value).strip() == "":
            print(f"[Policy Failure] Require_Annotations: La anotación '{target_key}' existe pero está vacía.")
            return False

        return True
    
    # POLÍTICA: Restrict AppArmor
    def _validate_restrict_apparmor(self, config_elements):
        """
        Verifica que si hay anotaciones de AppArmor, sean 'runtime/default' o 'localhost/*'.
        """
        annotations = self._find_all_annotations_recursive(config_elements)
        prefix = "container.apparmor.security.beta.kubernetes.io/"

        for k, v in annotations.items():
            key_str = str(k)
            # Solo validamos las que son de AppArmor
            if key_str.startswith(prefix):
                val_str = str(v)
                
                # Condición A: Es exactamente 'runtime/default'
                is_default = (val_str == 'runtime/default')
                
                # Condición B: Empieza por 'localhost/'
                is_localhost = val_str.startswith('localhost/')
                
                if not (is_default or is_localhost):
                    print(f"[Policy Failure] Restrict_AppArmor: Valor inválido en '{key_str}'. "
                          f"Se encontró '{val_str}', se esperaba 'runtime/default' o 'localhost/*'.")
                    return False

        return True
    
    def _validate_restrict_ingress_classes(self, config_elements):
        """
        Busca si existe la anotación. Si existe, valida el valor.
        Si no existe, devuelve True (no fuerza a usar anotaciones legacy).
        """
        target_key = "kubernetes_io/ingress_class"
        
        # Buscamos la anotación en todo el archivo (sin importar el Kind)
        annotations = self._find_all_annotations_recursive(config_elements)
        
        if target_key in annotations:
            val = annotations[target_key]
            # Validamos que sea uno de los permitidos
            if val not in ["HAProxy", "nginx"]:
                print(f"[Fail] Restrict_Ingress_Classes: Valor '{val}' no permitido. Use 'HAProxy' o 'nginx'.")
                return False
        
        return True
    

    def _validate_restrict_jobs(self, config_elements):
        """
        Policy: Restrict Jobs
        Regla: Si es un Job, DEBE tener un ownerReference de tipo CronJob.
        """
        # 1. Aquí SÍ es obligatorio comprobar el Kind.
        # Si no comprobamos el Kind, obligaríamos a los 'Deployment' o 'Pod' a tener ownerReference,
        # lo cual sería un error. La política solo aplica a Jobs.
        kinds = self._find_values_by_suffix_recursive(config_elements, "_kind")
        
        # Si no hay Jobs en este archivo, la política pasa.
        if "Job" not in kinds:
            return True

        # 2. Buscar ownerReferences
        owners = self._find_owner_references_recursive(config_elements)
        
        # CASO CRÍTICO: Si estamos validando un YAML estático de un desarrollador, lo normal es que NO tenga ownerReferences. 
        # Por lo tanto, si es un Job y no tiene owners -> FALLO (Intento de creación manual).
        if not owners:
            print("[Fail] Restrict_Jobs: Detectado un 'Job' manual (sin ownerReferences). Los Jobs deben ser creados por CronJobs.")
            return False

        # 3. Si tiene owners (ej: es un dump de un cluster), validamos que sea CronJob
        has_cronjob_owner = False
        for owner in owners:
            # owner es un dict, buscamos la clave 'kind'
            # Dependiendo de tu aplanado, puede ser 'kind' o 'metadata_ownerReferences_kind'
            # Asumimos que _find_owner... devuelve el dict reconstruido o buscamos la clave
            if owner.get('kind') == 'CronJob' or 'CronJob' in str(owner.values()): 
                has_cronjob_owner = True
                break
        
        if not has_cronjob_owner:
            print("[Fail] Restrict_Jobs: El Job no pertenece a un CronJob.")
            return False

        return True