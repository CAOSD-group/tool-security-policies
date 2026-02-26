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
            'Require_Labels': self._validate_require_labels,
            'Restrict_Ingress_Classes': self._validate_restrict_ingress_classes,
            'Restrict_Jobs': self._validate_restrict_jobs,
            ## New policies can be added here with their corresponding validation methods.
            'Restrict_Image_Registries': self._validate_restrict_image_registries,
            'Require_Images_Use_Checksums': self._validate_require_images_use_checksums,
            'Require_Ingress_HTTPS': self._validate_require_ingress_https,
            'Limit_hostPath_PersistentVolumes_to_Specific_Directories': self._validate_limit_pv_hostpath_specific_dirs,
            ## Added more policies here as needed...
            'Restrict_sysctls': self._validate_restrict_sysctls_allowlist,
            'Prevent_cr8escape_CVE_2022_0811': self._validate_prevent_cr8escape_sysctl_values,
            'Require_Container_Port_Names': self._validate_require_container_port_names,
            #'Require_imagePullSecrets': self._validate_require_imagepullsecrets, ## no detected at the moment
            #'cpuLimitsMissing': self._validate_cpu_limits_set, ## pendente to add the function
            #'cpuRequestsMissing': self._validate_cpu_requests_set,
            #'livenessProbeMissing': self._validate_liveness_probe_configured,
            #'readinessProbeMissing': self._validate_readiness_probe_configured,
        }
        
        # Definimos los sufijos que identifican a una imagen en tu modelo generado.
        self.TARGET_IMAGE_SUFFIXES = [
            "_containers_image",           # Caso estándar
            "_initContainers_image",       # Caso inicialización
            "_ephemeralContainers_image",  # Caso efímero
        ]

        # Allowlist exact (valores reales con puntos, como en YAML)
        self.SYSCTL_ALLOWLIST = {
            "kernel.shm_rmid_forced",
            "net.ipv4.ip_local_port_range",
            "net.ipv4.ip_unprivileged_port_start",
            "net.ipv4.tcp_syncookies",
            "net.ipv4.ping_group_range",
        }

        # Claves "container lists" típicas en PodSpec
        self.CONTAINER_LIST_KEY_SUFFIXES = [
            "spec_containers",
            "spec_initContainers",
            "spec_ephemeralContainers",
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

    def _find_all_labels_recursive(self, data):
        """Igual que _find_all_annotations pero para 'labels'"""
        found_labels = {}
        if isinstance(data, dict):
            for k, v in data.items():
                if str(k).endswith("labels") and isinstance(v, dict):
                    found_labels.update(v)
                elif isinstance(v, (dict, list)):
                    found_labels.update(self._find_all_labels_recursive(v))
        elif isinstance(data, list):
            for item in data:
                found_labels.update(self._find_all_labels_recursive(item))
        return found_labels
    

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
    
    # POLÍTICA: Require Labels
    def _validate_require_labels(self, config_elements):
        """
        Policy: Require Labels
        Regla: Debe existir la label 'app.kubernetes.io/name' con algún valor.
        """
        # Reutilizamos la lógica de anotaciones pero buscando 'labels'
        labels = self._find_all_labels_recursive(config_elements)
        target_key = "app.kubernetes.io/name"

        if target_key not in labels:
            # Fallo silencioso o verbose según prefieras
            # print(f"[Fail] Require_Labels: Falta la label obligatoria '{target_key}'.")
            return False

        if not labels[target_key]: # Chequeo de valor vacío (?*)
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
        kinds = self._find_values_by_suffix_recursive(config_elements, "_Job_kind")
        
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
    

    def _validate_require_ingress_https(self, config_elements):
        """
        Kyverno require-ingress-https:
        - Aplica SOLO a Ingress
        - Requiere metadata.annotations['kubernetes.io/ingress.allow-http'] == "false"
        - Requiere que exista spec.tls (clave tls presente)
        """
        # 0) Si no hay Ingress en el YAML/config, la política NO aplica -> pasa
        if not self._has_kind(config_elements, "Ingress"):
            return True

        # 1) Validar anotación allow-http = "false"
        annotations = self._find_all_annotations_recursive(config_elements)

        # Kyverno usa la clave real con puntos/slash:
        # kubernetes.io/ingress.allow-http
        allow_http_keys = [
            "kubernetes.io/ingress.allow-http",

            # variantes por si tu parser normaliza caracteres (por si acaso)
            "kubernetes_io/ingress.allow-http",
            "kubernetes_io/ingress_allow-http",
            "kubernetes_io/ingress_allow_http",
        ]

        found = False
        for k in allow_http_keys:
            if k in annotations:
                found = True
                val = str(annotations.get(k)).strip().lower()
                if val != "false":
                    print(f"[Fail] Require_Ingress_HTTPS: la anotación '{k}' debe ser 'false' (actual: '{annotations.get(k)}').")
                    return False
                break

        # En Kyverno la anotación es obligatoria -> si no está, FALLA
        if not found:
            print("[Fail] Require_Ingress_HTTPS: falta la anotación obligatoria 'kubernetes.io/ingress.allow-http'.")
            return False

        # 2) Validar que exista TLS (spec.tls presente)
        # En tu modelo UVL tienes: Ingress...spec_tls (feature de presencia)
        tls_vals = self._find_values_by_suffix_recursive(config_elements, "Ingress_spec_tls")

        # Si no encontramos ninguna clave/valor tls -> no existe spec.tls -> FALLA
        if not tls_vals:
            print("[Fail] Require_Ingress_HTTPS: TLS must be defined (spec.tls no encontrado).")
            return False

        # Si existe pero viene vacío/falso, también fallamos (por seguridad)
        # Nota: dependiendo del aplanado, puede ser bool, list, dict, string...
        any_present = False
        for v in tls_vals:
            if isinstance(v, bool):
                if v is True:
                    any_present = True
                    break
            elif v is None:
                continue
            elif isinstance(v, (str, int)):
                if str(v).strip() != "":
                    any_present = True
                    break
            else:
                # si llega algo raro, lo consideramos presente (porque la clave existe)
                any_present = True
                break

        if not any_present:
            print("[Fail] Require_Ingress_HTTPS: TLS must be defined (spec.tls vacío/no presente).")
            return False

        return True

    
    def _validate_require_images_use_checksums(self, config_elements):
        """
        Require_Images_Use_Checksums:
        - Exigir que las imágenes incluyan digest '@sha256:...' (o al menos '@').
        - Mejor que '*@*' en UVL.
        """
        images = self._find_image_values_recursive(config_elements)
        if not images:
            return True

        # Estricto: '@sha256:'; si prefieres laxo, usa solo '@'
        regex_digest = re.compile(r".+@sha256:[0-9a-fA-F]{64}$")

        for img in images:
            if not regex_digest.match(img):
                print(f"[Fail] Require_Images_Use_Checksums: imagen '{img}' no usa digest '@sha256:...'.")
                return False
        return True
    
    def _validate_restrict_image_registries(self, config_elements):
        """
        Valida que TODAS las imágenes (containers/init/ephemeral) provengan de registries permitidos.
        Basado en Kyverno: "eu.foo.io/* | bar.io/*"
        """
        allowed_prefixes = ["eu.foo.io/", "bar.io/"]

        images = self._find_image_values_recursive(config_elements)
        if not images:
            # Si no hay imágenes, no tiene sentido fallar aquí.
            return True

        for img in images:
            img = str(img).strip()
            if not any(img.startswith(p) for p in allowed_prefixes):
                print(f"[Fail] Restrict_Image_Registries: imagen '{img}' fuera de registries permitidos {allowed_prefixes}.")
                return False

        return True
    
    def _validate_limit_pv_hostpath_specific_dirs(self, config_elements):
        """
        Kyverno: si PV.spec.hostPath existe -> spec.hostPath.path debe empezar por '/data'
        """
        # 1) Solo aplica si hay un PersistentVolume en el YAML
        if not self._has_kind(config_elements, "PersistentVolume"):
            return True

        # 2) Extraer posibles hostPath.path
        # Ajusta el sufijo si en tu aplanado se llama distinto.
        paths = self._find_values_by_suffix_recursive(config_elements, "PersistentVolume_spec_hostPath_path")
        if not paths:
            # No hay hostPath.path => significa "no hay hostPath" o no aparece => pasa
            return True

        for p in paths:
            if p is None:
                continue
            p = str(p).strip()
            if not p.startswith("/data"):
                print(f"[Fail] Limit_hostPath_PersistentVolumes_to_Specific_Directories: hostPath '{p}' no permitido (debe empezar por '/data').")
                return False

        return True
    
    ### More added (26/02/2026)

    # --- helper: saca el primer valor de un dict cuya key termine en suffix ---
    def _get_value_by_key_suffix(self, d: dict, suffix: str):
        for k, v in d.items():
            if str(k).endswith(suffix):
                return v
        return None

    # --- helper: encuentra lista de dicts bajo una key que termine en suffix ---
    def _find_dict_list_under_key_suffix_recursive(self, data, key_suffix: str):
        found = []
        if isinstance(data, dict):
            for k, v in data.items():
                if str(k).endswith(key_suffix) and isinstance(v, list):
                    for it in v:
                        if isinstance(it, dict):
                            found.append(it)
                if isinstance(v, (dict, list)):
                    found.extend(self._find_dict_list_under_key_suffix_recursive(v, key_suffix))
        elif isinstance(data, list):
            for it in data:
                found.extend(self._find_dict_list_under_key_suffix_recursive(it, key_suffix))
        return found
    
    def _validate_restrict_sysctls_allowlist(self, config_elements):
        # sysctls es una lista de dicts
        sysctl_items = self._find_dict_list_under_key_suffix_recursive(config_elements, "sysctls")

        # Si no hay sysctls -> PASS
        if not sysctl_items:
            return True

        for item in sysctl_items:
            name = self._get_value_by_key_suffix(item, "sysctls_name")
            if name is None:
                print("[Fail] Restrict_sysctls: sysctl sin campo '*_sysctls_name'.")
                return False

            name_str = str(name).strip()
            if name_str not in self.SYSCTL_ALLOWLIST:
                print(f"[Fail] Restrict_sysctls: sysctl '{name_str}' no permitido.")
                return False

        return True
    
    def _validate_prevent_cr8escape_sysctl_values(self, config_elements):
        sysctl_items = self._find_dict_list_under_key_suffix_recursive(config_elements, "sysctls")

        if not sysctl_items:
            return True

        bad_chars = re.compile(r"[+=]")

        for item in sysctl_items:
            value = self._get_value_by_key_suffix(item, "sysctls_value")
            if value is None:
                # si falta value, no hay nada que validar
                continue

            value_str = str(value)
            if bad_chars.search(value_str):
                print(f"[Fail] Prevent_cr8escape_CVE_2022_0811: valor sysctl inválido '{value_str}' (contiene '+' o '=').")
                return False

        return True
    

    def _find_container_dicts_recursive(self, data):
        """Devuelve todos los dicts que representan contenedores (items de spec.containers/init/ephemeral)."""
        containers = []

        if isinstance(data, dict):
            for k, v in data.items():
                k_str = str(k)

                # Si esta clave es una lista de contenedores
                if any(k_str.endswith(suf) for suf in self.CONTAINER_LIST_KEY_SUFFIXES) and isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            containers.append(item)

                # Seguir buscando
                if isinstance(v, (dict, list)):
                    containers.extend(self._find_container_dicts_recursive(v))

        elif isinstance(data, list):
            for it in data:
                containers.extend(self._find_container_dicts_recursive(it))

        return containers


    def _validate_require_container_port_names(self, config_elements):
        """
        Kyverno: para cada contenedor, si define ports[], cada item debe tener name: "*".
        En tu modelo: io_k8s_api_core_v1_Pod_spec_containers_ports_name (string no vacío).
        """
        container_dicts = self._find_container_dicts_recursive(config_elements)

        # Si no hay contenedores en este YAML, no aplica / PASS
        if not container_dicts:
            return True

        for c in container_dicts:
            # (Opcional) nombre del contenedor para debug
            c_name = self._get_value_by_key_suffix(c, "containers_name")
            c_name = str(c_name) if c_name is not None else "<unknown>"

            # localizar ports dentro del dict del contenedor
            ports_items = []
            for k, v in c.items():
                if str(k).endswith("ports") and isinstance(v, list):
                    ports_items = [it for it in v if isinstance(it, dict)]
                    break

            # si el contenedor no define ports, no hay nada que exigir
            if not ports_items:
                continue

            # si define ports, cada port debe tener ports_name no vacío
            for p in ports_items:
                port_name = self._get_value_by_key_suffix(p, "ports_name")
                if port_name is None or str(port_name).strip() == "":
                    print(f"[Fail] Require_Container_Port_Names: contenedor '{c_name}' tiene un port sin 'name'.")
                    return False

        return True
    



    """
    def _validate_require_imagepullsecrets(self, config_elements):
        #Kyverno require-imagepullsecrets:
        #Si algún container image registry NO es ghcr.io ni quay.io => requiere spec.imagePullSecrets[0].name no vacío
    

        # 1) sacar todas las imágenes del manifest (ya tienes helper + sufijos)
        images = self._find_image_values_recursive(config_elements)
        if not images:
            return True  # sin imágenes, no aplica

        allowed = {"ghcr.io", "quay.io"}

        def extract_registry(image: str) -> str | None:
        
            #Kubernetes image reference rules (simplificado):
            #- Si no hay '/', suele ser Docker Hub library -> registry implícito (no es ghcr/quay)
            #- Si hay '/', el primer segmento puede ser registry si contiene '.' o ':' o es 'localhost'
         
            if not isinstance(image, str) or not image:
                return None
            first = image.split("/")[0]
            if "." in first or ":" in first or first == "localhost":
                return first
            return None  # registry implícito (docker hub)

        # 2) chequear precondición: AnyNotIn -> si existe alguno fuera del allowlist
        needs_secret = False
        for img in images:
            reg = extract_registry(img)
            if reg is None:
                # docker hub / registry implícito => NO está en allowlist, por tanto dispara
                needs_secret = True
                break
            if reg not in allowed:
                needs_secret = True
                break

        if not needs_secret:
            return True  # todos en ghcr/quay

        # 3) validar imagePullSecrets name ?*
        # en YAML: spec.imagePullSecrets: - name: "...".
        # En tu JSON aplanado puede salir como lista de dicts o claves con sufijo.
        secret_names = self._find_values_by_suffix_recursive(config_elements, "imagePullSecrets_name")
        # fallback común si tu flatten lo nombra distinto:
        if not secret_names:
            secret_names = self._find_values_by_suffix_recursive(config_elements, "_spec_imagePullSecrets_name")

        # ?* => no vacío / no whitespace
        for name in secret_names:
            if isinstance(name, str) and name.strip():
                return True

        print("[Fail] Require_imagePullSecrets: se detectó registry no permitido y falta spec.imagePullSecrets[].name.")
        return False """
