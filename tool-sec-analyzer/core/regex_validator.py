import re
import io, contextlib

class ContentPolicyValidator:
    """
    Validator of policies based on Regex and recursive traversal of the JSON.
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

        for policy in active_policies:
            if policy in self.policy_map:
                # Ejecutamos la validación específica
                is_valid = self.policy_map[policy](config_elements)
                if not is_valid:
                    return False
        return True
    
    
    def validate_with_report(self, config_elements: dict, active_policies: list[str]):
        """
        Get a list of policies that fail with reason if any.
        """
        report = []
        passed_all = True

        for policy in active_policies:
            fn = self.policy_map.get(policy)
            if fn is None:
                continue  # no es una policy de regex

            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    ok = fn(config_elements)
                reason = buf.getvalue().strip()

                if not ok:
                    passed_all = False
                    report.append({
                        "policy": policy,
                        "reason": reason or "Regex/content validation failed."
                    })

            except Exception as e:
                passed_all = False
                report.append({
                    "policy": policy,
                    "reason": f"Regex validator error: {e}"
                })

        return passed_all, report

    def _find_image_values_recursive(self, data):
        """
        Search recursively through dicts and lists for keys that end with any of the TARGET_IMAGE_SUFFIXES.
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
        Searches recursively for values of keys that end with ANY of the target_suffixes.
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

    def _find_all_annotations_recursive(self, data):
        """
        Searches recursively for all 'annotations' blocks and returns a unified dictionary with all annotations found in the file.
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
        Implementation of the 'tagNotSpecified' policy:
        - Check A: Each image must have a tag (format: "name:tag").
        - Check B: The tag cannot be "latest".
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
        Verify that the key 'corp.org/department' exists and is not empty.
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
        Rule: The label 'app.kubernetes.io/name' must exist with some value.
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
        Verify that if there are AppArmor annotations, they must be 'runtime/default' or 'localhost/*'.
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
        Search for the annotation 'kubernetes.io/ingress_class'. If it exists, validate that its value is either 'HAProxy' or 'nginx'.
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
        """

        kinds = self._find_values_by_suffix_recursive(config_elements, "_Job_kind")
        
        if "Job" not in kinds:
            return True

        owners = self._find_owner_references_recursive(config_elements)
        
        if not owners:
            print("[Fail] Restrict_Jobs: Detectado un 'Job' manual (sin ownerReferences). Los Jobs deben ser creados por CronJobs.")
            return False

        has_cronjob_owner = False
        for owner in owners:
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
        - Apply ONLY to Ingress resources
        - Require annotation 'kubernetes.io/ingress.allow-http' = "false"
        - Require TLS (spec.tls must be defined and non-empty)
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

        regex_digest = re.compile(r".+@sha256:[0-9a-fA-F]{64}$")

        for img in images:
            if not regex_digest.match(img):
                print(f"[Fail] Require_Images_Use_Checksums: imagen '{img}' no usa digest '@sha256:...'.")
                return False
        return True
    
    def _validate_restrict_image_registries(self, config_elements):
        """
        Validate that ALL images (containers/init/ephemeral) come from allowed registries.
        Based in Kyverno: "eu.foo.io/* | bar.io/*"
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
        """Return all dicts that represent containers (items of spec.containers/init/ephemeral)."""
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
        Kyverno: for each container port defined in spec.containers/init/ephemeral, the 'name' field must be present and non-empty.
        io_k8s_api_core_v1_Pod_spec_containers_ports_name (string no vacío).
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
    
    # Polaris: New recursive helper to check if any resources cpu or memory limits/requests are defined (for future policies)


def _find_objects_in_lists_by_suffix(self, data, list_suffixes):
    """
    Searches recursively for lists whose KEY ends with any of the list_suffixes and returns all dicts (items) inside those lists.
    """
    if isinstance(list_suffixes, str):
        list_suffixes = [list_suffixes]

    found = []

    if isinstance(data, dict):
        for k, v in data.items():
            k_str = str(k)

            # Si esta clave es una lista objetivo, extraemos sus items dict
            if any(k_str.endswith(suf) for suf in list_suffixes) and isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        found.append(item)

            # Recursión
            if isinstance(v, (dict, list)):
                found.extend(self._find_objects_in_lists_by_suffix(v, list_suffixes))

    elif isinstance(data, list):
        for item in data:
            found.extend(self._find_objects_in_lists_by_suffix(item, list_suffixes))

    return found