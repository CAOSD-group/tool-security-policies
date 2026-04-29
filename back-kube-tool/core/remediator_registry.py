class RemediationRegistry:
    def __init__(self, uvl_path: str = None):
        """
        Registro Estático de Remediaciones (Fallback Semántico).
        Exclusivamente mapea las políticas activas en la sección 'constraints' del UVL.
        Utiliza sufijos dinámicos para abstraer el Kind del recurso y garantizar el Mínimo Cambio.
        """
        self.registry = {

            # ==========================================
            # 1. POLÍTICAS DE CONTENEDOR (SecurityContext, Image, Probes)
            # ==========================================
            # --- Privilegios y Escalada ---
            "kubernetes_no_self_privesc": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_allowPrivilegeEscalation", "safe_value": False}],
            "Disallow_Privilege_Escalation": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_allowPrivilegeEscalation", "safe_value": False}],
            "no_privileged_containers": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_privileged", "safe_value": False}],
            "Disallow_Privileged_Containers": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_privileged", "safe_value": False}],
            
            # --- Filesystem y ProcMount ---
            "kubernetes_use_readonly_filesystem": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_readOnlyRootFilesystem", "safe_value": True}],
            "Require_Read_Only_Root_Filesystem": [{"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_containers_securityContext_readOnlyRootFilesystem", "safe_value": True}],
            "kubernetes_no_custom_proc_mask": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_procMount", "safe_value": "Default"}],
            "Disallow_procMount": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_procMount", "safe_value": "Default"}],
            
            # --- Capacidades (Capabilities) ---
            "kubernetes_drop_default_capabilities": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_capabilities_drop", "safe_value": ["ALL"]}],
            "kubernetes_drop_unused_capabilities": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_capabilities_drop", "safe_value": ["ALL"]}],
            "insecureCapabilities": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_capabilities_drop", "safe_value": ["ALL"]}],
            "kubernetes_no_non_default_capabilities": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_capabilities_add", "safe_value": ["NONE"]}],
            "dangerousCapabilities": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_capabilities_add", "safe_value": []}], ## Encontrar en la definicion de la politica
            "no_sysadmin_capability": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_capabilities_add", "safe_value": []}],
            "no_sysmodule_capability": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_capabilities_add", "safe_value": []}],
            "kubernetes_no_net_raw": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_capabilities_add", "safe_value": []}],
            
            # --- Usuarios y Grupos (UID/GID) ---
            "no_root": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_runAsNonRoot", "safe_value": True}],
            "Require_Run_As_Non_Root_User": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_runAsNonRoot", "safe_value": True}],
            "use_high_uid": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_runAsUser", "safe_value": 10001}],
            "use_high_gid": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_runAsGroup", "safe_value": 10001}],
            "kubernetes_primary_supplementary_gid": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_runAsGroup", "safe_value": 10001}],
            "Require_Run_As_ContainerUser_Windows": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_securityContext_windowsOptions_runAsUserName", "safe_value": "ContainerUser"}],

            # --- Imágenes ---
            "pullPolicyNotAlways": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_imagePullPolicy", "safe_value": "Always"}],
            "Require_imagePullPolicy_Always": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_imagePullPolicy", "safe_value": "Always"}],
            
            # --- Sondas (Probes) ---
            "livenessProbeMissing": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_livenessProbe", "safe_value": {"exec": {"command": ["cat", "/tmp/healthy"]}, "initialDelaySeconds": 5, "periodSeconds": 5}}],
            "readinessProbeMissing": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_readinessProbe", "safe_value": {"exec": {"command": ["cat", "/tmp/healthy"]}, "initialDelaySeconds": 5, "periodSeconds": 5}}],

            # --- Puertos del contenedor ---
            "kubernetes_no_host_port_access": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_ports_hostPort", "safe_value": 0}],
            "Disallow_hostPorts": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_ports_hostPort", "safe_value": 0}],
            "hostPortSet": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_ports_hostPort", "safe_value": 0}],
            "Require_Container_Port_Names": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_ports_name", "safe_value": "app-port"}],

            # --- Recursos (Polaris) ---
            # Nota: memoryLimitsMissing y memoryRequestsMissing fueron filtrados por no estar en constraints.
            "cpuLimitsMissing": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_resources_limits_cpu", "safe_value": "100m"}],
            "cpuRequestsMissing": [{"feature_to_fix": "DYNAMIC_CONTAINER_SUFFIX_resources_requests_cpu", "safe_value": "100m"}],


            # ==========================================
            # 2. POLÍTICAS DE POD (Afectan a todo el PodSpec)
            # ==========================================
            # --- Host Namespaces ---
            "no_host_network": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostNetwork", "safe_value": False}],
            "no_shared_ipc_namespace": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostIPC", "safe_value": False}],
            "no_host_pid": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostPID", "safe_value": False}],
            "Disallow_Host_Namespaces": [
                {"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostNetwork", "safe_value": False},
                {"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostIPC", "safe_value": False},
                {"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostPID", "safe_value": False}
            ],
            
            # --- Service Account Tokens ---
            "no_auto_mount_service_token": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_automountServiceAccountToken", "safe_value": False}],
            "Restrict_Auto_Mount_of_Service_Account_Tokens": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_automountServiceAccountToken", "safe_value": False}],
            
            # --- HostAliases y Windows Options ---
            "kubernetes_no_hostaliases": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostAliases", "safe_value": []}],
            "kubernetes_no_hostprocess_containers": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_windowsOptions_hostProcess", "safe_value": False}],
            "Disallow_hostProcess": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_windowsOptions_hostProcess", "safe_value": False}],

            # --- Confiabilidad y Volúmenes ---
            "topologySpreadConstraint": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_topologySpreadConstraints", "safe_value": [{"maxSkew": 1, "topologyKey": "topology.kubernetes.io/zone", "whenUnsatisfiable": "DoNotSchedule", "labelSelector": {"matchLabels": {"app": "secure-app"}}}]}],
            "no_mounted_hostpath": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_volumes", "safe_value": []}],
            "Disallow_hostPath": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_volumes", "safe_value": []}],


            # ==========================================
            # 3. POLÍTICAS DE METADATA (Raíz del Controlador)
            # ==========================================
            "kubernetes_default_namespace_should_not_be_used": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_metadata_namespace", "safe_value": "production-secure"}],
            "Disallow_Default_Namespace": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_metadata_namespace", "safe_value": "production-secure"}],
            
            # --- Controladores (HPA, Deployments) ---
            "Require_Multiple_Replicas": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_spec_replicas", "safe_value": 3}],
            "hpaMinAvailability": [{"feature_to_fix": "io_k8s_api_autoscaling_v1_HorizontalPodAutoscaler_spec_minReplicas", "safe_value": 2}],
            "hpaMaxAvailability": [{"feature_to_fix": "io_k8s_api_autoscaling_v1_HorizontalPodAutoscaler_spec_maxReplicas", "safe_value": 5}],


            # ==========================================
            # 4. POLÍTICAS DE RED Y SERVICIOS (Services & Ingress)
            # ==========================================
            "Restrict_Service_Port_Range": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_ports_port", "safe_value": 32000}],
            "Disallow_Localhost_ExternalName_Services": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_externalName", "safe_value": "development.local"}],
            "tlsSettingsMissing": [{"feature_to_fix": "io_k8s_api_networking_v1_Ingress_spec_tls", "safe_value": [{"hosts": ["secure.example.com"], "secretName": "tls-secret"}]}],
            "Disallow_NodePort": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_type", "safe_value": "ClusterIP"}],
            "kubernetes_no_svc_with_extip": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_externalIPs", "safe_value": []}],
            "Restrict_External_IPs": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_externalIPs", "safe_value": []}],


            # ==========================================
            # 5. POLÍTICAS RBAC (RoleBinding & ClusterRoleBinding)
            # ==========================================
            "kubernetes_no_anonymous_user_bind": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_subjects_name", "safe_value": "authorized-user"}],
            "kubernetes_no_system_masters_group_bind": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_subjects_name", "safe_value": "authorized-group"}],
            "Restrict_Binding_System_Groups": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_subjects_name", "safe_value": "authorized-group"}]

        }

    def get_remediation_actions(self, policy_name: str):
        return self.registry.get(policy_name, [])