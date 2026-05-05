class RemediationRegistry:
    def __init__(self, uvl_path: str = None):
        """
        Registro Estático de Remediaciones (Fallback Semántico) para Kube-Sec Analyzer.
        
        DOMAIN BOUNDING STRATEGY:
        - DYNAMIC_ALL_CONTAINERS_ : Expande a main, init y ephemeral (Trivy/Seguridad Estricta).
        - DYNAMIC_MAIN_CONTAINERS_: Expande SOLO a main containers (Polaris/Fiabilidad).
        - DYNAMIC_POD_CONTAINERS_ : Expande a contenedores SOLO si el Workload es directamente un Pod (Kyverno).
        - DYNAMIC_POD_SUFFIX_     : Aplica a la raíz del PodSpec (aplica en Deployments, DaemonSets, etc.).
        - DYNAMIC_ROOT_SUFFIX_    : Aplica a la raíz del manifiesto (Metadata, Replicas).
        - {$remove: val}          : Operador de mutación segura para listas.
        """
        self.registry = {

            # =========================================================
            # 1. TRIVY: SEGURIDAD ESTRICTA (Aplica a TODOS los contenedores de cualquier workload)
            # =========================================================
            "no_privileged_containers": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_privileged", "safe_value": False}],
            "no_root": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_runAsNonRoot", "safe_value": True}],
            "use_high_uid": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_runAsUser", "safe_value": 10001}],
            "use_high_gid": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_runAsGroup", "safe_value": 10001}],
            "no_sysadmin_capability": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_capabilities_add", "safe_value": {"$remove": "SYS_ADMIN"}}],
            "no_sysmodule_capability": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_capabilities_add", "safe_value": {"$remove": "SYS_MODULE"}}],
            
            # --- Gestión de Imágenes (Se apoyan en tu token mágico) ---
            "tagNotSpecified": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_image", "safe_value": "__MAKE_IMAGE_SECURE__"}],
            "Require_Images_Use_Checksums": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_image", "safe_value": "__MAKE_IMAGE_SECURE__"}],
            "Restrict_Image_Registries": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_image", "safe_value": "__MAKE_IMAGE_SECURE__"}],

            # =========================================================
            # 2. POLARIS: FIABILIDAD Y RECURSOS (Aplica SÓLO a main containers)
            # =========================================================
            "pullPolicyNotAlways": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_imagePullPolicy", "safe_value": "Always"}],
            "Require_imagePullPolicy_Always": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_imagePullPolicy", "safe_value": "Always"}],
            "hostPortSet": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_ports_hostPort", "safe_value": 0}],
            "Require_Container_Port_Names": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_ports_name", "safe_value": "secure-port"}],
            
            # --- Sondas (Probes) ---
            "livenessProbeMissing": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_livenessProbe", "safe_value": {"exec": {"command": ["cat", "/tmp/healthy"]}, "initialDelaySeconds": 5, "periodSeconds": 5}}],
            "readinessProbeMissing": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_readinessProbe", "safe_value": {"exec": {"command": ["cat", "/tmp/healthy"]}, "initialDelaySeconds": 5, "periodSeconds": 5}}],
            
            # --- Hardware (Polaris Regex) ---
            "cpuLimitsMissing": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_resources_limits_cpu", "safe_value": "100m"}],
            "cpuRequestsMissing": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_resources_requests_cpu", "safe_value": "100m"}],
            "memoryLimitsMissing": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_resources_limits_memory", "safe_value": "512Mi"}],
            "memoryRequestsMissing": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_resources_requests_memory", "safe_value": "512Mi"}],
            
            # --- Capacidades ---
            "insecureCapabilities": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_capabilities_drop", "safe_value": ["ALL"]}],
            "dangerousCapabilities": [
                {"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_capabilities_add", "safe_value": {"$remove": "ALL"}},
                {"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_capabilities_add", "safe_value": {"$remove": "SYS_ADMIN"}},
                {"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_capabilities_add", "safe_value": {"$remove": "NET_ADMIN"}}
            ],

            # =========================================================
            # 3. KYVERNO: POD CONTAINERS (Reglas de Kyverno exclusivas para Pods)
            # =========================================================
            "Disallow_Privilege_Escalation": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_allowPrivilegeEscalation", "safe_value": False}],
            "Disallow_Privileged_Containers": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_privileged", "safe_value": False}],
            "Require_Read_Only_Root_Filesystem": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_readOnlyRootFilesystem", "safe_value": True}],
            "Disallow_procMount": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_procMount", "safe_value": "Default"}],
            "Require_Run_As_Non_Root_User": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_runAsUser", "safe_value": 10001}],
            "Require_Run_As_ContainerUser_Windows": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_windowsOptions_runAsUserName", "safe_value": "ContainerUser"}],
            "Disallow_hostPorts": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_ports_hostPort", "safe_value": 0}],

            # =========================================================
            # 4. POD SPEC (Atributos base del Pod, aplica a Deployments, DaemonSets, etc.)
            # =========================================================
            "no_host_network": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostNetwork", "safe_value": False}],
            "no_shared_ipc_namespace": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostIPC", "safe_value": False}],
            "no_host_pid": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostPID", "safe_value": False}],
            "Disallow_Host_Namespaces": [
                {"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostNetwork", "safe_value": False},
                {"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostIPC", "safe_value": False},
                {"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostPID", "safe_value": False}
            ],
            
            "no_auto_mount_service_token": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_automountServiceAccountToken", "safe_value": False}],
            "Restrict_Auto_Mount_of_Service_Account_Tokens": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_automountServiceAccountToken", "safe_value": False}],
            "Require_Pod_priorityClassName": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_priorityClassName", "safe_value": "high-priority"}],
            
            "Disallow_hostProcess": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_windowsOptions_hostProcess", "safe_value": False}],
            "Restrict_control_plane_scheduling": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_tolerations", "safe_value": []}], # Evitar programar en master
            "Prevent_cr8escape_CVE_2022_0811": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_sysctls", "safe_value": []}], # Borrar sysctls peligrosos
            
            # --- Grupos del Pod ---
            "Check_supplementalGroups": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_supplementalGroups", "safe_value": [100]}],
            "Require_Non_Root_Groups": [
                {"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_supplementalGroups", "safe_value": [100]},
                {"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_fsGroup", "safe_value": 2000}
            ],
            "Validate_User_ID_Group_ID_and_FS_Group": [
                {"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_runAsUser", "safe_value": 1000},
                {"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_runAsGroup", "safe_value": 3000},
                {"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_fsGroup", "safe_value": 2000}
            ],

            # --- Volumes ---
            "Disallow_hostPath": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_volumes", "safe_value": []}], # Si hay hostPaths, los vaciamos para forzar volúmenes seguros
            "Disallow_CRI_socket_mounts": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_volumes", "safe_value": []}],
            "Limit_hostPath_PersistentVolumes_to_Specific_Directories": [{"feature_to_fix": "io_k8s_api_core_v1_PersistentVolume_spec_hostPath_path", "safe_value": "/data"}],
            "Enforce_ReadWriteOncePod": [{"feature_to_fix": "io_k8s_api_core_v1_PersistentVolumeClaim_spec_accessModes", "safe_value": ["ReadWriteOncePod"]}],

            # =========================================================
            # 5. METADATA Y ESCALABILIDAD (Raíz del Controlador)
            # =========================================================
            "Disallow_Default_Namespace": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_metadata_namespace", "safe_value": "secure-namespace"}],
            "Require_Multiple_Replicas": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_spec_replicas", "safe_value": 2}],
            "hpaMinAvailability": [{"feature_to_fix": "io_k8s_api_autoscaling_v1_HorizontalPodAutoscaler_spec_minReplicas", "safe_value": 3}],
            "hpaMaxAvailability": [{"feature_to_fix": "io_k8s_api_autoscaling_v1_HorizontalPodAutoscaler_spec_maxReplicas", "safe_value": 10}],
            "PodDisruptionBudget_maxUnavailable_Non_Zero": [{"feature_to_fix": "io_k8s_api_policy_v1_PodDisruptionBudget_spec_maxUnavailable", "safe_value": 1}],

            # =========================================================
            # 6. NETWORKING (Services & Ingress)
            # =========================================================
            "Restrict_Service_Port_Range": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_ports_port", "safe_value": 32000}],
            "Disallow_Localhost_ExternalName_Services": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_externalName", "safe_value": "development.local"}],
            "Require_Ingress_HTTPS": [{"feature_to_fix": "io_k8s_api_networking_v1_Ingress_metadata_annotations_kubernetes_io_ingress_allow_http", "safe_value": "false"}],
            "Disallow_NodePort": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_type", "safe_value": "ClusterIP"}],
            "Restrict_External_IPs": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_externalIPs", "safe_value": []}],
            "Disallow_Service_Type_LoadBalancer": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_type", "safe_value": "ClusterIP"}],
            "tlsSettingsMissing": [{"feature_to_fix": "io_k8s_api_networking_v1_Ingress_spec_tls", "safe_value": [{"hosts": ["secure.example.com"], "secretName": "tls-secret"}]}],

            # =========================================================
            # 7. RBAC & CLUSTER SECURITY
            # ==========================================
            "Restrict_Binding_to_Cluster_Admin": [
                {"feature_to_fix": "io_k8s_api_rbac_v1_RoleBinding_roleRef_name", "safe_value": "view"},
                {"feature_to_fix": "io_k8s_api_rbac_v1_ClusterRoleBinding_roleRef_name", "safe_value": "view"}
            ],
            "Restrict_Binding_System_Groups": [
                {"feature_to_fix": "io_k8s_api_rbac_v1_RoleBinding_subjects_name", "safe_value": "safe-user"},
                {"feature_to_fix": "io_k8s_api_rbac_v1_ClusterRoleBinding_subjects_name", "safe_value": "safe-user"}
            ],
            "Deny_Secret_Service_Account_Token_Type": [{"feature_to_fix": "io_k8s_api_core_v1_Secret_type", "safe_value": "Opaque"}],
            "Require_aws_node_DaemonSet_use_IRSA": [{"feature_to_fix": "io_k8s_api_apps_v1_DaemonSet_spec_template_spec_serviceAccountName", "safe_value": "irsa-sa"}],
            "Restrict_Auto_Mount_of_Service_Account_Tokens_in_Service_Account": [{"feature_to_fix": "io_k8s_api_core_v1_ServiceAccount_automountServiceAccountToken", "safe_value": False}],
            "Require_StorageClass": [
                {"feature_to_fix": "io_k8s_api_core_v1_PersistentVolumeClaim_spec_storageClassName", "safe_value": "standard"},
                {"feature_to_fix": "io_k8s_api_apps_v1_StatefulSet_spec_volumeClaimTemplates_spec_storageClassName", "safe_value": "standard"}
            ],
            "Restrict_StorageClass": [{"feature_to_fix": "io_k8s_api_storage_v1_StorageClass_reclaimPolicy", "safe_value": "Delete"}],
            "Restrict_Jobs": [{"feature_to_fix": "io_k8s_api_batch_v1_Job_metadata_ownerReferences", "safe_value": [{"apiVersion": "batch/v1", "kind": "CronJob", "name": "parent-cronjob", "uid": "1234"}]}]
        }

    def get_remediation_actions(self, policy_name: str) -> list:
        return self.registry.get(policy_name, [])