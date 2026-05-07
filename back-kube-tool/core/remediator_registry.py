class RemediationRegistry:
    def __init__(self, uvl_path: str = None):
        """
        Registro Estático de Remediaciones (Fallback Semántico) para Kube-Sec Analyzer.
        
        DOMAIN BOUNDING STRATEGY:
        - DYNAMIC_ALL_CONTAINERS_ : Expande a main, init y ephemeral (Trivy/Seguridad Estricta).
        - DYNAMIC_MAIN_CONTAINERS_: Expande SOLO a main containers (Polaris/Fiabilidad).
        - DYNAMIC_POD_CONTAINERS_ : Expande a contenedores SOLO si el Workload es directamente un Pod (Kyverno).
        - DYNAMIC_POD_SUFFIX_     : Aplica a la raíz del PodSpec (Deployments, DaemonSets, etc.).
        - DYNAMIC_ROOT_SUFFIX_    : Aplica a la raíz del manifiesto (Metadata, Replicas).
        - {$remove: val}          : Operador de mutación segura para listas.
        """
        self.registry = {

            # =========================================================
            # 1. TRIVY: SEGURIDAD ESTRICTA & KSV (Aplica a TODOS los contenedores)
            # =========================================================
            "no_privileged_containers": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_privileged", "safe_value": False}],
            "no_root": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_runAsNonRoot", "safe_value": True}],
            "use_high_uid": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_runAsUser", "safe_value": 10001}],
            "use_high_gid": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_runAsGroup", "safe_value": 10001}],
            "no_sysadmin_capability": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_capabilities_add", "safe_value": {"$remove": "SYS_ADMIN"}}],
            "no_sysmodule_capability": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_capabilities_add", "safe_value": {"$remove": "SYS_MODULE"}}],
            
            # --- Faltantes de Trivy (Históricas / KSV) ---
            "kubernetes_no_self_privesc": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_allowPrivilegeEscalation", "safe_value": False}],
            "kubernetes_use_readonly_filesystem": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_readOnlyRootFilesystem", "safe_value": True}],
            "kubernetes_no_custom_proc_mask": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_procMount", "safe_value": {"$delete": True}}],
            "kubernetes_drop_default_capabilities": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_capabilities_drop", "safe_value": ["ALL"]}],
            "kubernetes_drop_unused_capabilities": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_capabilities_drop", "safe_value": ["ALL"]}],
            "kubernetes_no_net_raw": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_capabilities_add", "safe_value": {"$remove": "NET_RAW"}}],
            "kubernetes_no_non_default_capabilities": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_capabilities_add", "safe_value": {"$delete": True}}], 
            "kubernetes_primary_supplementary_gid": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_securityContext_runAsGroup", "safe_value": 10001}],
            ## "kubernetes_no_host_port_access": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_ports_hostPort", "safe_value": 0}],
            "kubernetes_no_host_port_access": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_ports_hostPort", "safe_value": {"$delete": True}}],
            # --- Gestión de Imágenes (Se apoyan en tu token dinámico mágico) ---
            "tagNotSpecified": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_image", "safe_value": "__MAKE_IMAGE_SECURE__"}],
            "Require_Images_Use_Checksums": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_image", "safe_value": "__MAKE_IMAGE_SECURE__"}],
            "Restrict_Image_Registries": [{"feature_to_fix": "DYNAMIC_ALL_CONTAINERS_image", "safe_value": "__MAKE_IMAGE_SECURE__"}],

            # =========================================================
            # 2. POLARIS: FIABILIDAD Y RECURSOS (Aplica SÓLO a main containers)
            # =========================================================
            "pullPolicyNotAlways": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_imagePullPolicy", "safe_value": "Always"}],
            "Require_imagePullPolicy_Always": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_imagePullPolicy", "safe_value": "Always"}],
            "hostPortSet": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_ports_hostPort", "safe_value": {"$delete": True}}], ## port 0 is invalid port in Kubernetes, "0 < x < 65536" so it effectively removes the hostPort configuration 
            "Require_Container_Port_Names": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_ports_name", "safe_value": "secure-port"}],
            "livenessProbeMissing": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_livenessProbe", "safe_value": {"exec": {"command": ["cat", "/tmp/healthy"]}, "initialDelaySeconds": 5, "periodSeconds": 5}}],
            "readinessProbeMissing": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_readinessProbe", "safe_value": {"exec": {"command": ["cat", "/tmp/healthy"]}, "initialDelaySeconds": 5, "periodSeconds": 5}}],
            "cpuLimitsMissing": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_resources_limits_cpu", "safe_value": "100m"}],
            "cpuRequestsMissing": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_resources_requests_cpu", "safe_value": "100m"}],
            "memoryLimitsMissing": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_resources_limits_memory", "safe_value": "512Mi"}],
            "memoryRequestsMissing": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_resources_requests_memory", "safe_value": "512Mi"}],
            "insecureCapabilities": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_capabilities_drop", "safe_value": ["ALL"]}],
            "dangerousCapabilities": [
                {"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_capabilities_add", "safe_value": {"$remove": "ALL"}},
                {"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_capabilities_add", "safe_value": {"$remove": "SYS_ADMIN"}},
                {"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_capabilities_add", "safe_value": {"$remove": "NET_ADMIN"}}
            ],
            
            # --- Polaris Homologación ---
            "notReadOnlyRootFilesystem": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_readOnlyRootFilesystem", "safe_value": True}],
            "privilegeEscalationAllowed": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_allowPrivilegeEscalation", "safe_value": False}],
            "runAsPrivileged": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_privileged", "safe_value": False}],
            "runAsRootAllowed": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_runAsNonRoot", "safe_value": True}],
            "linuxHardening": [{"feature_to_fix": "DYNAMIC_MAIN_CONTAINERS_securityContext_seccompProfile", "safe_value": {"type": "RuntimeDefault"}}],

            # =========================================================
            # 3. KYVERNO: POD CONTAINERS (Reglas de Kyverno exclusivas para Pods)
            # =========================================================
            "Disallow_Privilege_Escalation": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_allowPrivilegeEscalation", "safe_value": False}],
            "Disallow_Privileged_Containers": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_privileged", "safe_value": False}],
            "Require_Read_Only_Root_Filesystem": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_readOnlyRootFilesystem", "safe_value": True}],
            "Disallow_procMount": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_procMount", "safe_value": "Default"}], ## Dude for DefaultProcMount is the default value that allows the container runtime to choose the procMount type, which is typically "Unmasked" but can be more secure than "Unmasked" depending on the runtime's defaults and configuration. By setting it to "Default", you allow the runtime to apply its default security settings, which can help mitigate risks associated with custom procMount configurations.
            "Require_Run_As_Non_Root_User": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_runAsUser", "safe_value": 10001}],
            "Require_Run_As_ContainerUser_Windows": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_windowsOptions_runAsUserName", "safe_value": "ContainerUser"}],
            "Disallow_hostPorts": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_ports_hostPort", "safe_value": {"$delete": True}}], ## port 0 is invalid port in Kubernetes, "0 < x < 65536" so it effectively removes the hostPort configuration
            "Disallow_SELinux": [{"feature_to_fix": "DYNAMIC_POD_CONTAINERS_securityContext_seLinuxOptions", "safe_value": {"$remove": "ALL"}}],

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
            "priorityClassNotSet": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_priorityClassName", "safe_value": "high-priority"}],
            
            "Disallow_hostProcess": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_windowsOptions_hostProcess", "safe_value": False}],
            "kubernetes_no_hostprocess_containers": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_windowsOptions_hostProcess", "safe_value": False}],
            
            "Restrict_control_plane_scheduling": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_tolerations", "safe_value": {"$delete": True}}],
            "Prevent_cr8escape_CVE_2022_0811": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_securityContext_sysctls", "safe_value": {"$delete": True}}],
            
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

            "Disallow_hostPath": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_volumes", "safe_value": {"$delete": True}}], ## "safe_value": []
            "no_mounted_hostpath": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_volumes", "safe_value": {"$delete": True}}],
            "Disallow_CRI_socket_mounts": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_volumes_hostPath_path", "safe_value": "/data/secure"}],
            "kubernetes_no_non_ephemeral_volumes": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_volumes", "safe_value": {"$delete": True}}],
            "kubernetes_no_hostaliases": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostAliases", "safe_value": {"$delete": True}}],
            "Block_Ephemeral_Containers": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_ephemeralContainers", "safe_value": {"$delete": True}}],
            "Restrict_node_selection": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_nodeSelector", "safe_value": {"$delete": True}}],
            "Require_imagePullSecrets": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_imagePullSecrets", "safe_value": [{"name": "secure-registry-credentials"}]}], ### Not activated yet
            
            # --- Polaris Homologación ---
            "automountServiceAccountToken": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_automountServiceAccountToken", "safe_value": False}],
            "hostIPCSet": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostIPC", "safe_value": False}],
            "hostNetworkSet": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostNetwork", "safe_value": False}],
            "hostPIDSet": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_hostPID", "safe_value": False}],
            "topologySpreadConstraint": [{"feature_to_fix": "DYNAMIC_POD_SUFFIX_topologySpreadConstraints", "safe_value": [{"maxSkew": 1, "topologyKey": "topology.kubernetes.io/zone", "whenUnsatisfiable": "DoNotSchedule", "labelSelector": {"matchLabels": {"app": "secure-app"}}}]}],


            # =========================================================
            # 5. METADATA Y ESCALABILIDAD (Raíz del Controlador)
            # =========================================================
            "Disallow_Default_Namespace": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_metadata_namespace", "safe_value": "secure-namespace"}],
            "kubernetes_default_namespace_should_not_be_used": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_metadata_namespace", "safe_value": "secure-namespace"}],
            "Require_Multiple_Replicas": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_spec_replicas", "safe_value": 2}],
            "deploymentMissingReplicas": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_spec_replicas", "safe_value": 2}],
            "hpaMinAvailability": [{"feature_to_fix": "io_k8s_api_autoscaling_v1_HorizontalPodAutoscaler_spec_minReplicas", "safe_value": 3}],
            "hpaMaxAvailability": [{"feature_to_fix": "io_k8s_api_autoscaling_v1_HorizontalPodAutoscaler_spec_maxReplicas", "safe_value": 10}],
            "PodDisruptionBudget_maxUnavailable_Non_Zero": [{"feature_to_fix": "io_k8s_api_policy_v1_PodDisruptionBudget_spec_maxUnavailable", "safe_value": 1}],
            "Require_Labels": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_metadata_labels_app_kubernetes_io_name", "safe_value": "secure-app"}],
            "Require_Annotations": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_metadata_annotations_corp_org_department", "safe_value": "engineering"}],
            "Require_Kubecost_Labels": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_metadata_labels_owner", "safe_value": "platform-team"}],
            "Docker_Socket_Requires_Label": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_metadata_labels_allow_docker", "safe_value": "true"}],


            # =========================================================
            # 6. NETWORKING E INGRESS
            # =========================================================
            "Restrict_Service_Port_Range": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_ports_port", "safe_value": 32000}],
            "Disallow_Localhost_ExternalName_Services": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_externalName", "safe_value": "development.local"}],
            "Require_Ingress_HTTPS": [{"feature_to_fix": "io_k8s_api_networking_v1_Ingress_metadata_annotations_kubernetes_io_ingress_allow_http", "safe_value": "false"}],
            "Disallow_NodePort": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_type", "safe_value": "ClusterIP"}],
            "Restrict_External_IPs": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_externalIPs", "safe_value": {"$delete": True}}],
            "kubernetes_no_svc_with_extip": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_externalIPs", "safe_value": {"$delete": True}}],
            "Disallow_Service_Type_LoadBalancer": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_type", "safe_value": "ClusterIP"}], ## !Serv.io_k8s_api_core_v1_Service_spec_type_LoadBalancer
            "tlsSettingsMissing": [{"feature_to_fix": "io_k8s_api_networking_v1_Ingress_spec_tls", "safe_value": [{"hosts": ["secure.example.com"], "secretName": "tls-secret"}]}],
            "Require_Encryption_with_AWS_LoadBalancers": [{"feature_to_fix": "io_k8s_api_core_v1_Service_metadata_annotations_service_beta_kubernetes_io_aws_load_balancer_ssl_cert", "safe_value": "arn:aws:acm:region:account:certificate/uuid"}],
            "Restrict_Ingress_defaultBackend": [{"feature_to_fix": "io_k8s_api_networking_v1_Ingress_spec_defaultBackend", "safe_value": {"service": {"name": "secure-backend", "port": {"number": 443}}}}],
            "Restrict_Ingress_Classes": [{"feature_to_fix": "io_k8s_api_networking_v1_Ingress_metadata_annotations_kubernetes_io_ingress_class", "safe_value": "nginx"}],


            # =========================================================
            # 7. CLUSTER SECURITY, RBAC & NAMESPACES
            # =========================================================
            "Restrict_Binding_to_Cluster_Admin": [
                {"feature_to_fix": "io_k8s_api_rbac_v1_RoleBinding_roleRef_name", "safe_value": "view"},
                {"feature_to_fix": "io_k8s_api_rbac_v1_ClusterRoleBinding_roleRef_name", "safe_value": "view"}
            ],
            "Restrict_Binding_System_Groups": [
                {"feature_to_fix": "io_k8s_api_rbac_v1_RoleBinding_subjects_name", "safe_value": "safe-user"},
                {"feature_to_fix": "io_k8s_api_rbac_v1_ClusterRoleBinding_subjects_name", "safe_value": "safe-user"}
            ],
            "kubernetes_no_anonymous_user_bind": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_subjects_name", "safe_value": "authorized-user"}],
            "kubernetes_no_system_masters_group_bind": [{"feature_to_fix": "DYNAMIC_ROOT_SUFFIX_subjects_name", "safe_value": "authorized-group"}],
            "Deny_Secret_Service_Account_Token_Type": [{"feature_to_fix": "io_k8s_api_core_v1_Secret_type", "safe_value": "Opaque"}],
            "Require_aws_node_DaemonSet_use_IRSA": [{"feature_to_fix": "io_k8s_api_apps_v1_DaemonSet_spec_template_spec_serviceAccountName", "safe_value": "irsa-sa"}],
            "Restrict_Auto_Mount_of_Service_Account_Tokens_in_Service_Account": [{"feature_to_fix": "io_k8s_api_core_v1_ServiceAccount_automountServiceAccountToken", "safe_value": False}],
            "Require_StorageClass": [
                {"feature_to_fix": "io_k8s_api_core_v1_PersistentVolumeClaim_spec_storageClassName", "safe_value": "standard"},
                {"feature_to_fix": "io_k8s_api_apps_v1_StatefulSet_spec_volumeClaimTemplates_spec_storageClassName", "safe_value": "standard"}
            ],
            "Restrict_StorageClass": [{"feature_to_fix": "io_k8s_api_storage_v1_StorageClass_reclaimPolicy", "safe_value": "Delete"}],
            "Limit_hostPath_PersistentVolumes_to_Specific_Directories": [{"feature_to_fix": "io_k8s_api_core_v1_PersistentVolume_spec_hostPath_path", "safe_value": "/data"}],
            "Enforce_ReadWriteOncePod": [{"feature_to_fix": "io_k8s_api_core_v1_PersistentVolumeClaim_spec_accessModes", "safe_value": ["ReadWriteOncePod"]}],
            "Restrict_Jobs": [{"feature_to_fix": "io_k8s_api_batch_v1_Job_metadata_ownerReferences", "safe_value": [{"apiVersion": "batch/v1", "kind": "CronJob", "name": "parent-cronjob", "uid": "1234"}]}],
            "kubernetes_limit_range_usage": [{"feature_to_fix": "io_k8s_api_core_v1_LimitRange_spec_limits_type", "safe_value": "Container"}],
            
            # --- Reglas de Nivel Namespace ---
            "Add_PSA_Namespace_Reporting": [{"feature_to_fix": "io_k8s_api_core_v1_Namespace_metadata_labels_pod_security_kubernetes_io_enforce", "safe_value": "restricted"}],
            "Enforce_Istio_Ambient_Mode": [{"feature_to_fix": "io_k8s_api_core_v1_Namespace_metadata_labels_istio_io_dataplane_mode", "safe_value": "ambient"}],
            "Enforce_Istio_Sidecar_Injection": [{"feature_to_fix": "io_k8s_api_core_v1_Namespace_metadata_labels_istio_injection", "safe_value": "enabled"}],
            "Require_Linkerd_Mesh_Injection": [{"feature_to_fix": "io_k8s_api_core_v1_Namespace_metadata_annotations_linkerd_io_inject", "safe_value": "enabled"}],
            "Validate_Data_Protection_with_Kasten_Preset_Label": [{"feature_to_fix": "io_k8s_api_core_v1_Namespace_metadata_labels_dataprotection", "safe_value": "protected"}]
        }

    def get_remediation_actions(self, policy_name: str) -> list:
        return self.registry.get(policy_name, [])