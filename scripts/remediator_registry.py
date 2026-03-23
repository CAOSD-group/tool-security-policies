class RemediationRegistry:
    def __init__(self, uvl_path: str=None):
        self.registry = {}
        
        # DOMAIN BOUNDING STRATEGY: Mapeo exacto 1:1 a los nodos hoja del UVL.
        # Esto garantiza el "Minimal Change" en el AST sin sobrescribir listas/padres.
        self.registry = {
            
            # --- Network & Services ---
            "Restrict_Service_Port_Range": [
                {"feature_to_fix": "io_k8s_api_core_v1_Service_spec_ports_port", "safe_value": 32000}
            ],
            "Disallow_Localhost_ExternalName_Services": [
                {"feature_to_fix": "io_k8s_api_core_v1_Service_spec_externalName", "safe_value": "development.local"}
            ],
            "Require_Ingress_HTTPS": [
                {"feature_to_fix": "io_k8s_api_networking_v1_Ingress_metadata_annotations_kubernetes_io_ingress_allow_http", "safe_value": "false"}
            ],
            "Disallow_NodePort": [
                {"feature_to_fix": "io_k8s_api_core_v1_Service_spec_type", "safe_value": "ClusterIP"}
            ],
            "Restrict_External_IPs": [
                {"feature_to_fix": "io_k8s_api_core_v1_Service_spec_externalIPs", "safe_value": False}
            ],
            "Disallow_Service_Type_LoadBalancer": [
                {"feature_to_fix": "io_k8s_api_core_v1_Service_spec_type", "safe_value": "ClusterIP"}
            ],

            # --- Workload & Scalability ---
            "Require_Multiple_Replicas": [
                {"feature_to_fix": "io_k8s_api_apps_v1_Deployment_spec_replicas", "safe_value": 2}
            ],
            "Disallow_Default_Namespace": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_metadata_namespace", "safe_value": "secure-namespace"},
                {"feature_to_fix": "io_k8s_api_apps_v1_DaemonSet_metadata_namespace", "safe_value": "secure-namespace"},
                {"feature_to_fix": "io_k8s_api_apps_v1_Deployment_metadata_namespace", "safe_value": "secure-namespace"},
                {"feature_to_fix": "io_k8s_api_batch_v1_Job_metadata_namespace", "safe_value": "secure-namespace"},
                {"feature_to_fix": "io_k8s_api_apps_v1_StatefulSet_metadata_namespace", "safe_value": "secure-namespace"}
            ],
            "PodDisruptionBudget_maxUnavailable_Non_Zero": [
                {"feature_to_fix": "io_k8s_api_policy_v1_PodDisruptionBudget_spec_maxUnavailable_asInteger", "safe_value": 1}
            ],
            "hpaMinAvailability": [
                {"feature_to_fix": "io_k8s_api_autoscaling_v1_HorizontalPodAutoscaler_spec_minReplicas", "safe_value": 3}
            ],
            "hpaMaxAvailability": [
                {"feature_to_fix": "io_k8s_api_autoscaling_v1_HorizontalPodAutoscaler_spec_maxReplicas", "safe_value": 10}
            ],
            
            # --- Security Context, Privileges & Capabilities ---
            "Require_Run_As_Non_Root_User": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_runAsUser_valueInt", "safe_value": 10000},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_ephemeralContainers_securityContext_runAsUser_valueInt", "safe_value": 10000},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_initContainers_securityContext_runAsUser_valueInt", "safe_value": 10000},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_containers_securityContext_runAsUser_valueInt", "safe_value": 10000}
            ],
            "Check_supplementalGroups": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_supplementalGroups_IntegerValue", "safe_value": 100}
            ],
            "Require_Non_Root_Groups": [ 
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_supplementalGroups_IntegerValue", "safe_value": 100}, 
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_fsGroup_valueInt", "safe_value": 2000}
            ],
            "Validate_User_ID_Group_ID_and_FS_Group": [ 
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_runAsUser_valueInt", "safe_value": 1000}, 
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_runAsGroup_valueInt", "safe_value": 3000}, 
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_fsGroup_valueInt", "safe_value": 2000}
            ],
            "Require_Run_As_ContainerUser_Windows": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_windowsOptions_runAsUserName", "safe_value": "ContainerUser"},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_initContainers_securityContext_windowsOptions_runAsUserName", "safe_value": "ContainerUser"},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_containers_securityContext_windowsOptions_runAsUserName", "safe_value": "ContainerUser"}
            ],
            "Restrict_sysctls": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_sysctls_name", "safe_value": "kernel_shm_rmid_forced"}
            ],
            "Prevent_cr8escape_CVE_2022_0811": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_sysctls_value", "safe_value": "safe-value"}
            ],
            "insecureCapabilities": [
                {"feature_to_fix": "io_k8s_api_core_v1_Container_securityContext_capabilities_drop_StringValue", "safe_value": "ALL"}
            ],
            "dangerousCapabilities": [
                {"feature_to_fix": "io_k8s_api_core_v1_Container_securityContext_capabilities_add_StringValue", "safe_value": "NONE"}
            ],
            
            # --- Storage & Volumes ---
            "Require_StorageClass": [
                {"feature_to_fix": "io_k8s_api_core_v1_PersistentVolumeClaim_spec_storageClassName", "safe_value": "standard"},
                {"feature_to_fix": "io_k8s_api_apps_v1_StatefulSet_spec_volumeClaimTemplates_spec_storageClassName", "safe_value": "standard"}
            ],
            "Restrict_StorageClass": [
                {"feature_to_fix": "io_k8s_api_storage_v1_StorageClass_reclaimPolicy", "safe_value": "Delete"}
            ],
            "Limit_hostPath_PersistentVolumes_to_Specific_Directories": [
                {"feature_to_fix": "io_k8s_api_core_v1_PersistentVolume_spec_hostPath_path", "safe_value": "/data/secure"}
            ],
            "Enforce_ReadWriteOncePod": [
                {"feature_to_fix": "io_k8s_api_core_v1_PersistentVolumeClaim_spec_accessModes_StringValue", "safe_value": "ReadWriteOncePod"}
            ],
            "Disallow_CRI_socket_mounts": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_volumes_hostPath_path", "safe_value": "/data/secure"}
            ],
            "Disallow_hostPath": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_volumes_hostPath", "safe_value": False}
            ],
            
            # --- RBAC & Authentication ---
            "Restrict_Binding_to_Cluster_Admin": [
                {"feature_to_fix": "io_k8s_api_rbac_v1_RoleBinding_roleRef_name", "safe_value": "view"},
                {"feature_to_fix": "io_k8s_api_rbac_v1_ClusterRoleBinding_roleRef_name", "safe_value": "view"}
            ],
            "Restrict_Binding_System_Groups": [
                {"feature_to_fix": "io_k8s_api_rbac_v1_RoleBinding_subjects_name", "safe_value": "safe-user"},
                {"feature_to_fix": "io_k8s_api_rbac_v1_ClusterRoleBinding_subjects_name", "safe_value": "safe-user"}
            ],
            "Deny_Secret_Service_Account_Token_Type": [
                {"feature_to_fix": "io_k8s_api_core_v1_Secret_type", "safe_value": "Opaque"}
            ],
            "Require_aws_node_DaemonSet_use_IRSA": [
                {"feature_to_fix": "io_k8s_api_apps_v1_DaemonSet_spec_template_spec_serviceAccountName", "safe_value": "irsa-sa"}
            ],
            "Restrict_Auto_Mount_of_Service_Account_Tokens": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_automountServiceAccountToken", "safe_value": False}
            ],
            "Restrict_Auto_Mount_of_Service_Account_Tokens_in_Service_Account": [
                {"feature_to_fix": "io_k8s_api_core_v1_ServiceAccount_automountServiceAccountToken", "safe_value": False}
            ],
            
            # --- Strings & Enums ---
            "Check_Environment_Variables": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_containers_env_value", "safe_value": "false"}
            ],
            "Require_Pod_priorityClassName": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_priorityClassName", "safe_value": "high-priority"}
            ],
            "Restrict_control_plane_scheduling": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_tolerations_key", "safe_value": "dedicated-node"}
            ],
            "Restrict_Image_Registries": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_ephemeralContainers_image", "safe_value": "eu_foo_io/secure-image:v1"},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_initContainers_image", "safe_value": "eu_foo_io/secure-image:v1"},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_containers_image", "safe_value": "eu_foo_io/secure-image:v1"}
            ],
            "tagNotSpecified": [
                {"feature_to_fix": "io_k8s_api_core_v1_Container_image", "safe_value": "nginx:v1.28.0"}
            ],
            "Require_imagePullPolicy_Always": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_containers_imagePullPolicy_Always", "safe_value": True}
            ],
            "pullPolicyNotAlways": [
                {"feature_to_fix": "io_k8s_api_core_v1_Container_imagePullPolicy_Always", "safe_value": True}
            ],
            "hostPortSet": [
                {"feature_to_fix": "io_k8s_api_core_v1_Container_ports_hostPort", "safe_value": 0}
            ],
            "Disallow_hostPorts": [
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_ephemeralContainers_ports_hostPort", "safe_value": 0},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_initContainers_ports_hostPort", "safe_value": 0},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_containers_ports_hostPort", "safe_value": 0}
            ],

            # =========================================================
            # MACRO-WORKLOADS (Políticas expandidas) - NODOS HOJA EXACTOS
            # =========================================================
            "no_root": [
                {"feature_to_fix": "io_k8s_api_batch_v1_CronJob_spec_jobTemplate_spec_template_spec_containers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_batch_v1_CronJob_spec_jobTemplate_spec_template_spec_initContainers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_apps_v1_DaemonSet_spec_template_spec_containers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_apps_v1_DaemonSet_spec_template_spec_initContainers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_apps_v1_Deployment_spec_template_spec_containers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_apps_v1_Deployment_spec_template_spec_initContainers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_batch_v1_Job_spec_template_spec_containers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_batch_v1_Job_spec_template_spec_initContainers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_containers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_initContainers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_apps_v1_ReplicaSet_spec_template_spec_containers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_apps_v1_ReplicaSet_spec_template_spec_initContainers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_core_v1_ReplicationController_spec_template_spec_containers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_core_v1_ReplicationController_spec_template_spec_initContainers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_apps_v1_StatefulSet_spec_template_spec_containers_securityContext_runAsNonRoot", "safe_value": True},
                {"feature_to_fix": "io_k8s_api_apps_v1_StatefulSet_spec_template_spec_initContainers_securityContext_runAsNonRoot", "safe_value": True}
            ],

            "use_high_uid": [
                {"feature_to_fix": "io_k8s_api_batch_v1_CronJob_spec_jobTemplate_spec_template_spec_containers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_batch_v1_CronJob_spec_jobTemplate_spec_template_spec_initContainers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_DaemonSet_spec_template_spec_containers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_DaemonSet_spec_template_spec_initContainers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_Deployment_spec_template_spec_containers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_Deployment_spec_template_spec_initContainers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_batch_v1_Job_spec_template_spec_containers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_batch_v1_Job_spec_template_spec_initContainers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_containers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_initContainers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_ReplicaSet_spec_template_spec_containers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_ReplicaSet_spec_template_spec_initContainers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_core_v1_ReplicationController_spec_template_spec_containers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_core_v1_ReplicationController_spec_template_spec_initContainers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_StatefulSet_spec_template_spec_containers_securityContext_runAsUser_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_StatefulSet_spec_template_spec_initContainers_securityContext_runAsUser_valueInt", "safe_value": 10001}
            ],

            "use_high_gid": [
                {"feature_to_fix": "io_k8s_api_batch_v1_CronJob_spec_jobTemplate_spec_template_spec_containers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_batch_v1_CronJob_spec_jobTemplate_spec_template_spec_initContainers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_DaemonSet_spec_template_spec_containers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_DaemonSet_spec_template_spec_initContainers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_Deployment_spec_template_spec_containers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_Deployment_spec_template_spec_initContainers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_batch_v1_Job_spec_template_spec_containers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_batch_v1_Job_spec_template_spec_initContainers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_containers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_initContainers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_ReplicaSet_spec_template_spec_containers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_ReplicaSet_spec_template_spec_initContainers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_core_v1_ReplicationController_spec_template_spec_containers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_core_v1_ReplicationController_spec_template_spec_initContainers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_StatefulSet_spec_template_spec_containers_securityContext_runAsGroup_valueInt", "safe_value": 10001},
                {"feature_to_fix": "io_k8s_api_apps_v1_StatefulSet_spec_template_spec_initContainers_securityContext_runAsGroup_valueInt", "safe_value": 10001}
            ]
        }

    def get_remediation_actions(self, policy_name: str) -> list:
        return self.registry.get(policy_name, [])