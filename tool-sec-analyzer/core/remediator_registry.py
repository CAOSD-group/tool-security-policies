import re

class RemediationRegistry:
    def __init__(self, uvl_path: str):
        self.registry = {}
        # Aquí pones las decisiones "arquitectónicas" manuales
        self.manual_overrides = {
            "Disallow_Default_Namespace": [{"feature_to_fix": "io_k8s_api_core_v1_Pod_metadata_namespace", "safe_value": "kube-system"}],
            "PodDisruptionBudget_maxUnavailable_Non_Zero": [{"feature_to_fix": "io_k8s_api_policy_v1_PodDisruptionBudget_spec_maxUnavailable_asInteger", "safe_value": 1}],
            "Require_Multiple_Replicas": [{"feature_to_fix": "io_k8s_api_apps_v1_Deployment_spec_replicas", "safe_value": 2}],
            "insecureCapabilities": [{"feature_to_fix": "io_k8s_api_core_v1_Container_securityContext_capabilities_drop_StringValue", "safe_value": "ALL"}],
            "Restrict_Service_Port_Range": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_ports_port", "safe_value": 32400}],
            # --- Network & Services ---
            #"Restrict_Service_Port_Range": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_ports_port", "safe_value": 32000}],
            "Disallow_Localhost_ExternalName_Services": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_externalName", "safe_value": "development.local"}],            
            # --- Workload & Pods ---
            "Require_Multiple_Replicas": [{"feature_to_fix": "io_k8s_api_apps_v1_Deployment_spec_replicas", "safe_value": 2}],
            #"Disallow_Default_Namespace": [{"feature_to_fix": "io_k8s_api_core_v1_Pod_metadata_namespace", "safe_value": "kube-system"}],
            "PodDisruptionBudget_maxUnavailable_Non_Zero": [{"feature_to_fix": "io_k8s_api_policy_v1_PodDisruptionBudget_spec_maxUnavailable_asInteger", "safe_value": 1}],
            "hpaMinAvailability": [{"feature_to_fix": "io_k8s_api_autoscaling_v1_HorizontalPodAutoscaler_spec_minReplicas", "safe_value": 3}],
            #"hpaMaxAvailability": [{"feature_to_fix": "io_k8s_api_autoscaling_v1_HorizontalPodAutoscaler_spec_maxReplicas", "safe_value": 10}],
            
            # --- Security Context, Users & Groups ---
            #"insecureCapabilities": [{"feature_to_fix": "io_k8s_api_core_v1_Container_securityContext_capabilities_drop_StringValue", "safe_value": "ALL"}],
            #"Require_Run_As_Non_Root_User": [{"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_runAsUser_valueInt", "safe_value": 1000}],
            #"use_high_uid": [{"feature_to_fix": "io_k8s_api_core_v1_Container_securityContext_runAsUser_valueInt", "safe_value": 10001}],
            #"use_high_gid": [{"feature_to_fix": "io_k8s_api_core_v1_Container_securityContext_runAsGroup_valueInt", "safe_value": 10001}],
            "Check_supplementalGroups": [{"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_supplementalGroups_IntegerValue", "safe_value": 100}],
            "Require_Non_Root_Groups": [ {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_supplementalGroups_IntegerValue", "safe_value": 100}, {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_fsGroup_valueInt", "safe_value": 2000}],
            #"Validate_User_ID_Group_ID_and_FS_Group": [ {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_runAsUser_valueInt", "safe_value": 1000}, {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_runAsGroup_valueInt", "safe_value": 3000}, {"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_securityContext_fsGroup_valueInt", "safe_value": 2000}],
            
            # --- Storage & Volumes ---
            "Require_StorageClass": [{"feature_to_fix": "io_k8s_api_core_v1_PersistentVolumeClaim_spec_storageClassName", "safe_value": "standard"}],
            "Restrict_StorageClass": [{"feature_to_fix": "io_k8s_api_storage_v1_StorageClass_reclaimPolicy", "safe_value": "Delete"}],
            "Limit_hostPath_PersistentVolumes_to_Specific_Directories": [{"feature_to_fix": "io_k8s_api_core_v1_PersistentVolume_spec_hostPath_path", "safe_value": "/data/secure"}],
            "Enforce_ReadWriteOncePod": [{"feature_to_fix": "io_k8s_api_core_v1_PersistentVolumeClaim_spec_accessModes_StringValue", "safe_value": "ReadWriteOncePod"}],
            
            # --- RBAC & Authentication ---
            "Restrict_Binding_to_Cluster_Admin": [{"feature_to_fix": "io_k8s_api_rbac_v1_RoleBinding_roleRef_name", "safe_value": "view"}],
            "Restrict_Binding_System_Groups": [{"feature_to_fix": "io_k8s_api_rbac_v1_RoleBinding_subjects_name", "safe_value": "safe-user"}],
            "Deny_Secret_Service_Account_Token_Type": [{"feature_to_fix": "io_k8s_api_core_v1_Secret_type", "safe_value": "Opaque"}],
            #"Require_aws_node_DaemonSet_use_IRSA": [{"feature_to_fix": "io_k8s_api_apps_v1_DaemonSet_spec_template_spec_serviceAccountName", "safe_value": "irsa-sa"}],
            
            # --- Regex Fallbacks (Valores seguros para inyectar si falla la validación léxica) ---
            #"Check_Environment_Variables": [{"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_containers_env_value", "safe_value": "false"}],
            "Require_Pod_priorityClassName": [{"feature_to_fix": "io_k8s_api_core_v1_Pod_spec_priorityClassName", "safe_value": "high-priority"}],
            #"Restrict_Image_Registries": [{"feature_to_fix": "io_k8s_api_core_v1_Container_image", "safe_value": "eu.foo.io/segura:v1"}],
            "tagNotSpecified": [{"feature_to_fix": "io_k8s_api_core_v1_Container_image", "safe_value": "nginx:v1.28.0"}],
        }
        self._build_registry_from_uvl(uvl_path)

    def _build_registry_from_uvl(self, uvl_path: str):
        try:
            with open(uvl_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            for line in lines:
                line = line.strip()
                if '=>' not in line: continue
                    
                parts = line.split('=>')
                policy_name = parts[0].strip()
                condition = parts[1].strip()
                
                if policy_name in self.manual_overrides:
                    self.registry[policy_name] = self.manual_overrides[policy_name]
                    continue
                
                # Limpiamos paréntesis externos múltiples veces por si acaso
                while condition.startswith('(') and condition.endswith(')'):
                    condition = condition[1:-1].strip()
                    
                # Dividimos por '&' para capturar políticas multi-recurso
                sub_conditions = [c.strip() for c in condition.split('&')]
                actions = []
                
                for sub in sub_conditions:
                    while sub.startswith('(') and sub.endswith(')'):
                        sub = sub[1:-1].strip()
                        
                    if '|' in sub or '!=' in sub or '>' in sub or '<' in sub:
                        continue # Ignoramos lógicas no deterministas
                        
                    feature, safe_value = None, None
                    
                    if sub.startswith('!'):
                        feature = sub[1:].split('.')[-1].strip()
                        safe_value = False
                    elif '==' in sub:
                        f_part, v_part = sub.split('==')
                        feature = f_part.split('.')[-1].strip()
                        val_str = v_part.strip().strip("'").strip('"')
                        # Casteo de tipos básico
                        if val_str.isdigit(): safe_value = int(val_str)
                        elif val_str.lower() == 'true': safe_value = True
                        elif val_str.lower() == 'false': safe_value = False
                        else: safe_value = val_str
                    else:
                        feature = sub.split('.')[-1].strip()
                        safe_value = True
                        
                    if feature:
                        actions.append({"feature_to_fix": feature, "safe_value": safe_value})
                        
                if actions:
                    self.registry[policy_name] = actions
                    
        except Exception as e:
            print(f"Error parseando UVL: {e}")

    def get_remediation_actions(self, policy_name: str) -> list:
        """Devuelve una LISTA de acciones para arreglar la política."""
        return self.registry.get(policy_name, [])