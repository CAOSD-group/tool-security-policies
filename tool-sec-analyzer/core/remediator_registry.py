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
            "Restrict_Service_Port_Range": [{"feature_to_fix": "io_k8s_api_core_v1_Service_spec_ports_port", "safe_value": 32500}]
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