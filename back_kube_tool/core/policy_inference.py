import logging
from typing import Dict, List, Set
from flamapy.metamodels.fm_metamodel.models import FeatureModel

logger = logging.getLogger(__name__)

class PolicyInference:
  def __init__(self, flat_fm: FeatureModel, regex_policy_names: Set[str]):
    """
    Initializes the inference engine by parsing the UVL attributes.
    It builds an internal mapping: { 'Pod': ['Policy_1', 'Policy_2'], 'Service': [...] }
    """
    self.flat_fm = flat_fm
    self.kind_to_policies_map: Dict[str, Set[str]] = {}
    
    self.policy_features_map: Dict[str, Set[str]] = {} ## New mapping to track which features are associated with each policy
    
    self.regex_policies = regex_policy_names
    self._build_inference_map()

  def _build_inference_map(self):
    """
    Iterates through all features in the Feature Model. 
    If a feature has a 'kinds' attribute, it maps the feature name to those kinds.
    """
    logger.info("Building policy inference map from UVL attributes...")
    
    constrained_features = set()
    ctc_feature_groups = [] # Inicializamos la lista antes del bucle

    for ctc in self.flat_fm.get_constraints():
        ctc_feats = set()
        for feat in ctc.get_features():
            
            if isinstance(feat, str):
                constrained_features.add(feat)
                ctc_feats.add(feat)
            else:
                constrained_features.add(feat.name)
                ctc_feats.add(feat.name)
                #print(f"CTC feature: {feat}")
        
        # Save the complete group of features for this constraint
        ctc_feature_groups.append(ctc_feats)

    for feature in self.flat_fm.get_features():
        kinds_attr = None
        
        for attr in feature.get_attributes():
            if attr.name == 'kinds':
                kinds_attr = attr.get_default_value()
                break
          
        if kinds_attr:

            is_constrained = feature.name in constrained_features
            is_regex = feature.name in self.regex_policies
            
            # Si no tiene CTCs y no está en regex_validator, es Dummy.

            # If the policy belongs to a constraint, we search for all companion features in that same equation.
            if not is_constrained and not is_regex: ###PROV
                continue              
            involved_features = set()
            if is_constrained:
                for group in ctc_feature_groups:
                    if feature.name in group:
                        involved_features.update(group)
            
            self.policy_features_map[feature.name] = involved_features

            # Kinds are often comma-separated strings: 'cronjob, daemonset, pod'
            # Clean strings, make them lowercase for case-insensitive matching
            target_kinds = [k.strip().lower() for k in kinds_attr.split(',')]
            
            # =======================================================
            #if 'container' in target_kinds:
            container_policies = ['tagNotSpecified', 'cpuLimitsMissing', 'cpuRequestsMissing', 'memoryLimitsMissing', 'memoryRequestsMissing']
            
            if feature.name in container_policies :
                workloads = ['pod', 'deployment', 'daemonset', 'statefulset', 'job', 'cronjob', 'replicaset']
                for w in workloads:
                    if w not in target_kinds:
                        target_kinds.append(w)

            for kind in target_kinds:
                if kind not in self.kind_to_policies_map:
                    self.kind_to_policies_map[kind] = set()
                self.kind_to_policies_map[kind].add(feature.name)

    logger.info(f"Inference map built for {len(self.kind_to_policies_map)} resource kinds.")

  def get_policies_for_kind(self, kind: str) -> List[str]:
    """
    Returns a list of policy names that apply to a specific Kubernetes resource kind.
    """
    # Ensure case-insensitive matching (e.g., 'Pod' -> 'pod')
    kind_key = kind.strip().lower()
    # Return the policies as a list, or an empty list if kind is not found
    policies = self.kind_to_policies_map.get(kind_key, set())
    return list(policies)
  
  def get_features_for_policies(self, policy_names: List[str]) -> Set[str]:
    """Returns all mathematical features involved in a list of policies."""
    all_features = set()
    print(f"Second testing of list policies Set {policy_names}")
    for p in policy_names:
        all_features.update(self.policy_features_map.get(p, set()))
    return all_features