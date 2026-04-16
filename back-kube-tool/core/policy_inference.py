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

      self.regex_policies = regex_policy_names

      self._build_inference_map()

  def _build_inference_map(self):
    """
    Iterates through all features in the Feature Model. 
    If a feature has a 'kinds' attribute, it maps the feature name to those kinds.
    """
    logger.info("Building policy inference map from UVL attributes...")
    
    constrained_features = set()
    for ctc in self.flat_fm.get_constraints():
        for feat in ctc.get_features():
            
            if isinstance(feat, str):
                constrained_features.add(feat)
            else:
                constrained_features.add(feat.name)
                print(f"CTC feature: {feat}")
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
            if not is_constrained and not is_regex:
                continue              
              
            # Kinds are often comma-separated strings: 'cronjob, daemonset, pod'
            # Clean strings, make them lowercase for case-insensitive matching
            target_kinds = [k.strip().lower() for k in kinds_attr.split(',')]
            
            # =======================================================
            #if 'container' in target_kinds:
            if feature.name == 'tagNotSpecified':
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