import logging
from typing import Dict, List, Set
from flamapy.metamodels.fm_metamodel.models import FeatureModel, Feature

logger = logging.getLogger(__name__)

class PolicyInference:
  def __init__(self, flat_fm: FeatureModel):
      """
      Initializes the inference engine by parsing the UVL attributes.
      It builds an internal mapping: { 'Pod': ['Policy_1', 'Policy_2'], 'Service': [...] }
      """
      self.flat_fm = flat_fm
      self.kind_to_policies_map: Dict[str, Set[str]] = {}
      self._build_inference_map()

  def _build_inference_map(self):
      """
      Iterates through all features in the Feature Model. 
      If a feature has a 'kinds' attribute, it maps the feature name to those kinds.
      """
      logger.info("Building policy inference map from UVL attributes...")
      
      for feature in self.flat_fm.get_features():
          kinds_attr = None
          
          # Find the 'kinds' attribute in the feature
          for attr in feature.get_attributes():
              if attr.name == 'kinds':
                  kinds_attr = attr.get_default_value()
                  break
          
          if kinds_attr:
              # Kinds are often comma-separated strings: 'cronjob, daemonset, pod'
              # Clean strings, make them lowercase for case-insensitive matching
              target_kinds = [k.strip().lower() for k in kinds_attr.split(',')]
              
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