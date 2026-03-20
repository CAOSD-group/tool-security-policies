import logging
from flamapy.metamodels.configuration_metamodel.models import Configuration
from flamapy.metamodels.fm_metamodel.models import FeatureModel, Feature
from flamapy.metamodels.z3_metamodel.operations import Z3SatisfiableConfiguration
from core.policy_inference import PolicyInference

logger = logging.getLogger(__name__)

class Validator:
  def __init__(self, flat_fm: FeatureModel, z3_model):
    self.flat_fm = flat_fm
    self.z3_model = z3_model

  def validate_configuration(self, config: Configuration, active_policies: list[str]) -> list[dict]:
    """
    Iteratively tests policies against the configuration using Z3.
    Returns a list of violation dictionaries.
    """
    failed_policies_report = []
    
    # Note: I omitted the ContentPolicyValidator (regex) here for brevity, 
    # but you would call it here before the Z3 loop just like in your script.

    for policy in active_policies:
      try:
        # 1. Clean copy of the manifest elements
        temp_elements = config.elements.copy()
        
        # 2. Activate ONLY the current policy we want to audit
        temp_elements[policy] = True
        
        # 3. Complete the configuration (inject parents/mandatory children)
        temp_config = Configuration(temp_elements)
        temp_config_completed = self._complete_configuration(temp_config)
        temp_config_completed.set_full(True)
        
        # 4. Validate with Z3
        sat_op = Z3SatisfiableConfiguration()
        sat_op.set_configuration(temp_config_completed)
        is_sat = sat_op.execute(self.z3_model).get_result()
        
        # 5. If UNSAT, record vulnerability
        if not is_sat:
          meta = self.get_policy_metadata(policy)
          print(f"Error en la politica con el meta: {meta}")
          failed_policies_report.append({
            "policy": policy,
            "severity": meta.get("severity", "unknown"),
            "description": meta.get("description", "empty"),
            "remediation": meta.get("remediation", "Check policy")
          })

      except Exception as e:
        logger.error(f"Error evaluating policy {policy}: {e}")
        failed_policies_report.append({
          "policy": policy,
          "severity": "error",
          "description": f"Internal mapping/solver error: {e}",
          "remediation": "Check policy mapping and FM constraints."
        })

    return failed_policies_report

  def _complete_configuration(self, configuration: Configuration) -> Configuration:
    """Injects mandatory parents and children based on the FM tree."""
    configs_elements = dict(configuration.elements)
    
    for element in configuration.get_selected_elements():
      feature = self.flat_fm.get_feature_by_name(element)
      if feature is None:
        raise Exception(f'Error: the element "{element}" is not present in the FM model.')
        #continue # Skip unknown features mapping silently or log a warning
      
      children_names = self._get_all_mandatory_children(feature)
      parent_names = self._get_all_parents(feature)
      
      for parent in parent_names:
        parent_feature = self.flat_fm.get_feature_by_name(parent)
        if parent_feature:
          children_names.extend(self._get_all_mandatory_children(parent_feature))
          
      for parent in parent_names:
        if parent not in configs_elements:
          configs_elements[parent] = True
              
      for child in children_names:
        if child not in configs_elements:
          configs_elements[child] = True
                
    return Configuration(configs_elements)

  def _get_all_parents(self, feature: Feature) -> list[str]:
    parent = feature.get_parent()
    return [] if parent is None else [parent.name] + self._get_all_parents(parent)

  def _get_all_mandatory_children(self, feature: Feature) -> list[str]:
    children = []
    for child in feature.get_children():
      if child.is_mandatory():
        children.append(child.name)
        children.extend(self._get_all_mandatory_children(child))
    return children

  def get_policy_metadata(self, policy_name: str) -> dict:
      """
      Extracts metadata from UVL attributes defined in the Feature Model.
      Maps the UVL attributes to standard JSON reporting fields.
      """
      feat = self.flat_fm.get_feature_by_name(policy_name)
      
      # Default fallback values
      info = {
        "tool": "unknown",
        "severity": "unknown",
        "description": "",
        "remediation": "",
        "category": "Security"
      }
      
      if not feat:
        return info
      print(f"\n[DEBUG METADATA] Explorando atributos para política: {policy_name}")
      for attr in feat.get_attributes():
        val = attr.get_default_value()
        print(f"   -> Encontrado atributo: nombre='{attr.name}', valor='{val}', tipo_valor='{type(val)}'")
        if attr.name == 'tool':
          info['tool'] = val
        elif attr.name == 'severity':
          info['severity'] = val
        elif attr.name == 'doc':
          info["description"] = val
        elif attr.name == 'RecommendedAction':
          info["remediation"] = val

      return info
      """  def _get_policy_metadata(self, policy_name: str) -> dict:
        feat = self.flat_fm.get_feature_by_name(policy_name)
        info = {}
        if feat:
          for attr in feat.get_attributes():
            val = attr.get_default_value()
            if attr.name == 'RecommendedAction':
              info["remediation"] = val
            else:
              info[attr.name] = val
        return info"""