import logging
from flamapy.metamodels.configuration_metamodel.models import Configuration
from flamapy.metamodels.fm_metamodel.models import FeatureModel, Feature
from flamapy.metamodels.z3_metamodel.operations import Z3SatisfiableConfiguration
##from core.policy_inference import PolicyInference
import z3
import inspect

logger = logging.getLogger(__name__)

class Validator:
  def __init__(self, flat_fm: FeatureModel, z3_model):
    self.flat_fm = flat_fm
    self.z3_model = z3_model

    self._parent_cache: dict[str, list[str]] = {}
    self._mand_desc_cache: dict[str, list[str]] = {}
    
  def validate_configuration(self, config: Configuration, active_policies: list[str]) -> list[dict]:
      failed_policies_report = []
      base_completed_elements = self._complete_full_configuration(config.elements)
      
      # =========================================================
      # 1. INICIALIZACIÓN GLOBAL DEL SOLVER (El Universo Z3)
      # =========================================================
      z3_ctx = getattr(self.z3_model, 'ctx', None)
      solver = z3.Solver(ctx=z3_ctx) 
      
      # Cargamos las 76.580 reglas solo UNA VEZ
      for constraint in self.z3_model.constraints:
          try:
              if z3.is_expr(constraint) and z3.is_bool(constraint):
                  solver.add(constraint)
          except Exception:
              pass

      # Limpiamos las variables de FlamaPy para uso directo
      z3_vars = getattr(self.z3_model, 'variables', getattr(self.z3_model, 'features', {}))
      processed_vars = {}
      for k, v in z3_vars.items():
          if not z3.is_expr(v):
              if hasattr(v, 'z3_var'):
                  processed_vars[k] = v.z3_var
          else:
              processed_vars[k] = v

      # =========================================================
      # 2. BUCLE ITERATIVO ULTRARRÁPIDO CON "ASSUMPTIONS"
      # =========================================================
      for policy in active_policies:
          try:
              # FlamaPy prepara el Mundo Cerrado perfectamente
              temp_elements = base_completed_elements.copy()
              temp_elements[policy] = True
              temp_elements = self._add_single_feature_closure(temp_elements, policy)
              
              temp_config = Configuration(temp_elements)
              temp_config.set_full(True) 

              # ===============================================================
              # LA MAGIA: En lugar de usar solver.add(), empaquetamos el YAML 
              # en una lista de memoria (Assumptions) y se lo enviamos a C++.
              # ===============================================================
              assumptions = []
              for feat_name, val in temp_config.elements.items():
                  z3_var = processed_vars.get(feat_name)
                  if z3_var is None:
                      continue

                  sort_str = str(z3_var.sort())
                  if sort_str == "Bool" and isinstance(val, bool):
                      # Adjuntamos la variable o su negación a la lista de supuestos
                      assumptions.append(z3_var if val else z3.Not(z3_var))
                  elif sort_str == "Int" and isinstance(val, (int, float)):
                      assumptions.append(z3_var == z3.IntVal(int(val), ctx=z3_ctx))
                  elif sort_str == "String" and isinstance(val, str):
                      assumptions.append(z3_var == z3.StringVal(val, ctx=z3_ctx))

              # === COMPROBACIÓN MATEMÁTICA EN 1 SOLA LLAMADA ===
              # check(*assumptions) evalúa las reglas base BAJO las condiciones del YAML
              if solver.check(*assumptions) == z3.unsat:
                  meta = self.get_policy_metadata(policy)
                  failed_policies_report.append({
                      "policy": policy,
                      "severity": meta.get("severity", "unknown"),
                      "tool": meta.get("tool", "unknown"),
                      "description": meta.get("description", "empty"),
                      "remediation": meta.get("remediation", "Check policy")
                  })
                  
          except Exception as e:
              # pass silently or log
              pass

      return failed_policies_report

  # --- MÉTODOS DE CACHÉ Y AUTOCOMPLETADO OPTIMIZADOS ---
  def _parents_of(self, feature_name: str) -> list[str]:
      if feature_name in self._parent_cache:
          return self._parent_cache[feature_name]
      feat = self.flat_fm.get_feature_by_name(feature_name)
      if not feat or feat.get_parent() is None:
          res = []
      else:
          p = feat.get_parent()
          res = [p.name] + self._parents_of(p.name)
      self._parent_cache[feature_name] = res
      return res

  def _mandatory_descendants(self, feature_name: str) -> list[str]:
      if feature_name in self._mand_desc_cache:
          return self._mand_desc_cache[feature_name]
      feat = self.flat_fm.get_feature_by_name(feature_name)
      res = []
      if feat:
          for child in feat.get_children():
              if child.is_mandatory():
                  res.append(child.name)
                  res.extend(self._mandatory_descendants(child.name))
      self._mand_desc_cache[feature_name] = res
      return res

  def _add_single_feature_closure(self, elements: dict, feature_name: str) -> dict:
      for ch in self._mandatory_descendants(feature_name):
          if ch not in elements: elements[ch] = True
      for parent_name in self._parents_of(feature_name):
          if parent_name not in elements: elements[parent_name] = True
          for ch in self._mandatory_descendants(parent_name):
              if ch not in elements: elements[ch] = True
      return elements

  def _complete_full_configuration(self, original_elements: dict) -> dict:
      elems = original_elements.copy()
      for selected in list(elems.keys()):
          if elems[selected]:  
              elems = self._add_single_feature_closure(elems, selected)
      return elems


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
      
      if not feat: return info
      #print(f"\n[DEBUG METADATA] Explorando atributos para política: {policy_name}")
      for attr in feat.get_attributes():
        val = attr.get_default_value()
        #print(f"   -> Encontrado atributo: nombre='{attr.name}', valor='{val}', tipo_valor='{type(val)}'")
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