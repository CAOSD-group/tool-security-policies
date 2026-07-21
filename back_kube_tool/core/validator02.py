import logging
from flamapy.metamodels.configuration_metamodel.models import Configuration
from flamapy.metamodels.fm_metamodel.models import FeatureModel, Feature
from flamapy.metamodels.z3_metamodel.operations import Z3SatisfiableConfiguration
##from core.policy_inference import PolicyInference
import z3
import inspect
import concurrent.futures
import traceback
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
    
    # Extraemos las restricciones cruzadas (Tus políticas reales)
    ctcs = self.flat_fm.get_constraints()
    
    # Mapa maestro para distinguir qué es una Variable de K8s y qué es Texto Puro
    all_features = {f.name for f in self.flat_fm.get_features()}

    # =========================================================
    # MOTOR DE EVALUACIÓN AST NATIVO
    # =========================================================
    def evaluate_ast(node, elements):
        if node is None:
            return True
            
        # A. Nodo Hoja (Evaluación de variables y valores)
        if not node.left and not node.right:
            val = node.data
            
            # 1. Limpieza de comillas si Flamapy las dejó
            if isinstance(val, str) and ((val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"'))):
                return val.strip("'").strip('"')
                
            # 2. Si es un número en formato string, lo parseamos
            if isinstance(val, str) and val.replace('.','',1).isdigit():
                return float(val) if '.' in val else int(val)
            
            # 3. Buscamos en el manifiesto YAML
            if val in elements:
              res = elements[val]
              return res[0] if isinstance(res, list) and len(res) > 0 else res
            
            # [PARCHE DE ATRIBUTOS]: FlamaPy añade sufijos. Los limpiamos.
            for suffix in ['_asInteger', '_StringValue', '_IntegerValue']:
                if isinstance(val, str) and val.endswith(suffix):
                    clean_val = val[:-len(suffix)]
                    if clean_val in elements:
                      res = elements[clean_val]
                      return res[0] if isinstance(res, list) and len(res) > 0 else res
                    
            # 4. Si no está en el YAML, hay dos opciones:
            if val in all_features:
                # Es una característica de Kubernetes (ej. readOnlyRootFilesystem) que no está en el YAML -> Es Falso.
                return False
            else:
                # No es una característica del modelo. Es un texto literal de tu UVL (ej. 'aws-node', 'ALL')
                return val

        # B. Nodos Operadores (Con soporte para sintaxis interna astoperation.*)
        op = str(node.data).lower()

        if 'not' in op and 'equals' not in op: # astoperation.not
            return not evaluate_ast(node.left, elements)

        left_val = evaluate_ast(node.left, elements)
        right_val = evaluate_ast(node.right, elements)

        # Lógica Booleana
        if 'and' in op: return left_val and right_val
        if 'or' in op: return left_val or right_val
        if 'implies' in op or 'requires' in op: return (not left_val) or right_val
        if 'excludes' in op: return not (left_val and right_val)

        # Lógica Relacional (Atributos, Puertos, Textos)
        try:
            if 'not_equals' in op or '!=' in op: return str(left_val) != str(right_val)
            elif 'equals' in op or '==' in op: return str(left_val) == str(right_val)
            elif 'greater' in op or '>' in op: return float(left_val) > float(right_val)
            elif 'lower' in op or 'less' in op or '<' in op: return float(left_val) < float(right_val)
        except Exception:
            return False

        return False

    # =========================================================
    # BUCLE ITERATIVO (Velocidad O(1))
    # =========================================================
    for policy in active_policies:
        try:
            temp_elements = base_completed_elements.copy()
            temp_elements[policy] = True
            temp_elements = self._add_single_feature_closure(temp_elements, policy)

            policy_failed = False
            
            # Comprobamos las restricciones. Si alguna da False, el YAML incumple tu política
            for ctc in ctcs:
                if evaluate_ast(ctc.ast.root, temp_elements) is False:
                    policy_failed = True
                    break

            # Si falló, añadimos la alerta
            if policy_failed:
                meta = self.get_policy_metadata(policy)
                #print(f"Error en la politica con el meta: {meta}")
                failed_policies_report.append({
                    "policy": policy,
                    "severity": meta.get("severity", "unknown"),
                    "tool": meta.get("tool", "unknown"),
                    "description": meta.get("description", "empty"),
                    "remediation": meta.get("remediation", "Check policy")
                })

        except Exception as e:
            # print(f"Error evaluando AST en {policy}: {e}")
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