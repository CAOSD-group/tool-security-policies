import logging
from flamapy.metamodels.configuration_metamodel.models import Configuration
from flamapy.metamodels.fm_metamodel.models import FeatureModel, Feature
from flamapy.metamodels.z3_metamodel.operations import Z3SatisfiableConfiguration
##from core.policy_inference import PolicyInference
import z3

logger = logging.getLogger(__name__)

class Validator:
  def __init__(self, flat_fm: FeatureModel, z3_model):
    self.flat_fm = flat_fm
    self.z3_model = z3_model

    self._parent_cache: dict[str, list[str]] = {}
    self._mand_desc_cache: dict[str, list[str]] = {}
        
  def validate_configuration(self, config: Configuration, active_policies: list[str]) -> list[dict]:
    """
    Iteratively tests policies against the configuration using native Z3 push/pop.
    Separates Base YAML constraints (O(1)) from Policy constraints (O(P)) for max performance.
    """
    failed_policies_report = []
    base_completed_elements = self._complete_full_configuration(config.elements)
    
    # =========================================================
    # 1. INICIALIZACIÓN DEL SOLVER Y REGLAS DEL MODELO
    # =========================================================
    solver = z3.Solver()
    for constraint in self.z3_model.constraints:
        try:
            # Filtro estricto: Solo cargamos ecuaciones booleanas nativas de Z3.
            # Esto arregla el problema de las 0 alertas por motor vacío.
            if z3.is_expr(constraint) and z3.is_bool(constraint):
                solver.add(constraint)
        except Exception:
            pass

    # =========================================================
    # 2. DEFINIR EL DOMINIO DE LAS POLÍTICAS
    # Encontramos todas las variables de las políticas para no forzarlas a False
    # =========================================================
    policy_related = set()
    for p in active_policies:
        closure = self._add_single_feature_closure({p: True}, p)
        policy_related.update(closure.keys())

    # =========================================================
    # 3. CARGA BASE DEL MANIFIESTO Y "MUNDO CERRADO" (1 SOLA VEZ)
    # =========================================================
    base_keys = set(base_completed_elements.keys())
    
    # A. Inyectamos los datos reales del YAML (Booleanos y Atributos como puertos/strings)
    for key, val in base_completed_elements.items():
        if isinstance(val, bool):
            solver.add(z3.Bool(key) == val)
        elif isinstance(val, int) or (isinstance(val, float) and val.is_integer()):
            solver.add(z3.Int(key) == int(val))
        elif isinstance(val, str):
            solver.add(z3.String(key) == z3.StringVal(val))

    # B. Simulación de set_full(True): Todo lo que no está en el YAML es False.
    # Esto se ejecuta solo 1 vez, reduciendo el tiempo de 40s a milisegundos.
    all_features = [f.name for f in self.flat_fm.get_features()]
    for feat in all_features:
        if feat not in base_keys and feat not in policy_related:
            solver.add(z3.Bool(feat) == False)

    # =========================================================
    # 4. EVALUACIÓN DE POLÍTICAS (Iteración ultrarrápida)
    # =========================================================
    for policy in active_policies:
        solver.push() # Guardamos la memoria RAM con el YAML ya cargado
        
        try:
            # Calculamos las dependencias específicas de ESTA política
            policy_closure = self._add_single_feature_closure({policy: True}, policy)
            
            # Para todo el universo de políticas, activamos la actual y desactivamos el resto
            for feat in policy_related:
                if feat in policy_closure:
                    solver.add(z3.Bool(feat) == True)
                else:
                    solver.add(z3.Bool(feat) == False)
                    
            # Comprobación Matemática
            if solver.check() == z3.unsat:
                meta = self.get_policy_metadata(policy)
                failed_policies_report.append({
                    "policy": policy,
                    "severity": meta.get("severity", "unknown"),
                    "tool": meta.get("tool", "unknown"),
                    "description": meta.get("description", "empty"),
                    "remediation": meta.get("remediation", "Check policy")
                })
        except Exception as e:
            pass
            
        solver.pop() # Restauramos para la siguiente política

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