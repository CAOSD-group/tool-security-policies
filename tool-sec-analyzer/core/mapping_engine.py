from copy import deepcopy
from itertools import product
from typing import List, Dict, Any
from flamapy.metamodels.configuration_metamodel.models.configuration import Configuration

class MappingEngine:
  @staticmethod
  def qualify(fid: str, namespace: str = "") -> str:
    if not namespace:
        return fid
    return fid if fid.startswith(namespace) else f"{namespace}{fid}"

  @classmethod
  def manifest_to_configurations(cls, manifest_dict: Dict[str, Any], namespace: str = "") -> List[Configuration]:
    """
    Adapts the ConfigurationJSON logic to run entirely in-memory.
    Extracts features and generates cartesian products for lists.
    """
    base_config = {}
    blocks = []
    
    # Extract features recursively
    cls._extract_features(manifest_dict, base_config, blocks, namespace)
    
    # Generate combinations
    return cls._generate_combinations(base_config, blocks)

  @classmethod
  def _extract_features(cls, data: Any, base_config: Dict, blocks: List, namespace: str = ""):
    # Simplified version of your recursive extraction logic
    if isinstance(data, dict):
      for key, value in data.items():
        qkey = cls.qualify(key, namespace)

        if isinstance(value, (str, int, float, bool)):
          base_config[qkey] = value
        elif isinstance(value, dict):
          base_config[qkey] = True
          cls._extract_features(value, base_config, blocks, namespace)
        elif isinstance(value, list):
          if not value:
            base_config[qkey] = True
            continue
          
          combined_block = []
          for item in value:
            if isinstance(item, dict):
              flat_item = cls._flatten_primitive_kv(item, namespace)
              combined_block.append(flat_item)
            elif isinstance(item, (str, int, float, bool)):
              combined_block.append({cls.qualify(str(item), namespace): True})
          
          if combined_block:
            blocks.append(combined_block)
          base_config[qkey] = True

  @classmethod
  def _flatten_primitive_kv(cls, d: dict, namespace: str = "") -> dict:
    flat = {}
    for k, v in d.items():
      qk = cls.qualify(k, namespace)
      if isinstance(v, (str, int, float, bool)):
        flat[qk] = v
      elif isinstance(v, dict):
        flat[qk] = True
        flat.update(cls._flatten_primitive_kv(v, namespace))
    return flat

  @classmethod
  def _generate_combinations(cls, base_config: Dict, blocks: List, max_combinations: int = 10000) -> List[Configuration]:
    result = []
    
    def backtrack(index, current):
      if len(result) >= max_combinations:
        return
      if index == len(blocks):
        merged = deepcopy(base_config)
        for partial in current:
            merged.update(partial)
        result.append(Configuration(merged))
        return

      for option in blocks[index]:
        current.append(option)
        backtrack(index + 1, current)
        current.pop()

    backtrack(0, [])
    # Fallback if no blocks were found
    if not result:
      result.append(Configuration(base_config))
        
    return result