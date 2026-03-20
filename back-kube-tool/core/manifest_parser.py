import yaml
from typing import List, Dict, Any

class ManifestParser:
  @staticmethod
  def parse(yaml_content: str) -> List[Dict[str, Any]]:
    """Parses a multi-document YAML string into a list of Python dictionaries."""
    try:
        documents = yaml.safe_load_all(yaml_content)
        # Filter out empty documents
        return [doc for doc in documents if doc is not None]
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML manifest: {e}")