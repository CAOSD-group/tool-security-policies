import logging
import os
from pathlib import Path
from flamapy.metamodels.fm_metamodel.transformations import UVLReader
from flamapy.metamodels.fm_metamodel.transformations import FlatFM
from flamapy.metamodels.z3_metamodel.transformations import FmToZ3

logger = logging.getLogger(__name__)

class ModelLoader:
  def __init__(self, uvl_path: str):
    self.uvl_path = uvl_path
    self.fm = None
    self.z3_model = None
    self._load_and_transform()

  def _load_and_transform(self):
    """Loads UVL, flattens it, and transforms to Z3 once during initialization."""
    
    logger.info(f"Loading Feature Model from {self.uvl_path}")
    # 1. Obtener la ruta absoluta y el directorio donde vive el modelo
    abs_uvl_path = Path(self.uvl_path).resolve()
    model_dir = abs_uvl_path.parent
      
    # Guardamos el directorio de trabajo actual (la raíz del proyecto)
    original_cwd = os.getcwd()

    try:
      os.chdir(model_dir)
      self.fm = UVLReader(abs_uvl_path.name).transform()
      logger.info(f"Loading Feature Model from {self.uvl_path}")
      print(f"Path to UVL: {self.uvl_path}")
      flat_fm_op = FlatFM(self.fm)
      flat_fm_op.set_maintain_namespaces(False)
      self.flat_fm = flat_fm_op.transform()

      self.z3_model = FmToZ3(self.flat_fm).transform()
      logger.info("Successfully loaded and cached Flat_FM and Z3 model.")
    except Exception as e:  
      logger.error(f"Failed to load Feature Model: {e}")
      raise
    finally:
      os.chdir(original_cwd)
      logger.info(f"Restored working directory to: {original_cwd}")