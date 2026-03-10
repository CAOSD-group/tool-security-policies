import logging
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
    try:
        # 1. Read UVL
        self.fm = UVLReader(self.uvl_path).transform()
        
        # 2. Flatten FM (Assuming FlatFM is applied directly to the model)
        # Depending on flamapy version, this might be a transformation or an operation
        flat_transformer = FlatFM(self.fm)
        self.fm = flat_transformer.transform()

        # 3. Generate Z3 Representation
        z3_transformer = FmToZ3(self.fm)
        self.z3_model = z3_transformer.transform()
        
        logger.info("Successfully loaded and cached Z3 model.")
    except Exception as e:
        logger.error(f"Failed to load Feature Model: {e}")
        raise