import logging
import time
from flamapy.metamodels.fm_metamodel.transformations import UVLReader
from flamapy.metamodels.pysat_metamodel.transformations import FmToPysat
#from flamapy.metamodels.pysat_metamodel.operations import Glucose3ValidConfiguration
from flamapy.metamodels.pysat_metamodel.operations import PySATSatisfiableConfiguration
from flamapy.metamodels.configuration_metamodel.models import Configuration

logger = logging.getLogger(__name__)

class StructuralValidator:
    """
    Motor de validación estructural pura basado en SAT (Glucose3).
    Carga el Feature Model completo de Kubernetes (66k líneas)
    para validar manifiestos en milisegundos.
    """
    def __init__(self, full_uvl_path: str):
        logger.info(f"Cargando Feature Model ESTRUCTURAL COMPLETO desde: {full_uvl_path}")
        try:
            # 1. Leemos el UVL gigante (Se hace una sola vez)
            self.fm_model = UVLReader(full_uvl_path).transform()
            
            # 2. Compilamos a PySAT (CNF)
            self.sat_model = FmToPysat(self.fm_model).transform()
            logger.info("Modelo SAT estructural compilado con éxito.")
            
        except Exception as e:
            logger.error(f"Error cargando el modelo SAT estructural: {e}")
            raise

    def validate_structure(self, config_elements: dict) -> dict:
        """
        Evalúa si la configuración mapeada es válida según el FM Estructural.
        config_elements es un dict del tipo: {'feature_name': True/False, ...}
        """
        try:
            start_time = time.time()
            
            # 1. Filtramos solo las features activadas (True)
            # A diferencia de Z3, FlamaPy SAT asume que lo que no se le pasa es False
            selected_features = {k: True for k, v in config_elements.items() if v}
            
            # 2. Creamos la configuración de FlamaPy
            config = Configuration(selected_features)
            
            # 3. Operación de validación SAT
            valid_op = PySATSatisfiableConfiguration()
            valid_op.set_configuration(config)
            valid_op.execute(self.sat_model)
            
            is_valid = valid_op.get_result()
            val_time = round(time.time() - start_time, 4)
            
            if is_valid:
                return {
                    "valid": True,
                    "time": val_time,
                    "message": "El manifiesto es estructuralmente válido. Cumple el esquema de Kubernetes."
                }
            else:
                return {
                    "valid": False,
                    "time": val_time,
                    "message": "El manifiesto es INVÁLIDO estructuralmente. Faltan propiedades obligatorias (Mandatory) o existen conflictos de esquema."
                }
                
        except Exception as e:
            logger.error(f"Error en validación SAT: {e}")
            return {"valid": False, "time": 0, "message": f"Error interno del solver: {str(e)}"}