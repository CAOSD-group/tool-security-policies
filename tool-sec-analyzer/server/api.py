from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
import yaml
import logging
import os

from core.model_loader import ModelLoader
from core.manifest_parser import ManifestParser
from core.csv_mapper import CSVMapper
from core.mapping_engine import MappingEngine
from core.policy_inference import PolicyInference
from core.validator import Validator
from core.report_generator import ReportGenerator, AuditReport

from core.reverse_mapper import ReverseMapper
from core.remediator import Remediator

from fastapi.responses import StreamingResponse
import json
import asyncio

logger = logging.getLogger(__name__)

app_state = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Kube-Sec-Analyzer Engine...")
    uvl_path = os.getenv("UVL_MODEL_PATH", "models/HKFM.uvl")
    
    # Rutas absolutas a los CSV (asumiendo que están en la carpeta resources)
    base_dir = os.path.dirname(os.path.dirname(__file__))
    csv_features = os.path.join(base_dir, "resources", "mapping_csv", "kubernetes_mapping_properties_features.csv")
    csv_kinds = os.path.join(base_dir, "resources", "mapping_csv", "kubernetes_kinds_versions_detected.csv")
    
    try:
        loader = ModelLoader(uvl_path)
        
        # Guardamos en memoria global
        app_state['inference_engine'] = PolicyInference(loader.flat_fm)
        app_state['validator'] = Validator(loader.flat_fm, loader.z3_model)
        # INICIALIZAMOS TU CSV MAPPER AQUÍ (Lee los CSV una sola vez)
        app_state['csv_mapper'] = CSVMapper(csv_features, csv_kinds)
        app_state['reverse_mapper'] = ReverseMapper(csv_kinds)
        app_state['remediator'] = Remediator()        
        
        logger.info("Engine ready to accept requests.")
        yield
    except Exception as e:
        logger.error(f"Failed to start engine: {e}")
        raise
    finally:
        app_state.clear()

app = FastAPI(title="Kube-Sec-Analyzer API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

class ValidationRequest(BaseModel):
    manifest_yaml: str

class RemediateRequest(BaseModel):
    manifest_yaml: str
    feature_to_fix: str   # Ej: "io_k8s_api_core_v1_Pod_spec_hostNetwork"
    safe_value: bool


@app.post("/validate", response_model=AuditReport)
async def validate_manifest(request: ValidationRequest):
    try:
        documents = ManifestParser.parse(request.manifest_yaml)
        all_violations = []
        
        inference_engine = app_state['inference_engine']
        validator = app_state['validator']
        csv_mapper = app_state['csv_mapper']

        for doc in documents:
            kind = doc.get('kind')
            if not kind:
                continue 
                
            active_policies = inference_engine.get_policies_for_kind(kind)
            if not active_policies:
                continue

            try:
                # 1. Tu CSVMapper transforma el YAML a tu estructura especial JSON
                mapped_json_dict = csv_mapper.transform_manifest(doc)
            except ValueError as ve:
                logger.warning(f"Skipping document: {ve}")
                continue # Salta si no es una versión/kind soportada por tu CSV

            # 2. MappingEngine solo se encarga del producto cartesiano de FlamaPy
            configurations = MappingEngine.manifest_to_configurations(mapped_json_dict)
            
            if configurations:
                target_config = configurations[0]
                print("\n=== FEATURES MAPEADAS LISTAS PARA Z3 ===")
                print(target_config.elements)
                violations = validator.validate_configuration(target_config, active_policies)
                all_violations.extend(violations)

        return ReportGenerator.generate(violations=all_violations, scanned_resources=len(documents))

    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML provided: {str(e)}")
    except Exception as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during analysis.")


@app.post("/validate-stream")
async def validate_manifest_stream(request: ValidationRequest):
    """
    Endpoint que evalúa las políticas de forma iterativa y devuelve los resultados 
    en tiempo real (streaming) para que el Frontend no se quede congelado.
    """
    async def generate_results():
        try:
            # 1. Avisamos al frontend de que empezamos a parsear
            yield json.dumps({"status": "info", "message": "Parseando manifiesto YAML..."}) + "\n"
            await asyncio.sleep(0.1) # Pequeña pausa para que el stream fluya
            
            documents = ManifestParser.parse(request.manifest_yaml)
            
            inference_engine = app_state['inference_engine']
            validator = app_state['validator']
            csv_mapper = app_state['csv_mapper']

            scanned_resources = 0
            total_violations = 0

            for doc in documents:
                kind = doc.get('kind', 'Desconocido')
                api_version = doc.get('apiVersion', 'Desconocida')
                
                if not doc.get('kind'):
                    yield json.dumps({"status": "error", "message": "El documento no tiene propiedad 'kind'."}) + "\n"
                    continue 
                if not doc.get('apiVersion'):
                    yield json.dumps({"status": "error", "message": "El documento no tiene propiedad 'apiVersion'."}) + "\n"
                    continue                     
                active_policies = inference_engine.get_policies_for_kind(kind)
                if not active_policies:
                    yield json.dumps({"status": "info", "message": f"[{kind}] No hay políticas de seguridad aplicables a este recurso."}) + "\n"
                    continue

                try:
                    # Aquí es donde falla si el kind/version no está en tu CSV
                    mapped_json_dict = csv_mapper.transform_manifest(doc)
                except ValueError as ve:
                    # ¡NUEVO! Le enviamos el error exacto al frontend
                    yield json.dumps({"status": "error", "message": f"[{api_version}/{kind}] Recurso no soportado por el modelo: {str(ve)}"}) + "\n"
                    continue

                configurations = MappingEngine.manifest_to_configurations(mapped_json_dict)
                scanned_resources += 1

                if configurations:
                    target_config = configurations[0] 
                    
                    # Avisamos al frontend del recurso que estamos analizando
                    yield json.dumps({"status": "info", "message": f"Analizando {kind}: {doc.get('metadata', {}).get('name', 'unknown')}..."}) + "\n"
                    
                    # Aquí viene la magia: Iteramos sobre las políticas una a una
                    for policy in active_policies:
                        # Evaluamos SOLO UNA política
                        violation_list = validator.validate_configuration(target_config, [policy])
                        
                        if violation_list:
                            # Si hay vulnerabilidad, se la mandamos inmediatamente al frontend
                            for v in violation_list:
                                total_violations += 1
                                yield json.dumps({"status": "violation", "data": v}) + "\n"
                        
                        # Cedemos el control al event loop para asegurar que el chunk se envía
                        await asyncio.sleep(0.01) 

            # Al terminar todo, enviamos el resumen final
            yield json.dumps({
                "status": "done", 
                "secure": total_violations == 0,
                "scanned_resources": scanned_resources
            }) + "\n"

        except yaml.YAMLError as e:
            yield json.dumps({"status": "error", "message": f"YAML Inválido: {str(e)}"}) + "\n"
        except Exception as e:
            logger.error(f"Validation error: {e}")
            yield json.dumps({"status": "error", "message": "Error interno del servidor."}) + "\n"

    # Devolvemos el generador como un Stream NDJSON (Newline Delimited JSON)
    return StreamingResponse(generate_results(), media_type="application/x-ndjson")

@app.post("/remediate")
async def remediate_manifest(request: RemediateRequest):
    """
    Toma un manifiesto YAML, la feature que viola la seguridad, y el valor seguro.
    Devuelve el YAML parcheado conservando comentarios y formato.
    """
    try:
        reverse_mapper = app_state['reverse_mapper']
        remediator = app_state['remediator']

        # 1. Traducir la feature de FlamaPy a ruta estructural YAML
        yaml_path = reverse_mapper.get_yaml_path(request.feature_to_fix)
        
        # 2. Aplicar el parche físico en el texto
        fixed_yaml = remediator.apply_patch(
            yaml_content=request.manifest_yaml, 
            yaml_path=yaml_path, 
            new_value=request.safe_value
        )
        
        return {"status": "success", "remediated_yaml": fixed_yaml}

    except Exception as e:
        logger.error(f"Remediation error: {e}")
        raise HTTPException(status_code=500, detail=f"Error al parchear el YAML: {str(e)}")
