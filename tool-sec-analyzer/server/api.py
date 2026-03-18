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
from core.remediator_registry import RemediationRegistry
from core.regex_validator import ContentPolicyValidator
from core.utils.context_filter import filter_context_aware_actions
from fastapi.responses import StreamingResponse
from typing import List, Any
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
        app_state['remediator_registry'] = RemediationRegistry(uvl_path)
        app_state['remediator'] = Remediator()        
        # Motor Regex
        app_state['regex_validator'] = ContentPolicyValidator()
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

"""class RemediateRequest(BaseModel):
    manifest_yaml: str
    feature_to_fix: str   # Ej: "io_k8s_api_core_v1_Pod_spec_hostNetwork"
    safe_value: bool"""

class RemediateAction(BaseModel):
    feature_to_fix: str
    safe_value: Any

class RemediateRequest(BaseModel):
    manifest_yaml: str
    actions: List[RemediateAction]

@app.get("/")
async def root():
    return {"status": "Kube-Sec Analyzer API is running!", "docs": "/docs"}

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
            regex_val = app_state['regex_validator']
            registry = app_state['remediator_registry']
            
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
                    # Le enviamos el error exacto al frontend
                    yield json.dumps({"status": "error", "message": f"[{api_version}/{kind}] Recurso no soportado por el modelo: {str(ve)}"}) + "\n"
                    continue

                configurations = MappingEngine.manifest_to_configurations(mapped_json_dict)
                scanned_resources += 1

                if configurations:
                    target_config = configurations[0] 
                    print("\n=== FEATURES MAPEADAS LISTAS PARA Z3 ===")

                    print("\n" + "="*50)
                    print("1. DICCIONARIO EXTRAÍDO DEL CSV MAPPER (mapped_json_dict):")
                    print(json.dumps(mapped_json_dict, indent=2))
                    
                    print("\n2. ELEMENTOS FINALES ENVIADOS A Z3 (target_config.elements):")
                    print(f"{target_config.elements}")
                    # Filtramos solo lo relevante al puerto para que sea fácil de leer
                    for k, v in target_config.elements.items():
                        if "port" in str(k).lower():
                            print(f"   -> {k}: {v} (Tipo: {type(v).__name__})")
                    print("="*50 + "\n")
                    resource_name = doc.get('metadata', {}).get('name', 'unknown')
                    # Avisamos al frontend del recurso que estamos analizando
                    #yield json.dumps({"status": "info", "message": f"Analizando {kind}: {doc.get('metadata', {}).get('name', 'unknown')}..."}) + "\n"
                    yield json.dumps({"status": "info", "message": f"Analizando {kind}: {resource_name}..."}) + "\n"  
                    # Iteramos sobre las políticas una a una
                    for policy in active_policies:
                        violation_list = validator.validate_configuration(target_config, [policy])
                        if violation_list:
                            for v in violation_list:
                                total_violations += 1
                                # Obtenemos lista de acciones para reparar esta política
                                actions = registry.get_remediation_actions(v["policy"])
                                if actions:
                                    smart_actions = filter_context_aware_actions(target_config.elements, actions, strip_suffixes=True)
                                    if smart_actions:
                                        v["remediation_actions"] = smart_actions
                                yield json.dumps({"status": "violation", "data": v}) + "\n"
                        await asyncio.sleep(0.01)
                    # 2. VALIDACIÓN DE CONTENIDO (REGEX)
                    # El regex validator analiza el YAML puro (doc) contra las políticas activas
                    passed_regex, regex_report = regex_val.validate_with_report(doc, active_policies)
                    
                    if not passed_regex:
                        for rep in regex_report:
                            total_violations += 1
                            policy_name = rep.get("policy", "unknown")
                            # Le preguntamos al validador (que conoce el UVL) por la metadata de esta política Regex
                            meta = validator.get_policy_metadata(policy_name)
                            
                            # Obtenemos acciones de remediación si las hay
                            actions = registry.get_remediation_actions(policy_name)                            
                            v_obj = {
                                "policy": policy_name,
                                "severity": meta.get("severity", "medium"), # Usamos .get() de forma segura
                                "description": rep.get("reason", meta.get("description", "Revisión Regex fallida.")),
                                "remediation": meta.get("remediation", "Revisar configuración.")
                            }
                            # Si definiste una solución manual en el Registry para esta Regex, la inyectamos
                            actions = registry.get_remediation_actions(rep["policy"])
                            if actions:
                                v_obj["remediation_actions"] = actions
                                
                            yield json.dumps({"status": "violation", "data": v_obj}) + "\n"
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

        current_yaml = request.manifest_yaml
        
        # Iteramos sobre todas las correcciones de la lista
        for action in request.actions:
            yaml_path = reverse_mapper.get_yaml_path(action.feature_to_fix)
            current_yaml = remediator.apply_patch(
                yaml_content=current_yaml, 
                yaml_path=yaml_path, 
                new_value=action.safe_value
            )
        
        return {"status": "success", "remediated_yaml": current_yaml}

    except Exception as e:
        logger.error(f"Remediation error: {e}")
        raise HTTPException(status_code=500, detail=f"Error al parchear el YAML: {str(e)}")
