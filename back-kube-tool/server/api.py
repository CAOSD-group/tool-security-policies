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
from core.structural_validator import StructuralValidator


logger = logging.getLogger(__name__)

app_state = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Kube-Sec-Analyzer Engine...")
    uvl_path = os.getenv("UVL_MODEL_PATH", "models/HKFM.uvl")
    # Ruta absoluta al UVL completo para el validador estructural
    full_uvl_path = os.getenv("FULL_UVL_PATH", "models/kubernetes_combined.uvl")
    # Rutas absolutas a los CSV (asumiendo que están en la carpeta resources)
    base_dir = os.path.dirname(os.path.dirname(__file__))
    csv_features = os.path.join(base_dir, "resources", "mapping_csv", "kubernetes_mapping_properties_features.csv")
    csv_kinds = os.path.join(base_dir, "resources", "mapping_csv", "kubernetes_kinds_versions_detected.csv")
    
    try:
        loader = ModelLoader(uvl_path)
        
        # Guardamos en memoria global
        # Motor Regex
        app_state['regex_validator'] = ContentPolicyValidator()
        regex_policy_names = set(app_state['regex_validator'].policy_map.keys())
        #app_state['inference_engine'] = PolicyInference(loader.flat_fm)
        app_state['inference_engine'] = PolicyInference(loader.flat_fm, regex_policy_names)
        app_state['validator'] = Validator(loader.flat_fm, loader.z3_model)
        # Inicializamos el motor SAT estructural
        app_state['structural_validator'] = StructuralValidator(full_uvl_path)
        # INICIALIZAMOS TU CSV MAPPER AQUÍ (Lee los CSV una sola vez)
        app_state['csv_mapper'] = CSVMapper(csv_features, csv_kinds)
        app_state['reverse_mapper'] = ReverseMapper(csv_kinds)
        app_state['remediator_registry'] = RemediationRegistry(uvl_path)
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

            all_active_policies = set()
            failed_policies = set()
            
            for doc in documents:
                kind = doc.get('kind', 'Desconocido')
                api_version = doc.get('apiVersion', 'Desconocida')
                
                if not doc.get('kind'):
                    yield json.dumps({"status": "error", "message": "El documento no tiene propiedad 'kind'."}) + "\n"
                    continue
                if not doc.get('apiVersion'): ## Solo se comprueba si no existe la prop, si existe pero no está en el CSV, el error lo lanzará el CSVMapper y se lo enviaremos al frontend
                    yield json.dumps({"status": "error", "message": "El documento no tiene propiedad 'apiVersion'."}) + "\n"
                    continue
                
                # CORRECCIÓN BUG: INTENTAMOS MAPEAR PRIMERO (Filtro de sintaxis base)
                # Si esto falla (ej. v133), nunca sumamos políticas "fantasma" al recuento.
                # =========================================================================
                try:
                    # Aquí es donde falla si el kind/version no está en tu CSV
                    mapped_json_dict = csv_mapper.transform_manifest(doc)
                except ValueError as ve:
                    # Le enviamos el error exacto al frontend
                    yield json.dumps({"status": "error", "message": f"[{api_version}/{kind}] Recurso no soportado por el modelo: {str(ve)}"}) + "\n"
                    continue

                active_policies = inference_engine.get_policies_for_kind(kind)
                if not active_policies:
                    yield json.dumps({"status": "info", "message": f"[{kind}] No hay políticas de seguridad aplicables a este recurso."}) + "\n"
                    continue
                # --- NUEVO: Añadimos las políticas activas de este recurso ---
                all_active_policies.update(active_policies)

                configurations = MappingEngine.manifest_to_configurations(mapped_json_dict)
                scanned_resources += 1

                if configurations:
                    target_config = configurations[0] 
                    #print("\n=== FEATURES MAPEADAS LISTAS PARA Z3 ===")
                    resource_name = doc.get('metadata', {}).get('name', 'unknown')
                    # Avisamos al frontend del recurso que estamos analizando
                    #yield json.dumps({"status": "info", "message": f"Analizando {kind}: {doc.get('metadata', {}).get('name', 'unknown')}..."}) + "\n"
                    yield json.dumps({"status": "info", "message": f"Analizando {kind}: {resource_name}..."}) + "\n"  
                    
                    regex_policy_names = set(regex_val.policy_map.keys())
                    # Filtramos las políticas activas de Regex
                    print(f"Políticas Regex a evaluar: {regex_policy_names}")
                    # Iteramos sobre las políticas una a una
                    for policy in active_policies:
                        if policy in regex_policy_names:
                            continue # Saltamos las políticas Regex en esta fase, las evaluaremos al final contra el YAML puro
                        
                        try: 
                            violation_list = validator.validate_configuration(target_config, [policy])
                        except Exception as e:
                            error_msg = str(e)
                            print(f"Error al validar política {policy}: {error_msg}")
                            continue

                        if violation_list:
                            for v in violation_list:
                                total_violations += 1
                                failed_policies.add(v["policy"])
                                ## Extract policy tool from UVL metadata
                                meta = validator.get_policy_metadata(v["policy"])
                                v["tool"] = meta.get("tool", "Desconocida")
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
                    active_regex_policies = list(set(active_policies) & regex_policy_names)
                    passed_regex, regex_report = regex_val.validate_with_report(doc, target_config.elements, active_regex_policies)
                    
                    if not passed_regex:
                        for rep in regex_report:
                            total_violations += 1
                            policy_name = rep.get("policy", "unknown")
                            # Le preguntamos al validador (que conoce el UVL) por la metadata de esta política Regex
                            meta = validator.get_policy_metadata(policy_name)
                            failed_policies.add(policy_name)
                            print(f"Error en la politica con el meta {policy_name}: {meta}")
                            v_obj = {
                                "policy": policy_name,
                                "tool": meta.get("tool", "Desconocida"),
                                "severity": meta.get("severity", "medium"), # Usamos .get() de forma segura
                                "description": rep.get("reason", meta.get("description", "Revisión Regex fallida.")),
                                "remediation": meta.get("remediation", "Revisar configuración.")
                            }
                            # Obtenemos acciones de remediación si las hay
                            actions = registry.get_remediation_actions(policy_name)                            
                            # Si definiste una solución manual en el Registry para esta Regex, la inyectamos
                            #actions = registry.get_remediation_actions(rep["policy"])
                            if actions:
                                smart_actions = filter_context_aware_actions(target_config.elements, actions, strip_suffixes=True)
                                v_obj["remediation_actions"] = smart_actions

                            yield json.dumps({"status": "violation", "data": v_obj}) + "\n"
                            await asyncio.sleep(0.01)
            # Al terminar todo, enviamos el resumen final
            passed_policies_names = list(all_active_policies - failed_policies)
            passed_policies_details = []
            for p_name in passed_policies_names:
                # Obtenemos la metadata del modelo UVL
                meta = validator.get_policy_metadata(p_name)
                
                # La descripción puede estar en 'doc' o 'description' según el modelo
                desc = meta.get("doc", meta.get("description", ""))
                if not desc or str(desc).strip() == "":
                    desc = "Política evaluada y superada con éxito. El manifiesto cumple con este requisito de seguridad."

                passed_policies_details.append({
                    "policy": p_name,
                    "tool": meta.get("tool", "Desconocida"),
                    "severity": meta.get("severity", "INFO"), # Nivel por defecto si no tiene
                    "description": desc
                })
            
            yield json.dumps({
                "status": "done", 
                "secure": total_violations == 0,
                "scanned_resources": scanned_resources,
                "passed_policies": passed_policies_details
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

        yaml_content = request.manifest_yaml
        all_patches = []
        
        # 1. Iteramos sobre todas las correcciones ya calculadas que vienen del frontend
        for action in request.actions:
            # Mapeo inverso: de la feature plana (UVL) a ruta de lista para ruamel
            yaml_path = reverse_mapper.get_yaml_path(action.feature_to_fix)
            
            # Acumulamos el parche en lugar de aplicarlo uno a uno
            all_patches.append({
                "path": yaml_path,
                "value": action.safe_value
            })

        # 2. Ejecución del lote de remediación (Mínimo Cambio y 1 sola operación de E/S)
        if all_patches:
            final_yaml = remediator.apply_batch_remediation(yaml_content, all_patches)
        else:
            final_yaml = yaml_content

        return {"status": "success", "remediated_yaml": final_yaml}

    except KeyError as ke:
        logger.error(f"Remediation error (Dependency missing in app_state): {ke}")
        raise HTTPException(status_code=500, detail=f"Error interno: Dependencia {str(ke)} no encontrada.")
    except Exception as e:
        logger.error(f"Remediation error: {e}")
        raise HTTPException(status_code=500, detail=f"Error al parchear el YAML: {str(e)}")

@app.post("/validate-structure")
async def validate_structure_endpoint(request: ValidationRequest):
    """
    Endpoint dedicado a la validación estructural pura del esquema de K8s.
    Usa el Feature Model completo y un solver SAT (PySAT).
    """
    try:
        documents = ManifestParser.parse(request.manifest_yaml)
        if not documents:
            return {"status": "error", "message": "YAML vacío o inválido."}
            
        csv_mapper = app_state['csv_mapper']
        sat_validator = app_state['structural_validator']
        
        doc = documents[0] # Validamos el primer YAML (puedes iterar si hay varios)
        api_version = doc.get('apiVersion', 'Desconocida')
        kind = doc.get('kind', 'Desconocido')
        
        # 1. Filtro 1: ¿Existe en el CSV? (Sintaxis Base)
        try:
            mapped_json_dict = csv_mapper.transform_manifest(doc)
        except ValueError as ve:
            return {
                "status": "invalid",
                "source": "Mapper",
                "message": f"[{api_version}/{kind}] Recurso no soportado por el modelo estructural: {str(ve)}"
            }

        # 2. Generación de Configuración FlamaPy
        configurations = MappingEngine.manifest_to_configurations(mapped_json_dict)
        if not configurations:
            return {"status": "error", "message": "No se pudo generar la configuración para el solver."}
            
        target_config = configurations[0]
        
        # 3. Filtro 2: Validación Formal SAT
        structural_report = sat_validator.validate_structure(target_config.elements)
        
        if structural_report["valid"]:
            return {
                "status": "valid",
                "message": structural_report["message"],
                "time": structural_report["time"]
            }
        else:
            return {
                "status": "invalid",
                "source": "SAT Solver",
                "message": structural_report["message"],
                "time": structural_report["time"]
            }

    except Exception as e:
        logger.error(f"Structural Validation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))