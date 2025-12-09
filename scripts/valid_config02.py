# ============================================================
# FAST VALIDATOR FOR CONFIGURATIONS - Flamapy + PySAT
# ============================================================

import contextlib
import io
import time
import logging
from pathlib import Path

from flamapy.metamodels.fm_metamodel.models import Feature
from flamapy.metamodels.fm_metamodel.transformations import UVLReader, FlatFM
from flamapy.metamodels.configuration_metamodel.models import Configuration
from flamapy.metamodels.pysat_metamodel.transformations import FmToPysat

from pysat.solvers import Glucose3   # SOLVER PERSISTENTE
from scripts.configurationJSON01 import ConfigurationJSON ## clase Reader JSON

from scripts._inference_policy import (
    extract_policy_kinds_from_constraints,
    infer_policies_from_kind
)


# ============================================================
# FAST VALIDATOR CLASS
# ============================================================

class FastValidator:

    def __init__(self, uvl_path: Path):
        """
        Carga el modelo UVL, su SAT model y construye un solver persistente.
        Toda esta inicialización se ejecuta una sola vez.
        """
        start = time.time()

        # ------------------------------
        # Cargar FM
        # ------------------------------
        print("[INIT] Cargando modelo UVL...")
        fm_model = UVLReader(str(uvl_path)).transform()

        # ------------------------------
        # Aplanar FM
        # ------------------------------
        print("[INIT] Aplanando modelo (FlatFM)...")
        flat_op = FlatFM(fm_model)
        flat_op.set_maintain_namespaces(False)
        flat_fm = flat_op.transform()

        # ------------------------------
        # SAT Model
        # ------------------------------
        print("[INIT] Generando SAT model (FmToPysat)...")
        silent = io.StringIO()
        with contextlib.redirect_stdout(silent):
            sat_model = FmToPysat(flat_fm).transform()

        # ------------------------------
        # Construir solver persistente PySAT
        # ------------------------------
        print("[INIT] Construyendo solver persistente...")

        # Detectar dónde están realmente las cláusulas en esta versión de Flamapy
        if hasattr(sat_model, 'cnf') and sat_model.cnf is not None:
            clause_source = sat_model.cnf.clauses
        elif hasattr(sat_model, '_cnf') and sat_model._cnf is not None:
            clause_source = sat_model._cnf.clauses
        else:
            raise RuntimeError("ERROR: No se encontró ninguna estructura CNF en PySATModel.")

        solver = Glucose3()

        for clause in clause_source:
            solver.add_clause(clause)

        # ------------------------------
        # Precomputar datos necesarios
        # ------------------------------
        print("[INIT] Precomputando SAT_FEATURES & variables...")
        sat_features = set(sat_model.variables.keys())
        varmap = sat_model.variables  # mapping feature → SAT int var

        print("[INIT] Cacheando constraints para inferencia...")
        constraint_map = extract_policy_kinds_from_constraints(uvl_path)

        print("[INIT] Construyendo índice de cardinalidades...")
        suffix_map = self._build_suffix_map(sat_features)

        # Guardar en instancia
        self.fm = fm_model
        self.sat_model = sat_model
        self.solver = solver
        self.sat_features = sat_features
        self.varmap = varmap
        self.constraint_map = constraint_map
        self.suffix_map = suffix_map

        end = time.time()
        print(f"[INIT] COMPLETADO en {round(end - start, 3)} segundos\n")


    # ============================================================
    # Suffix cardinality index (normalización O(1))
    # ============================================================

    @staticmethod
    def _build_suffix_map(sat_features):
        """
        Construye un índice O(1) para mapear nombres base de features con cardinalidad.
        """
        mapping = {}
        for sf in sat_features:
            if "_n1_" in sf:
                base = sf.split("_n1_")[-1]
                mapping[base] = sf
            else:
                base = sf.split("_")[-1]
                mapping[base] = sf
        return mapping


    # ============================================================
    # Obtener hijos obligatorios y padres
    # ============================================================

    def _complete_configuration(self, config: Configuration):
        elems = dict(config.elements)

        for element in config.get_selected_elements():
            feature = self.fm.get_feature_by_name(element)
            if feature is None:
                raise Exception(f"Feature '{element}' no existe en el modelo.")

            # Añadir mandatory children
            stack = list(feature.get_children())
            while stack:
                child = stack.pop()
                if child.is_mandatory():
                    elems[child.name] = True
                    stack.extend(child.get_children())

            # Añadir padres
            parent = feature.get_parent()
            while parent:
                elems[parent.name] = True
                parent = parent.get_parent()

        return Configuration(elems)


    # ============================================================
    # VALIDACIÓN ULTRA RÁPIDA
    # ============================================================

    def validate(self, config_json: Configuration):
        """
        Dado un Configuration JSON cargado con ConfigurationJSON,
        devuelve si es válido y la configuración completa normalizada.
        """

        # 1) Política inferida (constraints ya cacheados)
        inferred = infer_policies_from_kind(config_json.elements, self.constraint_map)
        for p in inferred:
            config_json.elements[p] = True

        # 2) Completar con mandatory + parents
        config = self._complete_configuration(config_json)
        config.set_full(True)

        # 3) Normalizar a SAT assumptions
        assumptions = []

        for feat, enabled in config.elements.items():
            # Direct SAT var
            if feat in self.sat_features:
                var = self.varmap[feat]
            else:
                # cardinalidad normalizada
                mapped = self.suffix_map.get(feat)
                if not mapped:
                    continue
                var = self.varmap[mapped]

            lit = var if enabled else -var
            assumptions.append(lit)

        # 4) SAT solve incremental (ultra rápido)
        valid = self.solver.solve(assumptions=assumptions)

        return valid, config.elements


# ============================================================
# SIMPLE USO DIRECTO
# ============================================================

if __name__ == "__main__":
    HERE = Path(__file__).resolve().parent
    ROOT = HERE.parent
    UVL_PATH = ROOT / "variability_model" / "policies_template" / "policy_structure03.uvl"
    SAMPLE_JSON = ROOT / "resources" / "valid_yamls" / "test-require-run-as-nonroot_1.json"

    print("Inicializando FastValidator...")
    fv = FastValidator(UVL_PATH)

    print("Cargando configuración JSON...")
    cfg_reader = ConfigurationJSON(str(SAMPLE_JSON))
    configs = cfg_reader.transform()
    config = configs[0]

    print("\n==== VALIDANDO ====")
    t0 = time.time()
    valid, full = fv.validate(config)
    t1 = time.time()

    print("Resultado:", valid)
    print("Tiempo validación:", round(t1 - t0, 6), "segundos")
    print("Configuración completa:", full)