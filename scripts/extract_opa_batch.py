import os, yaml
from extract_rego_policies import parse_rego_policy, rego_policy_to_uvl
from extract_rego_policies import load_feature_dict, load_kinds_prefix_mapping

from extract_polaris_checks import (
    parse_polaris_check,
    polaris_to_uvl
)

def load_polaris_severities(path):
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return data.get("checks", {})

def parse_opa_directory(rego_dir):
  feature_dict = load_feature_dict('../resources/mapping_csv/kubernetes_mapping_properties_features.csv')
  kind_prefix_map = load_kinds_prefix_mapping("../resources/mapping_csv/kubernetes_kinds_versions_detected.csv")

  results = []

  for root, _, files in os.walk(rego_dir):
    for file in files:
      if not file.endswith(".rego"):
        continue
      
      path = os.path.join(root, file)
      policy = parse_rego_policy(path)

      if not policy["conditions"]:
        print(f"[SKIP] No simple conditions found in {file}")
        continue
      
      uvldata = rego_policy_to_uvl(policy, feature_dict, kind_prefix_map)
      if uvldata:
        feature_block, constraint = uvldata
        results.append({"feature": feature_block, "constraint": constraint
        })
  
  return results



def parse_polaris_directory(polaris_dir):
  results = []
  severity_map = load_polaris_severities("../resources/polaris_severity_enhances/config-full.yaml")
  feature_dict = load_feature_dict('../resources/mapping_csv/kubernetes_mapping_properties_features.csv')
  kind_prefix_map = load_kinds_prefix_mapping("../resources/mapping_csv/kubernetes_kinds_versions_detected.csv")
  for root, _, files in os.walk(polaris_dir):
    for file in files:
      if not file.endswith(".yaml"):
          continue

      full_path = os.path.join(root, file)
      check = parse_polaris_check(full_path)

      if not check:
          print(f"[SKIP] Invalid YAML {file}")
          continue

      # polaris_to_uvl returns (feature_block, constraint_expression)
      uvl_feature_block, uvl_constraint_expr = polaris_to_uvl(
          check, feature_dict, kind_prefix_map
      )

      if not uvl_constraint_expr:
          print(f"[SKIP] No mappable conditions in {file}")
          continue
      # lookup severity from severity_map
      severity = severity_map.get(check["id"], "warning")  # default to warning

      # Construct the feature block cleanly (this is the UVL feature definition)
      feature_block = (
          f"{check['id']} {{doc '{check['failure']}', "
          f"tool 'Polaris', severity '{severity}', category '{check['category']}'}}"
      )

      # Store only the constraint expression
      results.append({
          "feature": feature_block,
          "constraint": uvl_constraint_expr,
          "tool": "Polaris",
          "id": check["id"],
          "severity": severity
      })

  return results


def parse_all_sources(rego_dir, polaris_dir):
    feature_dict = load_feature_dict('../resources/mapping_csv/kubernetes_mapping_properties_features.csv')
    kind_prefix_map = load_kinds_prefix_mapping("../resources/mapping_csv/kubernetes_kinds_versions_detected.csv")

    print("=== Procesando Rego/OPA ===")
    opa_rules = parse_opa_directory(rego_dir)

    print("\n=== Procesando Polaris ===")
    polaris_rules = parse_polaris_directory(polaris_dir, feature_dict, kind_prefix_map)

    return opa_rules + polaris_rules