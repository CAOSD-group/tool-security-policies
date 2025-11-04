import os
from extract_rego_policies import parse_rego_policy, rego_policy_to_uvl
from extract_rego_policies import load_feature_dict, load_kinds_prefix_mapping

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