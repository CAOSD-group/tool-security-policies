import csv
import re
from datetime import datetime, timezone, date, time

class CSVMapper:
  def __init__(self, csv_features_path: str, csv_kinds_path: str):
    self.csv_dict = self._load_features_csv(csv_features_path)
    self.allowed_kinds = self._load_kinds_versions(csv_kinds_path)

  def _load_features_csv(self, csv_path):
    feature_dict = {}
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            feature_dict[row['Feature']] = {
                "middle": row['Midle'],
                "turned": row['Turned'],
                "value": row['Value']
            }
    return feature_dict

  def _load_kinds_versions(self, path_csv):
    kinds_versions = set()
    with open(path_csv, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            kinds_versions.add((row['Version'].strip(), row['Kind'].strip()))
    return kinds_versions

  def extract_yaml_properties(self, data, parent_key='', root_info=None, first_add=True):
    # ... (Copia aquí el contenido exacto de tu función extract_yaml_properties) ...
    simple_props = []
    hierarchical_props = []
    key_value_pairs = []
    
    if root_info is None:
        root_info = {}

    if isinstance(data, dict):
        for key, value in data.items():
          if key is None and value is None: ## Omit the type of cases with declarations "name: [ ? ]"
              raise ValueError(f"Clave o valor inválida detectada: {key}: {value}")
          
          new_key = f"{parent_key}_{key}" if parent_key else key
          # Save key values (apiVersion and kind) to determine the context
          if key in ['apiVersion', 'kind'] and first_add: ## It is only modified if it is the first call
              if key not in root_info:  # Do not overwrite if already defined at the top level.
                  if '/' in value and not '.' in value:
                      value = value.replace('/', '_')
                  elif '.' in value and '/' in value: ## In case the version value contains dots '.' only the second part separated by the sidebar '/' is used to indicate the version within the schemas
                      aux_value = value.split('/') ## As represented in the api_rbac_v1_ schemas, case in the yaml: rbac.authorization.k8s.io/v1
                      value = aux_value[1]
                  elif '.' in value and not '/' in value:
                      ## There is no version definition and only a group or an invalid version is added.
                      raise ValueError(f"apiVersion sin versión explícita: {value}")

                  root_info[key] = value
          simple_props.append(key)

          if isinstance(value, (dict, list)):
              sub_simple, sub_hierarchical, sub_kv_pairs, _ = self.extract_yaml_properties(value, new_key, root_info, first_add=False)
              simple_props.extend(sub_simple)
              hierarchical_props.extend(sub_hierarchical)
              hierarchical_props.append(new_key)  # Values are added after recursion
              key_value_pairs.extend(sub_kv_pairs)
          else:
              hierarchical_props.append(new_key)
              key_value_pairs.append((new_key, value))  # Save key and value

    elif isinstance(data, list):
        for item in data:
          sub_simple, sub_hierarchical, sub_kv_pairs, _ = self.extract_yaml_properties(item, parent_key, root_info, first_add=False)
          simple_props.extend(sub_simple)
          hierarchical_props.extend(sub_hierarchical)
          key_value_pairs.extend(sub_kv_pairs)

    # If we have apiVersion and kind, we add a prefix to the feature to improve accuracy.
    if 'apiVersion' in root_info and 'kind' in root_info and first_add:
        prefix = f"{root_info['apiVersion']}_{root_info['kind']}"
        hierarchical_props = [f"{prefix}_{prop}" for prop in hierarchical_props]
        key_value_pairs = [(f"{prefix}_{key}", value) for key, value in key_value_pairs]
    elif 'apiVersion' not in root_info or 'kind' not in root_info and first_add:
        return None, None, None, root_info ## Try to determine files without apiVersion kind in the root. It also detects those that do not declare properties at the beginning.
    return simple_props, hierarchical_props, key_value_pairs, root_info


  def search_features_in_csv(self, hierarchical_props, key_value_pairs, root_info):
    feature_map = {}

    for feature, meta in self.csv_dict.items():
        middle, turned, value = meta["middle"], meta["turned"], meta["value"]
        if f"_{root_info.get('apiVersion', 'unknown')}_{root_info.get('kind', 'unknown')}_" in feature:
            for hierarchical_prop in hierarchical_props:
                if middle.strip() and hierarchical_prop.endswith(middle):   
                    if value == "-":
                        feature_map[hierarchical_prop] =  {"feature_type": "array", "feature": feature}
                    else:
                        ## Normal execution
                        feature_map[hierarchical_prop] = feature
                
                aux_hierchical_maps = feature.rsplit("_", 1)[0] ## The last part of the feature is omitted to make it possible to compare with the hierarchical_prop and filter the related ones.
                ## Conditions where you want to capture the map features named in the YAMLS
                if middle.strip() and turned == "KeyMap" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop):
                    aux_hierchical_maps_key = f"{hierarchical_prop}_KeyMap" ## The _KeyMap is created manually because it is not included in the YAMLS.
                    feature_map[aux_hierchical_maps_key] = feature
                elif middle.strip() and turned == "ValueMap" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop):
                    aux_hierchical_maps_value = f"{hierarchical_prop}_ValueMap" ## The _ValueMap is created manually because it is not included in the YAMLS.
                    feature_map[aux_hierchical_maps_value] = feature
                elif middle.strip() and turned == "StringValue" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add StringValues appearing in the feature list
                    aux_hierchical_arr_string = f"{hierarchical_prop}_StringValue" ## The _StringValue is created manually because it is a custom feature of the model. It is used to refer to arrays of strings.
                    feature_map[aux_hierchical_arr_string] = feature
                elif middle.strip() and turned == "IntegerValue" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add StringValues appearing in the feature list
                    aux_hierchical_arr_integer = f"{hierarchical_prop}_IntegerValue" ## The _StringValue is created manually because it is a custom feature of the model. It is used to refer to arrays of strings.
                    feature_map[aux_hierchical_arr_integer] = feature
                ## Modified for valueInt
                elif middle.strip() and turned == "valueInt" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add StringValues appearing in the feature list
                    aux_hierchical_value_integer = f"{hierarchical_prop}_valueInt" ## The _StringValue is created manually because it is a custom feature of the model. It is used to refer to arrays of strings.
                    print(f"Deteccion / ejecucion  value int {feature}   {hierarchical_prop} {aux_hierchical_maps}")
                    feature_map[aux_hierchical_value_integer] = feature
                ## StringValueAdditional: Array of Strings that is added differently in the main script of the model.
                elif middle.strip() and turned == "StringValueAdditional" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add StringValues appearing in the feature list
                    aux_hierchical_arr_string_additional = f"{hierarchical_prop}_StringValueAdditional" ## The _StringValue is created manually because it is a custom feature of the model. It is used to refer to arrays of strings.
                    feature_map[aux_hierchical_arr_string_additional] = feature
                ## To add the incorporation of the data selection type features, they are added “manually”. When there is a match of the feature with Turned equal to asString, asNumber or asInteger, they are added if the
                ## inheritance matches the omitted feature. It is added by the alternativity of the model and in the output the one that appears in the JSON is selected. Not knowing the value that is added to the property, it is not possible to define before the data type
                elif middle.strip() and turned == "asString" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add asString in the feature list
                    aux_hierchical_as_string = f"{hierarchical_prop}_asString" ## The _asString is created manually because it is a custom feature of the model. It is used to refer to the String type data selection.
                    feature_map[aux_hierchical_as_string] = feature
                elif middle.strip() and turned == "asNumber" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add asNumber in the feature list
                    aux_hierchical_as_number = f"{hierarchical_prop}_asNumber" ## The _asNumber is created manually because it is a custom feature of the model. It is used to refer to the Number type data selection.
                    feature_map[aux_hierchical_as_number] = feature
                elif middle.strip() and turned == "asInteger" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add asInteger in the feature list
                    aux_hierchical_as_integer = f"{hierarchical_prop}_asInteger" ## The _asInteger is created manually because it is a custom feature of the model. It is used to refer to the Integer type data selection.
                    feature_map[aux_hierchical_as_integer] = feature
                elif middle.strip() and turned == "isNull" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop):
                    aux_hierchical_is_null = f"{hierarchical_prop}_isNull" ## The _isNull is created manually because it is a custom feature of the model. It is used to refer to the features with null value in the properties. It is added to be able to reference such non-value...
                    feature_map[aux_hierchical_is_null] = feature
                elif middle.strip() and turned == "isEmpty" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop):
                    aux_hierchical_is_empty = f"{hierarchical_prop}_isEmpty" ## The _isEmpty is created manually because it is a custom feature of the model. It is used to refer to the features with empty value in the properties. It is added to be able to reference such non-value...
                    feature_map[aux_hierchical_is_empty] = feature
                elif middle.strip() and turned == "isEmpty02" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop):
                    aux_hierchical_is_empty = f"{hierarchical_prop}_isEmpty02" ## The _isEmpty is created manually because it is a custom feature of the model. It is used to refer to the features with empty value in the properties. It is added to be able to reference such non-value...
                    feature_map[aux_hierchical_is_empty] = feature
                # Representation of the selected values, it is checked if any yaml value matches the last part...
                elif middle.strip() and hierarchical_prop in hierarchical_props and hierarchical_prop.endswith(middle) and value == "preserveUnknownFields" and feature not in feature_map: # preserveUnknownFieldsX
                    print(f"Coincidencia features   {feature}   {hierarchical_prop} {aux_hierchical_maps}")
                    feature_map[hierarchical_prop] =  {"feature_type": "specialType", "feature": feature}

                for key, yaml_value in key_value_pairs:
                    if value and str(yaml_value) == value and feature not in feature_map: ## Try to avoid adding the same feature
                        aux_hierchical_value_added = f"{key}_{yaml_value}" ## The yaml_value is added manually because in the inheritance the value of the yaml properties is not appended.
                        if feature.endswith(aux_hierchical_value_added): ## Perhaps the match can be better defined but this ensures that the value matches the yaml value.
                            feature_map[aux_hierchical_value_added] = feature ## Added the feature that also matches the yaml
                            continue
    return feature_map

  def apply_feature_mapping(self, yaml_data, feature_map, auxFeaturesAddedList, aux_hierchical_prop, mapped_key, aux_bool, depth_mapping=0):
    if isinstance(yaml_data, dict) and feature_map is not None:
        new_data = {}
        possible_type_data = ['asString', 'asNumber', 'asInteger']
        yaml_with_error_type = False
        #print(f"YAML DICT: {yaml_data}")
        for key, value in yaml_data.items():
            aux_nested = False ## boolean to determine if a property has a feature value
            aux_array = False ## boolean to determine if a property contains an array or is an array of features
            aux_maps = False ## marking to determine the maps
            aux_str_values = False
            aux_int_value = False
            aux_value_type = False
            aux_value_type_array = False
            aux_feat_empty = False
            aux_feat_null = False
            list_double_version = {'apps_v1', 'batch_v1', 'autoscaling_v1', 'autoscaling_v2', 'policy_v1', 'core_v1'}
            feature_nested = {} ## Structure to add the custom value to define the matching of the default values in the template
            feature_type_value = {}
            feature_map_key_value = {} ## batch.v1 ,autoscaling.v1 y autoscaling.v2, policy.v1, core.v1, core.v1.Binding
            feature_type_array = []
            feature_empty = {}
            feature_null = {}
            
            if isinstance(value, datetime): ## Checking if any of the values are of type Time RCF 3339
                value = value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            if isinstance(key, str) and key == 'clusterName': ## It checks if any keys match 'clusterName' to omit the field directly. Prop does not validate in schema or doc
                continue
            # print(f"FEAUTRE MAP {feature_map}")
            for key_features, value_features in feature_map.items():
                
                # Normal logic for string type values, the value of the key is changed directly
                if isinstance(value_features, str) and value_features.endswith(key) and value_features not in auxFeaturesAddedList:

                    if key_features.count("_") == 2: # len(auxFeaturesAddedList) < 3 and
                        key = value_features
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)
                    elif key_features.count("_") == 3 and any(version in key_features for version in list_double_version): ## batch.v1 ,autoscaling.v1 y autoscaling.v2, policy.v1, core.v1, core.v1.Binding
                        key = value_features
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)
                    elif key_features.count("_") == 3:
                            aux_feature_before_insertion = value_features.rsplit("_", 1)[0]                    
                            if aux_feature_before_insertion in auxFeaturesAddedList:
                                key = value_features
                                auxFeaturesAddedList.add(value_features)                            
                                key = value_features
                                aux_hierchical_prop.append(key_features)
                    else:
                        if any(feature.endswith(key) for feature in auxFeaturesAddedList): ## and aux_feature_before_map not in auxFeaturesAddedList
                            aux_feature_before_insertion = value_features.rsplit("_", 1)[0]
                            feature_aux_depth = re.search(r"[A-Z].*", value_features) ## Regex to capture the group of the first match with an uppercase letter: kind always has the first uppercase letter
                            midle_depth = feature_aux_depth.group(0) ## It is the most ‘real’ feature depth, since it is only based on the properties from the kind that have been chained together.

                            if aux_bool and isinstance(mapped_key, str) and mapped_key and depth_mapping == midle_depth.count('_'): ## mapped_key is the father of the arr
                                mapped_key_before = mapped_key.rsplit("_", 1)[0]
                                if aux_bool and mapped_key.count("_") > 2 and mapped_key.count("_") < value_features.count("_") and mapped_key == aux_feature_before_insertion:
                                    key = value_features
                                    auxFeaturesAddedList.add(value_features)
                                    aux_hierchical_prop.append(key_features)
                                elif aux_bool and aux_feature_before_insertion == mapped_key_before: ## inserted with the depth
                                    key = value_features
                                    auxFeaturesAddedList.add(value_features)
                                    aux_hierchical_prop.append(key_features)
                                else:
                                    continue

                            if aux_feature_before_insertion in auxFeaturesAddedList and not aux_bool:
                                if depth_mapping == midle_depth.count('_'):
                                    if mapped_key.rsplit("_", 1)[0] == aux_feature_before_insertion:
                                        key = value_features
                                        auxFeaturesAddedList.add(value_features)
                                        aux_hierchical_prop.append(key_features)
                                elif mapped_key.count("_") > value_features.count("_"):
                                    continue
                            else:
                                continue
                        aux_feature_before_insertion = value_features.rsplit("_", 1)[0]
                        feature_aux_depth = re.search(r"[A-Z].*", value_features) ## Regex to capture the group of the first match with an uppercase letter: kind always has the first uppercase letter
                        midle_depth = feature_aux_depth.group(0)

                        if isinstance(mapped_key, str) and midle_depth.count("_") == depth_mapping:
                            aux_mapped_before = mapped_key.rsplit("_", 1)[0]
                            if mapped_key.count("_") > 2 and mapped_key.count("_") < value_features.count("_"):
                                feature_mapped_key_depth = re.search(r"[A-Z].*", mapped_key) ## Regex to capture the group of the first match with an uppercase letter: kind always has the first uppercase letter
                                mapped_depth = feature_mapped_key_depth.group(0)
                                if aux_feature_before_insertion == mapped_key:
                                    auxFeaturesAddedList.add(value_features)                          
                                    key = value_features
                                    aux_hierchical_prop.append(key_features)
                                else:
                                    continue
                            elif aux_mapped_before in value_features:
                                auxFeaturesAddedList.add(value_features)                          
                                key = value_features
                                aux_hierchical_prop.append(key_features)
                            else:
                                pass
                        else:
                            continue
                # Check arrays or other assigned features, treat dict type values by the type of structure they have. Modification with 'feature_type': 'array'.
                elif key_features.endswith(key) and isinstance(value_features, dict) and value_features.get("feature_type") == "array": ### Comprobando
                    aux_feature_before_insertion = value_features["feature"].rsplit("_", 1)[0]
                    feature_aux_depth = re.search(r"[A-Z].*", value_features["feature"]) ## Regex to capture the group of the first match with an uppercase letter: kind always has the first uppercase letter
                    midle_depth = feature_aux_depth.group(0)
                    mapped_key_before = mapped_key.rsplit("_", 1)[0]

                    if value_features["feature"] not in auxFeaturesAddedList and midle_depth.count("_") == depth_mapping and mapped_key_before in value_features ["feature"]:
                        if mapped_key.count("_") > 2 and mapped_key.count("_") < value_features["feature"].count("_"):
                            if mapped_key == aux_feature_before_insertion:
                                auxFeaturesAddedList.add(value_features["feature"])
                                key = value_features["feature"]
                                aux_hierchical_prop.append(key_features)
                                aux_array = True
                            else:
                                continue
                        auxFeaturesAddedList.add(value_features["feature"])
                        key = value_features["feature"]
                        aux_hierchical_prop.append(key_features)
                        aux_array = True
                elif isinstance(value, list) and key_features.endswith("StringValue") and  isinstance(value_features, str) and "StringValue" == value_features.split("_")[-1]: ## and value_features not in auxFeaturesAddedList
                    aux_key_last_before_map = value_features.split("_")[-2] ## The penultimate prop is obtained
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0] ## get the value feature minus the last insert

                    str_arr_values = []
                    if value and key == aux_feature_before_insertion and key_features.endswith(f"{aux_key_last_before_map}_StringValue"):### and value.get("key") in value_features  ## key coge los valores del feature mapeado ## key.endswith(aux_key_last_before_map)
                        for str_value in value:
                            str_arr_values.append({
                                value_features: str_value
                            })
                            auxFeaturesAddedList.add(value_features)
                            aux_hierchical_prop.append(key_features)
                        feature_str_value = str_arr_values
                        aux_str_values = True
                ## Seguir un tratamiento similar que con los mapas. Parte final del feature
                elif isinstance(value, list) and key_features.endswith("IntegerValue") and isinstance(value_features, str) and "IntegerValue" == value_features.split("_")[-1]:
                    aux_key_last_before_map = value_features.split("_")[-2]
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0] ## you get the value feature minus the last insert
                    values_arr_int = []
                    if value and key == aux_feature_before_insertion and key_features.endswith(f"{aux_key_last_before_map}_IntegerValue"):
                        for int_value in value:
                            values_arr_int.append({
                                value_features: int_value
                            })
                            auxFeaturesAddedList.add(value_features)
                            aux_hierchical_prop.append(key_features)
                        feature_str_value = values_arr_int
                        aux_str_values = True
                        ## Seguir un tratamiento similar que con los mapas. Parte final del feature
                elif isinstance(value, int) and key_features.endswith("valueInt") and isinstance(value_features, str) and "valueInt" == value_features.split("_")[-1]:
                    aux_key_last_before_map = value_features.split("_")[-2]
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0] ## you get the value feature minus the last insert
                    #values_arr_int = []
                    print(f"Deteccion / ejecucion integration  {value}  {key}  {key_features}   {aux_key_last_before_map} {aux_feature_before_insertion}")
                    if value and key == aux_feature_before_insertion and key_features.endswith(f"{aux_key_last_before_map}_valueInt"):
                        print("ENTRA CONDICIONAL valueInt")
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)
                        feature_int_value = {value_features: value}
                        aux_int_value = True
                        print(f"Dont passed conditionals {key_features}   {aux_key_last_before_map} {aux_feature_before_insertion}")
                elif isinstance(value, dict) and key_features.endswith("StringValueAdditional") and isinstance(value_features, str) and "StringValueAdditional" == value_features.split("_")[-1]: ## and value_features not in auxFeaturesAddedList
                    aux_key_last_before_map = value_features.split("_")[-2]
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0] ## you get the value feature minus the last insert
                    str_values = []
                    if value and key == aux_feature_before_insertion and key_features.endswith(f"{aux_key_last_before_map}_StringValueAdditional"):
                        for str_key, str_value in value.items():
                            str_values.append({
                                value_features:f"{str_key}:{str_value}" 
                            })
                        auxFeaturesAddedList.add(value_features) ## Added by list check
                        aux_hierchical_prop.append(key_features)
                        feature_str_value = str_values
                        aux_str_values = True
                elif isinstance(value, dict) and key_features.endswith("KeyMap") and isinstance(value_features, str) and "KeyMap" == value_features.split("_")[-1] and value_features not in auxFeaturesAddedList:
                    aux_key_last_before_map = value_features.split("_")[-2]
                    aux_feature_before_map = value_features.rsplit("_", 1)[0]
                    key_values = []
                    if key.endswith(aux_key_last_before_map) and key_features.endswith(f"{aux_key_last_before_map}_KeyMap") and key == aux_feature_before_map: # Several checks are made to see if it is the right feature ## key obtains the values of the mapped feature
                        for map_key, map_value in value.items():
                            aux_feature_maps = value_features.rsplit("_", 1)[0] ## the feature is obtained by removing the last part to manually add the ValueMap
                            aux_feature_value = f"{aux_feature_maps}_ValueMap"
                            key_values.append({
                                value_features: map_key,
                                aux_feature_value: map_value
                            })
                            auxFeaturesAddedList.add(value_features)
                            auxFeaturesAddedList.add(aux_feature_value)
                        feature_map_key_value = key_values
                        aux_maps = True

                elif any(key_features.endswith(keyword) for keyword in possible_type_data) and isinstance(value_features, str) and value_features not in auxFeaturesAddedList and value_features.endswith(key_features): ## and any(keyword == value_features.split("_")[1] for keyword in possible_type_data) ### isinstance(value, str) and # and key_features.endswith(possible_type_data)
                    aux_key_last_before_value = value_features.split("_")[-2]
                    aux_value_last = value_features.rsplit("_", 1)[0]
                    if key == aux_value_last:
                        if isinstance(value, dict):
                            for key_item, value_item in value.items():
                                if value_features not in auxFeaturesAddedList:
                                    feature_entry = {}  # Dictionary for each feature
                                    # Validate that the value is consistent with the expected type of the feature
                                    if isinstance(value_item, str) and value_features.endswith("asString"):
                                        feature_entry[value_features] = f"{key_item}:{value_item}"
                                    elif isinstance(value_item, int) and value_features.endswith("asInteger"):
                                        feature_entry[value_features] = f"{key_item}:{value_item}"
                                    elif isinstance(value_item, float) and value_features.endswith("asNumber"): ## There may be cases that in the doc are defined as Number but in the Yaml you enter an Int and it is not detected
                                        ## Alternative to take into account the Integer and map them to Number if necessary. Vice versa for the other case.
                                        ## Add to condition: or (isinstance(value_item, int)
                                        # value_item = float(value_item) if isinstance(value_item, int) else value_item
                                        feature_entry[value_features] = f"{key_item}:{value_item}"
                                    if feature_entry:
                                        feature_type_array.append(feature_entry)
                        
                            if len(feature_type_array) > 0:
                                aux_value_type_array = True
                                auxFeaturesAddedList.add(value_features)
                                aux_hierchical_prop.append(key_features)
                        else:
                            if isinstance(value, str) and key_features.endswith(f"{aux_key_last_before_value}_asString"):
                                feature_type_value[value_features] = value
                                aux_value_type = True
                                auxFeaturesAddedList.add(value_features)
                                aux_hierchical_prop.append(key_features)
                            elif isinstance(value, int) and key_features.endswith(f"{aux_key_last_before_value}_asInteger"):
                                feature_type_value[value_features] = value
                                aux_value_type = True
                                auxFeaturesAddedList.add(value_features)
                                aux_hierchical_prop.append(key_features)
                            elif isinstance(value, float) and key_features.endswith(f"{aux_key_last_before_value}_asNumber"):
                                feature_type_value[value_features] = value
                                aux_value_type = True 
                                auxFeaturesAddedList.add(value_features)
                                aux_hierchical_prop.append(key_features)
                # Representation of the selected values, it is checked if any yaml value matches the last part of the characteristics in the list.
                elif isinstance(value_features, str) and value == value_features.split("_")[-1] and value_features not in auxFeaturesAddedList:
                    aux_key_last_before_value = value_features.split("_")[-2]
                    if value_features.endswith(key_features) and key.endswith(aux_key_last_before_value):
                        aux_nested = True
                        feature_nested[value_features] = aux_nested ## value: at the end the boolean value is left as the added feature is boolean as well
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)

                elif isinstance(value_features, str) and isinstance(value, dict) and not value and 'isEmpty02' == value_features.split("_")[-1] and value_features not in auxFeaturesAddedList:
                    aux_key_last_before_value = value_features.split("_")[-2]
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0] ## you get the value feature minus the last insert
                    if key == aux_feature_before_insertion and value_features.endswith(key_features) and key_features.endswith(f"{aux_key_last_before_value}_isEmpty02"): # and key_features.endswith(f"{aux_key_last_before_map}_StringValueAdditional"):
                        aux_feat_empty = True
                        feature_empty[value_features] = aux_feat_empty
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)
                    
                elif isinstance(value_features, str) and isinstance(value, dict) and not value and 'isEmpty' == value_features.split("_")[-1] and value_features not in auxFeaturesAddedList:
                    aux_key_last_before_value = value_features.split("_")[-2] ## 
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0] 
                    if key == aux_feature_before_insertion and value_features.endswith(key_features) and key_features.endswith(f"{aux_key_last_before_value}_isEmpty"): # and key_features.endswith(f"{aux_key_last_before_map}_StringValueAdditional"):
                        aux_feat_empty = True
                        feature_empty[value_features] = aux_feat_empty
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)

                elif isinstance(value_features, str) and value is None and 'isNull' == value_features.split("_")[-1] and value_features not in auxFeaturesAddedList:
                    aux_key_last_before_value = value_features.split("_")[-2]
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0]
                    if key == aux_feature_before_insertion and key_features.endswith(f"{aux_key_last_before_value}_isNull"):
                        aux_feat_null = True
                        feature_null[value_features] = aux_feat_null
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)
                # Representation of the selected values, it is checked if any yaml value matches the last part...
                # 
                elif key_features.endswith(key) and isinstance(value_features, dict) and value_features.get("feature_type") == "specialType" and not value_features.get("feature_type") == "array": # and value_features in auxFeaturesAddedList
                    auxFeaturesAddedList.add(value_features["feature"])
                    key = value_features["feature"]
                    aux_hierchical_prop.append(key_features)                    
                    #continue  # saltar hijos
                    ## elif value_features.get("feature_type") == "preserveUnknownFieldsX" and value_features not in auxFeaturesAddedList:
                """elif key_features.endswith(key) and isinstance(value_features, dict) and value_features.get("feature_type") == "specialTypeX" and not value_features.get("feature_type") == "array": # and value_features in auxFeaturesAddedList
                    auxFeaturesAddedList.add(value_features["feature"])
                    key = value_features["feature"]
                    aux_hierchical_prop.append(key_features)"""

            mapped_key = feature_map.get(key, key)
            aux_arr_key = None
            aux_array_bool = False
            aux_bool_dict = False ## unused
            if aux_nested:
                new_data[mapped_key] = feature_nested
            elif aux_feat_empty:
                new_data[mapped_key] = feature_empty
            elif aux_feat_null:
                new_data[mapped_key] = feature_null
            elif aux_str_values:
                new_data[mapped_key] = feature_str_value
            elif aux_int_value:
                new_data[mapped_key] = feature_int_value
            elif aux_value_type : 
                new_data[mapped_key] = feature_type_value
            elif aux_value_type_array:
                new_data[mapped_key] = feature_type_array
            elif aux_array or isinstance(value, list):
                if aux_maps: 
                    new_data[mapped_key] = feature_map_key_value
                elif value is None:
                    new_data[mapped_key] = []
                else:
                    aux_bool = aux_array
                    try:
                        new_data[mapped_key] = [self.apply_feature_mapping(item, feature_map, auxFeaturesAddedList.copy(), aux_hierchical_prop, mapped_key, aux_bool, depth_mapping+1) if isinstance(item, (dict, list)) else item for item in value] ## auxFeaturesAddedList: antes de la mod
                    except TypeError as te:
                        print(f"[ERROR DE TIPO] en key {mapped_key} (valor: {value}) - {te}")
                        yaml_with_error_type = True ## To mark yamls with error for revision. Not implemented already
                        with open("./error_log_mapping01Types.log", "w", encoding="utf-8") as error_log:
                            error_log.write(f"[ERROR DE TIPO] en key: {mapped_key}, Valor inválido: {value} - {te}\n")
            else:
                aux_bool = aux_array
                try:
                    new_data[mapped_key] = self.apply_feature_mapping(value, feature_map, auxFeaturesAddedList, aux_hierchical_prop, mapped_key, aux_bool, depth_mapping+1) if isinstance(value, (dict, list)) else value
                except TypeError as te:
                    yaml_with_error_type = True ## To mark yamls with error for revision. Not implemented already
                    with open("./error_log_mapping01Types.log", "w", encoding="utf-8") as error_log:
                        error_log.write(f"[ERROR DE TIPO] 2º else, en key: {mapped_key}, Valor inválido: {value} - {te}\n")
            ## Condition to omit the props without feature mapping
            if isinstance(key, str) and key not in feature_map and '_io_' not in key: ## all(not k.startswith(key + "_") for k in feature_map)
                #print(f"PROPS QUE NO SE MAPEAN: {key}    {value}")
                continue
        return new_data

    elif isinstance(yaml_data, list):
        print(f"YAML DATA ELIF {yaml_data}")
        return [self.apply_feature_mapping(item, feature_map, auxFeaturesAddedList, aux_hierchical_prop, mapped_key, aux_bool,depth_mapping+1) for item in yaml_data]
    return yaml_data

  def transform_manifest(self, doc_dict: dict) -> dict:
      """
      Esta es la función principal que llamará la API.
      Recibe el diccionario del YAML, extrae propiedades, busca en el CSV y devuelve el diccionario mapeado al UVL.
      """
      root_info = {}
      # 1. Extraer propiedades
      simple_props, hierarchical_props, key_value_pairs, root_info = self.extract_yaml_properties(doc_dict, root_info=root_info)
      
      # Validar versión (Opcional, si quieres bloquear peticiones no soportadas)
      apiVersion = root_info.get('apiVersion', '').split("_")[-1] if "_" in root_info.get('apiVersion', '') else root_info.get('apiVersion', '')
      kind = root_info.get('kind')
      if (apiVersion, kind) not in self.allowed_kinds:
          # FastAPI devuelva un 400 Bad Request
          raise ValueError(f"Unsupported apiVersion and kind combination: {apiVersion}, {kind}")
          #raise HTTPException(status_code=400, detail=f"Unsupported apiVersion and kind combination: {apiVersion}, {kind}")
      # 2. Buscar en CSV
      feature_map = self.search_features_in_csv(hierarchical_props, key_value_pairs, root_info)
      
      # 3. Aplicar mapeo
      auxFeaturesAddedList = set()
      aux_hierchical = []
      mapped_dict = self.apply_feature_mapping(doc_dict, feature_map, auxFeaturesAddedList, aux_hierchical, {}, False, 1)
      
      # Como tu script original creaba una estructura {"policies": {}, "config": {...}}, lo replicamos:
      return {
          "config": mapped_dict
      }