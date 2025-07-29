##https://raw.githubusercontent.com/flamapy/flamapy_fw/refs/heads/develop/flamapy/metamodels/configuration_metamodel/transformations/configuration_basic_reader.py
import json
import os
from flamapy.core.transformations.text_to_model import TextToModel

from copy import deepcopy
from itertools import product
from flamapy.metamodels.configuration_metamodel.models.configuration import Configuration
from flamapy.core.utils import file_exists
from flamapy.core.exceptions import ConfigurationNotFound


class ConfigurationJSON(TextToModel):
    @staticmethod
    def get_source_extension() -> str:
        return 'json'

    def __init__(self, path: str) -> None:
        self._path = path

    def transform(self):
        """
        Transform the JSON configuration file into a list of Configuration objects.

        Returns:
            list: List of Configuration instances created from the JSON input.
        """

        json_data = self.get_configuration_from_json(self._path)
        base_config = {}
        blocks = []

        self.extract_features(json_data['config'], base_config, blocks)

        configurations = self.generate_combinations(base_config, blocks)
        return configurations

    def extract_features(self, data, base_config, blocks):
        """
        Recursively extract base feature values and blocks of alternative feature sets.

        Args:
            data (dict or list): Raw JSON configuration input.
            base_config (dict): Dictionary to store static feature-value pairs.
            blocks (list): List to store grouped combinations of features.
        """

        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (str, int, float, bool)):
                    base_config[key] = value

                elif isinstance(value, dict):
                    base_config[key] = True
                    self.extract_features(value, base_config, blocks)

                elif isinstance(value, list):
                    if not value:
                        if key:
                            base_config[key] = True
                        continue

                    if all(isinstance(x, dict) for x in value):
                        combined_block = []
                        if len(value) > 0:
                            for item in value:
                                static = {}
                                lists = {}
                                aux_lists = {}
                                
                                for k, v in item.items():
                                    #base_config[k] = True
                                    if isinstance(v, list):
                                        # Attempt to extract primitive values from dicts
                                        static[k] = True
                                        extracted_values = []
                                        aux_combined_block = []
                                        for item in v:
                                            if isinstance(item, dict):
                                                # If it is a dictionary with a single primitive value
                                                if len(item) == 1:
                                                    inner_value = list(item.values())[0] ## Cases where there is only 1 item in the list: StringValue, Maps etc.
                                                    inner_key = list(item.keys())[0]
                                                    aux_block = {}
                                                    if isinstance(inner_value, (str, int, float, bool)):
                                                        extracted_values.append(inner_value)
                                                        aux_lists[inner_key] = extracted_values
                                                    elif isinstance(inner_value, dict):
                                                        inner_value [inner_key]= True
                                                        aux_combined_block.append(inner_value)
                                                    else:
                                                        pass
                                                else:
                                                    flat_kv = self.flatten_primitive_kv(item)
                                                    aux_combined_block.append(flat_kv)

                                            elif isinstance(item, (str, int, float, bool)):
                                                extracted_values.append(item)
                                        if extracted_values:
                                            lists = aux_lists
                                        if aux_combined_block :
                                            blocks.append(aux_combined_block)

                                    elif isinstance(v, (str, int, float, bool)):
                                        static[k] = v
    
                                    elif isinstance(v, dict):
                                        self.extract_features(v, static, blocks)

                                if lists:
                                    keys = list(lists.keys())
                                    value_lists = [lists[k] for k in keys]

                                    for prod in product(*value_lists):
                                        merged = {k: prod[i] for i, k in enumerate(keys)}
                                        merged.update(static)
                                        combined_block.append(merged)
                                else:
                                    combined_block.append(static.copy())
                        else:

                            if isinstance(value, (str, int, float, bool)):
                                base_config[key] = value

                        # We add a single combined block
                        blocks.append(combined_block)
                        base_config[key] = True        
        elif isinstance(data, list):
            print(f"Data is list")

    def generate_combinations(self, base_config, blocks, max_combinations = 10000):
        """
        Generate all possible combinations between blocks while including base configuration.

        Args:
            base_config (dict): Base configuration with fixed feature values.
            blocks (list): List of feature blocks with alternative values.
            max_combinations (int): Maximum number of configurations to generate.

        Returns:
            list: List of Configuration objects.
        """
        def backtrack(index, current, result):
            if len(result) >= max_combinations: ## Limiting the generation of configurations to 10k. Case argo-cd.v2.10.6_44.json generates millions and crashes the program..
                return  # Stop generation
            if index == len(blocks):
                merged = deepcopy(base_config)
                for partial in current:
                    merged.update(partial)
                result.append(Configuration(merged))
                return

            for option in blocks[index]:
                current.append(option)
                backtrack(index + 1, current, result)
                current.pop()
        result = []
        backtrack(0, [], result)
        return result

    def flatten_primitive_kv(self ,d):
        """
        Flatten a dictionary to extract all primitive key-value pairs.

        Args:
            d (dict): Nested dictionary to flatten.

        Returns:
            dict: Flattened dictionary with primitive values.
        """
        flat = {}
        for k, v in d.items():
            if isinstance(v, (str, int, float, bool)):
                flat[k] = v
            elif isinstance(v, dict):
                flat[k] = True
                inner = self.flatten_primitive_kv(v)
                flat.update(inner)
        return flat

    def get_configuration_from_json(self, path: str) -> dict:
        """
        Load a configuration from a JSON file and parse its contents.

        Args:
            path (str): Path to the JSON configuration file.

        Returns:
            dict: Parsed JSON content.

        Raises:
            ConfigurationNotFound: If the file does not exist.
        """
        if not file_exists(path):
            raise ConfigurationNotFound

        with open(path, 'r', encoding='utf-8') as jsonfile:
            data = json.load(jsonfile)

        return data
        
if __name__ == '__main__':

    path_json = '../resources/kyverno_policies_jsons/disallow-host-namespaces.json'

    # Imprimir todas las configuraciones generadas    
    configuration_reader = ConfigurationJSON(path_json)
    configurations = configuration_reader.transform()

    print(f"Configuraciones que hay:    {len(configurations)}")
    for i, config in enumerate(configurations):
        configuration = configuration_reader.transform()
        print(f'Configuration {i+1}: {config.elements}') ##{config.elements"""