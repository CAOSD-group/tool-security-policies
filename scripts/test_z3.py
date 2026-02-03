import logging
from flamapy.metamodels.configuration_metamodel.models import Configuration
from flamapy.metamodels.fm_metamodel.transformations import UVLReader
from flamapy.metamodels.z3_metamodel.transformations import FmToZ3
from flamapy.metamodels.z3_metamodel.operations import (
    Z3Satisfiable,
    Z3Configurations,
    Z3ConfigurationsNumber,
    Z3CoreFeatures,
    Z3DeadFeatures,
    Z3FalseOptionalFeatures,
    Z3AttributeOptimization,
    Z3SatisfiableConfiguration,
    Z3AllFeatureBounds,
)
from flamapy.metamodels.z3_metamodel.operations.interfaces import OptimizationGoal

from flamapy.metamodels.configuration_metamodel.transformations import ConfigurationJSONReader


logging.basicConfig(
    level=logging.DEBUG, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


MODEL = 'resources/models/uvl_models/Pizza_z3.uvl'
CONFIG_1 = 'resources/configs/pizza_z3_config1.json'
CONFIG_2 = 'resources/configs/pizza_z3_config2.json'


def main():
    fm_model = UVLReader(MODEL).transform()
    print(fm_model)
    z3_model = FmToZ3(fm_model).transform()
    print(z3_model)

    result = Z3Satisfiable().execute(z3_model).get_result()
    print(f'Satisfiable: {result}')

    core_features = Z3CoreFeatures().execute(z3_model).get_result()
    print(f'Core features: {core_features}')

    dead_features = Z3DeadFeatures().execute(z3_model).get_result()
    print(f'Dead features: {dead_features}')

    false_optional_features = Z3FalseOptionalFeatures().execute(z3_model).get_result()
    print(f'False optional features: {false_optional_features}')

    configurations = Z3Configurations().execute(z3_model).get_result()
    print(f'Configurations: {len(configurations)}')
    for i, config in enumerate(configurations, 1):
        config_str = ', '.join(f'{f}={v}' if not isinstance(v, bool) else f'{f}' for f,v in config.elements.items() if config.is_selected(f))
        print(f'Config. {i}: {config_str}')

    n_configs = Z3ConfigurationsNumber().execute(z3_model).get_result()
    print(f'Configurations number: {n_configs}')

    attributes = fm_model.get_attributes()
    print('Attributes in the model')
    for attr in attributes:
        print(f' - {attr.name} ({attr.attribute_type})')
    
    variable_bounds = Z3AllFeatureBounds().execute(z3_model).get_result()
    print('Variable bounds for all typed variables:')
    for var_name, bounds in variable_bounds.items():
        print(f' - {var_name}: {bounds}')

    attribute_optimization_op = Z3AttributeOptimization()
    attributes = {'Price': OptimizationGoal.MAXIMIZE,
                  'Kcal': OptimizationGoal.MINIMIZE}
    attribute_optimization_op.set_attributes(attributes)
    configurations_with_values = attribute_optimization_op.execute(z3_model).get_result()
    print(f'Optimum configurations: {len(configurations_with_values)} configs.')
    for i, config_value in enumerate(configurations_with_values, 1):
        config, values = config_value
        config_str = ', '.join(f'{f}={v}' if not isinstance(v, bool) else f'{f}' for f,v in config.elements.items() if config.is_selected(f))
        values_str = ', '.join(f'{k}={v}' for k,v in values.items())
        print(f'Config. {i}: {config_str} | Values: {values_str}')

    configuration = ConfigurationJSONReader(CONFIG_1).transform()
    configuration.set_full(False)
    print(f'Configuration from {CONFIG_1}: {configuration.elements}')
    satisfiable_configuration_op = Z3SatisfiableConfiguration()
    satisfiable_configuration_op.set_configuration(configuration)
    is_satisfiable = satisfiable_configuration_op.execute(z3_model).get_result()
    print(f'Is the configuration satisfiable? {is_satisfiable}')

    configuration = ConfigurationJSONReader(CONFIG_2).transform()
    configuration.set_full(False)
    print(f'Configuration from {CONFIG_2}: {configuration.elements}')
    satisfiable_configuration_op = Z3SatisfiableConfiguration()
    satisfiable_configuration_op.set_configuration(configuration)
    is_satisfiable = satisfiable_configuration_op.execute(z3_model).get_result()
    print(f'Is the configuration satisfiable? {is_satisfiable}')

    # Create a partial configuration
    elements = {'Pizza': True, 'SpicyLvl': 5}
    partial_config = Configuration(elements)
    partial_config.set_full(False)
    # Calculate the number of configuration from the partial configuration
    configs_number_op = Z3ConfigurationsNumber()
    configs_number_op.set_partial_configuration(partial_config)
    n_configs = configs_number_op.execute(z3_model).get_result()
    print(f'#Configurations: {n_configs}')

if __name__ == "__main__":
    main()