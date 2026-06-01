from flamapy.metamodels.fm_metamodel.transformations import UVLReader
from flamapy.metamodels.fm_metamodel.models import Constraint
from flamapy.core.models import AST


UVL_MODEL = "../variability_model/HKTFM.uvl"

def main():
    fm = UVLReader(UVL_MODEL).transform()
    print(f'Constraints: {len(fm.get_constraints())}')
    features_per_constraint = {}
    for ctc in fm.get_constraints():
        implication = Constraint('c', AST(ctc.ast.root.right))
        features_in_ctcs = implication.get_features()
        features_per_constraint[ctc.ast.root.left.data] = len(features_in_ctcs)
    
    with open(UVL_MODEL, 'r', encoding='utf-8') as f:
        for line in f:
            if "constraints" in line.strip():
                break
        remaining_lines = f.readlines()
    strings_per_constraints = []
    for line in remaining_lines:
        strings_per_constraints.append(line.count("'") // 2)
    
    for ctc_name, feature_count in features_per_constraint.items():
        print(f'CTC {ctc_name}: {feature_count - strings_per_constraints[list(features_per_constraint.keys()).index(ctc_name)]} features')

    


if __name__ == "__main__":
    main()