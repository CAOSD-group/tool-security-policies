# Table of Contents

- [Table of Contents](#table-of-contents)
- [tool-security-policies](#tool-security-policies)
  - [Description](#description)
  - [How it works: Hybrid Validation](#how-it-works-hybrid-validation)
  - [Using the scripts](#using-the-scripts)
    - [Requirements](#requirements)
    - [Download and install](#download-and-install)
    - [Execution](#execution)
  - [Architecture and repository structure](#architecture-and-repository-structure)
  - [Implemented Logic](#implemented-logic)
  - [References and third-party tools](#references-and-third-party-tools)

---

# Kube-Sec Analyzer

## Description

**tool-security-policies** is a research prototype for automated security analysis of Kubernetes manifests using Variability Models (UVL) and Constraint Solving (Z3).

Unlike traditional approaches that rely solely on logic solvers (SAT/SMT) —which struggle with string pattern matching, dynamic lists, and complex content rules— this pipeline implements a **Hybrid Validation Engine**:

1.  **Structural Validation (Z3 Solver):** Uses [Flamapy](https://www.flamapy.org/) to transform UVL constraints into logic formulas to validate boolean properties, field existence, and structural integrity.

---

## Using the scripts

### Requirements

- [Python 3.9+](https://www.python.org/)
- [Flamapy](https://www.flamapy.org/) (and `flamapy-z3` plugin)
- Git
- Bash or PowerShell for script execution

### Download and install

- [Python 3.9+](https://www.python.org/)
- Git
- Bash or PowerShell for script execution

---

### Download and install

1. Install [Python 3.9+](https://www.python.org/)

2. Clone this repository and enter the project folder:
  ```bash
  git clone https://github.com/CAOSD-group/fm-security-policies.git
  cd fm-json-kubernetes
  ```
3. Create a virtual environment:

  ```bash
  python -m venv envFmSec
  ```

4. Activate the environment:

  - **Linux:**
    ```bash
    source envFmSec/bin/activate
    ```
  - **Windows:**
    ```powershell
    .\envFmSec\Scripts\Activate
    ```

5. Install the dependencies:

  ```bash
  pip install -r requirements.txt
  ```


## Architecture and repository structure
The validation workflow is designed as a Hybrid Engine, separating structural logic from content analysis to maximize accuracy.

Note on Solver Evolution: Initially, this project utilized a SAT solver (Boolean Satisfiability) via Flamapy. However, due to the increasing complexity of Kubernetes policies (integers, ranges, and non-boolean logic), the core engine was migrated to Z3 (SMT Solver). This transition allows for richer constraints while maintaining the formal verification capabilities of Feature Models.

### Core Components

* **`getValidationConfigurations02_Z3.py`**: The **Main Orchestrator**. It loads the UVL feature model, parses the input Kubernetes configurations (JSON/YAML), manages the hybrid validation flow (Python First -> Z3/SAT Second), and aggregates results.
* **`scripts/regex_validator.py`** (Class `ContentPolicyValidator`): The **Content Engine**. It handles deep inspection of the configuration files, including:
    * Recursive search for specific keys (e.g., `_image`, `ownerReferences`).
    * Regex pattern matching (e.g., for image tags).
    * Complex logic for dynamic types (Lists, Maps, Annotations) that are difficult for SAT solvers.
* **`scripts/_inference_policy.py`**: The **Policy Selector**. It determines which policies apply to a specific input file based on structural hints (from UVL constraints) and content discovery hooks (e.g., detecting if an image field exists).


### Key folders

* `/variability_model/`: Contains the `Policies.uvl` feature model (the Single Source of Truth for security rules).
* `/resources/`: Dataset containing valid and invalid Kubernetes manifests used for testing and validation.
* `/scripts/`: Source code for the validation logic, helpers, and inference engines.
* `/evaluation/`: Generated CSV reports, logs, and performance metrics from mass validation runs.


## Implemented Logic

The framework aggregates security best practices from multiple industry-standard tools (Kyverno, Fairwinds Polaris, Aqua Security Trivy, OPA/Gatekeeper) into a unified Feature Model.

---

## References and third-party tools

This project relies on the following open-source technologies and standards:

* [**Flamapy**](https://www.flamapy.org/) - Python framework for automated analysis of feature models, used here to parse UVL and interface with solvers.
* [**Kyverno**](https://kyverno.io/) - Kubernetes Native Policy Management. The security policies implemented in this project are based on the Kyverno policy library.
* [**Trivy**](https://github.com/aquasecurity/trivy) - Comprehensive security scanner (formerly OPA/Rego rules).
* [**Polaris**](https://github.com/FairwindsOps/polaris) - Validation of best practices and security.
* [**UVL (Universal Variability Language)**](https://universal-variability-language.github.io/) - The text-based language used to define the security feature model (`Policies.uvl`).
* [**Kubernetes JSON Schema**](https://github.com/yannh/kubernetes-json-schema) - Used as the baseline for the variability model generation.


### FM MODEL OF SECURITY POLICIES AND RULES

Preview of new project to use policies and rules of external tools to check vulnerabilities in configurations with UVL.


