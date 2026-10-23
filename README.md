# 🛡️ ML-Based Suspicious Process Detection System

An operating-system-level security system utilizing Machine Learning to detect, profile, and help identify potentially malicious processes in real time. By analyzing runtime process telemetry and behavioral memory indicators rather than relying exclusively on static file signatures, this system aims to identify suspicious activity associated with obfuscated and memory-resident malware while minimizing disruption to legitimate operating system tasks.

---

## 📌 Project Overview

- **Domain:** Operating System Security & Machine Learning-Based Malware Detection
- **Target Environment:** Runtime Process Inspection and Volatile Memory Analysis
- **Core Problem:** Traditional antivirus systems that rely heavily on static file signatures and hashes can be challenged by polymorphic code, packed malware, and fileless execution techniques.
- **Solution:** An **XGBoost-based classification pipeline** trained on behavioral memory artifacts from the `CIC-MalMem-2022` dataset, integrated with an interactive process monitoring engine.

The project combines offline model training and evaluation with a live monitoring demonstration that collects available process information and uses the trained model to classify processes into four categories.

## 📊 Dataset & Multi-Class Classification

- **Dataset:** `CIC-MalMem-2022`
- **Dataset File:** `Obfuscated-MalMem2022.csv`
- **Total Samples:** 58,596
- **Behavioral Features:** 55
- **Classification Type:** Four-class classification

### Target Classes

| Class Label | Category | Description | Samples |
|---|---|---|---:|
| `0` | **Benign** | Legitimate processes and safe activity | 29,298 |
| `1` | **Ransomware** | Malware associated with file encryption and ransomware behavior | 9,791 |
| `2` | **Spyware** | Malware associated with surveillance and data collection | 10,020 |
| `3` | **Trojan** | Malware associated with unauthorized access and backdoor behavior | 9,487 |

### Why Multi-Class Classification?

Binary classification experiments on this dataset can produce unrealistically high scores when dataset-specific artifacts or shortcuts make the classes easy to distinguish.

This project uses multi-class classification to distinguish between benign processes, ransomware, spyware, and trojans. The approach provides a more detailed classification output, although its generalization to unseen malware and real-world environments requires further validation.

---

## 🔬 Model Training & Performance

Four machine learning models were trained and benchmarked using an **80:20 train-test split**.

| Model | Accuracy | Macro F1-Score | Status |
|---|---:|---:|---|
| **XGBoost** | **84.31%** | **76.44%** | Selected Model |
| Random Forest | 81.87% | 72.86% | Evaluated Baseline |
| Logistic Regression | 74.02% | 61.04% | Evaluated Baseline |
| Linear SVM | 73.00% | 59.43% | Evaluated Baseline |

### Why XGBoost?

XGBoost achieved the highest accuracy and macro F1-score among the evaluated models. It was therefore selected as the primary classification engine.

The macro F1-score gives equal importance to each class, making it useful for assessing performance across multiple categories rather than focusing only on the overall number of correct predictions.

### Key Behavioral Indicators

The following dataset features are relevant to the project's behavioral analysis:

- **`svcscan.nservices`** — Number of detected Windows services.
- **`svcscan.shared_process_services`** — Information about services associated with shared processes.
- **`malfind.ninjections`** — Indicators associated with suspicious memory regions and possible process injection.
- **`handles.nfile`** — Number of file handles, which can contribute to analyzing process behavior.

These indicators can help a classifier distinguish patterns in the training data. However, individual features do not independently prove that a process is malicious.

### False Positive Evaluation

The project documentation reports **zero false positives across 5,860 clean system instances** in the evaluated test.

This result applies to the tested samples and conditions. It does not guarantee zero false positives on other computers, unseen software, or future real-world workloads.

---

## 🏗️ System Workflow

The system follows this general workflow:

1. **Dataset Preparation:** Load the `CIC-MalMem-2022` dataset and prepare the behavioral features.
2. **Preprocessing:** Apply the fitted `StandardScaler` where required by the pipeline.
3. **Model Training:** Train and compare XGBoost, Random Forest, Logistic Regression, and Linear SVM.
4. **Model Evaluation:** Evaluate classification accuracy, macro F1-score, and other relevant metrics.
5. **Artifact Serialization:** Save the trained XGBoost model and fitted scaler.
6. **Live Monitoring:** Collect supported process information using `psutil` and Windows process inspection capabilities.
7. **Classification:** Apply the required feature preparation and model inference to produce a predicted class.
8. **Threat Reporting:** Display the classification results in the terminal for interactive demonstration.

> **Important:** The live detector's reliability depends on whether its runtime feature extraction matches the 55-feature training schema. Ordinary process metadata is not automatically equivalent to the original memory-forensics features.

---

## 🛠️ Repository Structure

```text
Suspicious_Process_Detection/
│
├── Obfuscated-MalMem2022.csv
│   └── Training dataset containing behavioral memory features
│
├── main_notebook.ipynb
│   └── Model development, evaluation, and visualizations
│
├── xgboost_process_detector.pkl
│   └── Serialized trained XGBoost classifier
│
├── process_scaler.pkl
│   └── Fitted StandardScaler preprocessing artifact
│
├── live_monitor.py
│   └── Interactive terminal-based process detection engine
│
├── project_notes.pdf
│   └── Project documentation and analysis notes
│
├── .gitignore
│   └── Files and directories excluded from Git tracking
│
└── README.md
    └── Project documentation and setup instructions
```

---

## ⚙️ Installation & Setup

Follow these steps to clone the repository, install the required dependencies, and run the live monitoring demonstration.

### Prerequisites

- **Operating System:** Windows 10 or Windows 11 is the intended environment for the Windows-specific live monitoring functionality.
- **Python:** Python 3.10–3.14, subject to compatibility with the installed dependency versions.
- **Git:** Required to clone the repository.
- **Terminal:** PowerShell, Command Prompt, or the VS Code integrated terminal.
- **Internet Connection:** Required to clone the repository and install dependencies.

### Step 1: Clone the Repository

Open PowerShell, Command Prompt, or the VS Code terminal and execute:

```powershell
git clone https://github.com/knAshvita/Suspicious_Process_Detection.git

cd Suspicious_Process_Detection
```

### Step 2: Create a Virtual Environment

Creating a virtual environment helps keep project dependencies separate from other Python projects.

```powershell
python -m venv .venv
```

Activate the environment in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation because of its execution policy, you can use Command Prompt instead:

```cmd
.venv\Scripts\activate.bat
```

Alternatively, continue using the environment's Python executable directly without activating it.

### Step 3: Install Dependencies

First, upgrade `pip`:

```powershell
python -m pip install --upgrade pip
```

Install the project's main Python dependencies:

```powershell
python -m pip install numpy pandas scikit-learn xgboost joblib psutil
```

These packages serve the following purposes:

| Package | Purpose |
|---|---|
| `numpy` | Numerical operations and array processing |
| `pandas` | Dataset loading and manipulation |
| `scikit-learn` | Preprocessing, baseline models, and evaluation |
| `xgboost` | XGBoost classification model |
| `joblib` | Loading and saving serialized model artifacts |
| `psutil` | Runtime process and system information |

### Troubleshooting Python Installation Paths

If your computer has multiple Python installations, or if `python` points to the wrong interpreter, check which Python installations are available:

```powershell
py -0p
```

Check the active interpreter and `pip`:

```powershell
python --version
python -m pip --version
```

If you use a specific Python executable, invoke it directly. For example:

```powershell
& "C:\Path\To\Your\Python\python.exe" -m pip install numpy pandas scikit-learn xgboost joblib psutil
```

Replace the example path with the actual path to your installed Python executable.

**Note:** If installation fails because a package does not support your Python version, use a compatible Python release and reinstall the dependencies inside a fresh virtual environment.

### Step 4: Verify the Required Project Files

Before running the detector, ensure the following files are present in the project root directory:

- `live_monitor.py`
- `xgboost_process_detector.pkl`
- `process_scaler.pkl`

The dataset file is also required if the script uses it for runtime simulations or dataset-based demonstrations:

- `Obfuscated-MalMem2022.csv`

The model and scaler files must be compatible with the feature schema and preprocessing used by the script.

**Important:** If these artifacts are not included in the cloned repository, obtain them from the project's authorized source or generate them by running the appropriate training workflow in `main_notebook.ipynb`.

You can list the files in PowerShell using:

```powershell
Get-ChildItem
```

---

## 💻 Running the Live Demonstration

Once the dependencies are installed and the required model artifacts are available, run the detector from the project root directory:

```powershell
python live_monitor.py
```

The script should start the interactive terminal-based monitoring workflow, subject to its implementation and system permissions.

### Expected Workflow

1. The script loads the trained XGBoost model and preprocessing scaler.
2. It begins collecting the process information supported by the implementation.
3. The required features are prepared for model inference.
4. The classifier predicts one of the configured categories.
5. The terminal displays the resulting process classifications and monitoring output.

The exact prompts, output format, monitoring interval, and available commands depend on the current implementation of `live_monitor.py`.

### If the Script Does Not Start

**Model or scaler file not found**

Check that `xgboost_process_detector.pkl` and `process_scaler.pkl` are present in the expected directory.

**Missing Python module**

Install the missing package using:

```powershell
python -m pip install <package_name>
```

Replace `<package_name>` with the module named in the error message.

**Feature mismatch error**

Ensure the live monitoring script supplies the same features in the correct order and format expected by the trained model and scaler.

**Permission or process-access error**

Some process details may require additional permissions. Run with appropriate permissions only when necessary and only if you trust the code being executed.

---

## 📁 Model Development

The `main_notebook.ipynb` notebook contains the model development and evaluation workflow.

To open the notebook in Jupyter, install Jupyter if necessary:

```powershell
python -m pip install notebook
```

Launch it from the project directory:

```powershell
python -m notebook
```

Open `main_notebook.ipynb` in the Jupyter interface.

The notebook can be used to inspect the dataset, prepare features, train and compare models, evaluate performance, and generate the serialized artifacts when the corresponding training cells are executed.

---

## 🔒 Limitations & Responsible Use

- **Dataset limitations:** Performance on CIC-MalMem-2022 does not establish equivalent performance on every operating system, malware family, or real-world workload.
- **Runtime feature coverage:** The availability of live process metadata does not guarantee that all original memory-forensics features can be collected from ordinary running processes.
- **False positives and false negatives:** The classifier can incorrectly flag legitimate processes or miss malicious ones.
- **Model compatibility:** Serialized model artifacts should be loaded only from trusted sources because pickle-based files can execute code during deserialization.
- **Monitoring permissions:** Process inspection may be limited by operating-system permissions and protected processes.
- **No guaranteed remediation:** Classification is not equivalent to malware removal, process termination, or complete endpoint protection. The project should not be treated as a replacement for established security software.

Use the system for educational, research, and authorized security-testing purposes. Validate the live feature extraction and detection results before relying on them in a production environment.

---

## 🚀 Future Enhancements

- Improve runtime feature extraction to better align with the training dataset.
- Evaluate generalization using independent datasets and more rigorous validation splits.
- Add a graphical dashboard for process classifications and monitoring history.
- Introduce explainability features to show which behavioral indicators influenced a prediction.
- Add configurable alert thresholds, structured logging, and report generation.
- Explore safe, controlled integration with additional memory-forensics tools.
- Investigate carefully validated response mechanisms for confirmed threats.

---

## 👩‍💻 Project Information

**Project:** ML-Based Suspicious Process Detection System  
**Primary Model:** XGBoost  
**Dataset:** CIC-MalMem-2022  
**Language:** Python  
**Core Libraries:** NumPy, Pandas, Scikit-learn, XGBoost, Joblib, Psutil  
**Repository:** [Suspicious_Process_Detection on GitHub](https://github.com/knAshvita/Suspicious_Process_Detection)

---

*Developed as a machine learning and operating system security project focused on behavioral malware classification and process monitoring.*
