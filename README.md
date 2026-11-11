# 🛡️ ML-Based Suspicious Process Detection System

A machine-learning project that combines a four-class malware classifier with a web-based system monitoring dashboard. The project uses the CIC-MalMem-2022 dataset to train a hybrid ensemble model and provides APIs and a React interface for viewing system processes, checking model status, running controlled dataset-based simulations, and trying an experimental process scan.

> **Important limitation:** The model was trained on memory-forensics features from CIC-MalMem-2022. Ordinary live process metadata collected through `psutil` is not equivalent to those 55 training features. The live process scan currently fills most feature values using a benign-dataset baseline, so its prediction is experimental and must not be treated as a reliable malware verdict or endpoint-protection tool.

---

## 📌 Project Overview

- **Domain:** Operating System Security and Machine Learning
- **Dataset:** CIC-MalMem-2022 (`Obfuscated-MalMem2022.csv`)
- **Model:** Three-model weighted soft-voting ensemble
- **Algorithms:** XGBoost, Random Forest, Logistic Regression
- **Classification:** Benign, Ransomware, Spyware, Trojan
- **Backend:** Python, FastAPI
- **Frontend:** React, Vite
- **System information:** `psutil`

### Project objectives

1. Train and evaluate machine-learning models using memory-forensics data.
2. Compare individual classifiers and a hybrid ensemble.
3. Expose model and process information through a FastAPI backend.
4. Provide a dashboard for system monitoring and model status.
5. Demonstrate dataset-based threat predictions and an experimental live process scan.

---

## ✨ Features

### Web dashboard

- **Dashboard:** Overview of monitored system processes and scanner status.
- **Live Monitoring:** Displays running process information and provides a manual process-scan interface.
- **Threat Detection:** Runs controlled predictions using samples from the dataset.
- **Model Performance:** Displays model information and available performance details.
- **Settings:** Provides the available interface and refresh settings.

### Backend

- FastAPI service with a health endpoint.
- Reads running process information from the operating system using `psutil`.
- Loads the trained model artifacts and dataset for supported operations.
- Provides controlled dataset-based simulations for Ransomware, Spyware, and Trojan samples.
- Provides an experimental `/api/scan-process` endpoint for scanning a named running process.

### Machine-learning model

The hybrid classifier combines three estimators using weighted soft voting:

| Estimator | Weight |
|---|---:|
| XGBoost | 2 |
| Random Forest | 2 |
| Logistic Regression | 1 |

The model returns a prediction across four classes: Benign, Ransomware, Spyware, and Trojan.

---

## 📊 Dataset and Classification

| Item | Details |
|---|---|
| Dataset | CIC-MalMem-2022 |
| CSV file | `Obfuscated-MalMem2022.csv` |
| Total samples | 58,596 |
| Input features | 55 |
| Classification | Four classes |

### Target classes

| Label | Category | Samples |
|---:|---|---:|
| 0 | Benign | 29,298 |
| 1 | Ransomware | 9,791 |
| 2 | Spyware | 10,020 |
| 3 | Trojan | 9,487 |

The input columns represent memory-forensics indicators. They should not be interpreted as a direct representation of ordinary process metadata such as process name, CPU usage, or memory usage.

---

## 🔬 Model Training and Reported Results

The project evaluates Logistic Regression, Random Forest, XGBoost, and a three-model hybrid soft-voting ensemble.

The following figures are the results recorded for the model evaluation run documented by the project:

| Model | Accuracy | Macro F1-score |
|---|---:|---:|
| Logistic Regression | 74.02% | 61.03% |
| Random Forest | 83.34% | 75.06% |
| XGBoost | 85.40% | 78.06% |
| Hybrid (XGBoost + Random Forest + Logistic Regression) | 84.85% | 77.26% |

**Reported observations:**

- XGBoost had the highest standalone accuracy in that evaluation.
- The hybrid model combines probability outputs from the three estimators using weights `[2, 2, 1]`.
- The hybrid model did not outperform XGBoost on the reported accuracy or macro F1-score; it is included as an ensemble comparison.

These results describe evaluation on the project dataset and split only. They do not establish equivalent accuracy on unseen malware, other datasets, or live Windows processes.

---

## 🧠 How Soft Voting Works

Each estimator produces class probabilities. The ensemble calculates a weighted average of those probabilities and selects the class with the highest combined probability.

\[
P_{\mathrm{ensemble}}(k) =
\frac{2P_{\mathrm{XGBoost}}(k) + 2P_{\mathrm{RandomForest}}(k) + P_{\mathrm{LogisticRegression}}(k)}{5}
\]

The class with the highest ensemble probability becomes the model's predicted class.

---

## 🏗️ System Workflow

1. Load and prepare the CIC-MalMem-2022 dataset.
2. Map the target categories to four class labels.
3. Preprocess the 55 input features using the model's expected scaler.
4. Train and evaluate the individual estimators and hybrid classifier.
5. Load the saved model and preprocessing artifacts in the FastAPI backend.
6. Retrieve operating-system process information for the monitoring interface.
7. Display process and model information in the React dashboard.
8. Run controlled simulations using dataset samples.
9. Optionally run an experimental scan for a named process.

### Understanding the two scan paths

**Controlled dataset simulation:** The backend selects an existing dataset sample for the requested malware category and passes its feature values through the model. This is useful for demonstrating the classifier, but it is not a live infection test.

**Experimental live process scan:** The backend looks up a running process and collects a small amount of available process metadata. Since this does not provide the full 55 memory-forensics features, the current implementation fills the remaining feature vector using a benign-dataset median baseline. The output is therefore only an experimental demonstration and is not suitable for security decisions.

---

## 🖥️ Technology Stack

| Area | Technologies |
|---|---|
| Programming language | Python, JavaScript |
| Machine learning | Scikit-learn, XGBoost |
| Data processing | NumPy, Pandas |
| Model persistence | Joblib |
| Process monitoring | psutil |
| Backend API | FastAPI, Uvicorn |
| Frontend | React, Vite |
| UI / charts | Lucide React, Recharts |
| Styling | CSS |
| Development tools | VS Code, PowerShell, Git |

---

## 📁 Repository Structure

```text
Suspicious-Process-Detection/
│
├── backend/
│   └── main.py
│
├── frontend/
│   ├── src/
│   │   └── App.jsx
│   ├── package.json
│   └── ...
│
├── Obfuscated-MalMem2022.csv
├── hybrid_process_detector.pkl
├── process_scaler.pkl
├── xgboost_process_detector.pkl
├── train_hybrid.py
├── live_monitor.py
├── .gitignore
└── README.md
```

The exact contents may vary as the project evolves. The backend expects the model, scaler, and dataset files at the paths configured in `backend/main.py`.

---

## ⚙️ Installation and Setup

### Prerequisites

- Windows 10 or Windows 11
- Python installed and available from PowerShell
- Node.js and npm
- Git
- VS Code or another code editor

### 1. Clone the repository

```powershell
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd Suspicious-Process-Detection
```

Replace the placeholder with the actual repository URL.

### 2. Set up the backend

Open a PowerShell terminal:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

Install the backend packages:

```powershell
python -m pip install fastapi "uvicorn[standard]" numpy pandas scikit-learn xgboost joblib psutil
```

Return to the project root if needed. Confirm that the model, scaler, and dataset files are present in the locations expected by `backend/main.py`.

Start the backend:

```powershell
python -m uvicorn main:app --reload --port 8000
```

When started from the `backend` directory, the API is available at:

- API base: `http://127.0.0.1:8000`
- Interactive API documentation: `http://127.0.0.1:8000/docs`
- Health endpoint: `http://127.0.0.1:8000/health`

Keep this terminal running.

### 3. Set up the frontend

Open a **second** PowerShell terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local development URL printed by Vite. In the current development setup, this is typically:

`http://localhost:5173`

Keep the frontend terminal running as well.

---

## 🔌 API Endpoints

The backend currently provides the following application endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Checks whether the API is running |
| GET | `/api/processes` | Retrieves the current process information |
| GET | `/api/model-status` | Retrieves model availability/status information |
| POST | `/api/simulate` | Runs a controlled prediction using a dataset sample |
| POST | `/api/scan-process` | Runs an experimental scan for a named running process |

For the exact request fields and response schemas, open the FastAPI Swagger page at `http://127.0.0.1:8000/docs` while the backend is running.

---

## 🧪 Testing the Application

1. Start the backend and confirm that `http://127.0.0.1:8000/health` responds successfully.
2. Open `http://127.0.0.1:8000/docs` and test the available endpoints.
3. Start the frontend and open the Vite local URL.
4. Check that the Dashboard displays system information.
5. Open Live Monitoring and confirm that process information is displayed.
6. Try the manual process scanner with the name of a process that is currently running, for example `notepad.exe` if Notepad is open.
7. Try the controlled threat simulations and confirm that the interface displays their returned predictions.

A successful API response confirms that the endpoint executed; it does not prove that the experimental live process scan can reliably detect malware.

---

## ⚠️ Limitations and Responsible Use

- **Training/runtime feature mismatch:** The model uses 55 memory-forensics features. The current live process scanner cannot obtain all of these features from ordinary process metadata.
- **Experimental live scan:** Most values in the current live scan are filled from a benign-dataset baseline. The resulting prediction and confidence must not be treated as a trustworthy security verdict.
- **Dataset generalization:** Performance on CIC-MalMem-2022 does not guarantee performance on new malware families, unseen datasets, or real-world machines.
- **False positives and false negatives:** A model prediction may be incorrect.
- **Simulation is not infection detection:** Dataset-based simulations demonstrate model behavior; they do not infect or scan the computer for those malware categories.
- **No automatic remediation:** The application does not provide guaranteed malware removal or complete endpoint protection.
- **Model artifact safety:** Only load trusted pickle/joblib model files. Deserializing untrusted files can execute malicious code.

This project is intended for educational, research, and authorized testing purposes. Do not use its experimental scan output as the sole basis for terminating processes, deleting files, or making security decisions.

---

## 🚀 Future Enhancements

- Integrate a validated memory-forensics feature extraction pipeline.
- Evaluate the model on independent datasets and unseen samples.
- Improve live process analysis without substituting unrelated values for missing training features.
- Add scan history, structured logs, and downloadable reports.
- Add explainability to show which validated features influence predictions.
- Improve model evaluation with repeatable experiments and additional metrics.
- Explore safe integration with established memory-analysis tools.

---

## 👩‍💻 Project Information

- **Project:** ML-Based Suspicious Process Detection System
- **Model:** Weighted soft-voting ensemble (XGBoost + Random Forest + Logistic Regression)
- **Dataset:** CIC-MalMem-2022
- **Backend:** FastAPI
- **Frontend:** React + Vite
- **Purpose:** Academic project for machine-learning-based malware classification and system process monitoring
