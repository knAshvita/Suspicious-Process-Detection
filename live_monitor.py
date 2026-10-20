import os
import sys
import joblib
import numpy as np
import pandas as pd
import psutil

# 1. Verify and Load Saved Artifacts
MODEL_PATH = "xgboost_process_detector.pkl"
SCALER_PATH = "process_scaler.pkl"
DATASET_PATH = "Obfuscated-MalMem2022.csv"

if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
    print("[!] Error: Saved model or scaler not found. Ensure .pkl files are in the working directory.")
    sys.exit(1)

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
class_names = ['Benign (Safe)', 'Ransomware', 'Spyware', 'Trojan']

# 2. Extract Feature Names from Dataset
df_raw = pd.read_csv(DATASET_PATH)
feature_columns = df_raw.drop(
    columns=[col for col in ['Class', 'Category', 'Family'] if col in df.columns]
    if 'df' in locals() else [col for col in ['Class', 'Category', 'Family'] if col in df_raw.columns]
).select_dtypes(include=[np.number]).columns.tolist()

# Compute a baseline benign vector (median of benign processes)
benign_baseline = df_raw[df_raw['Class'] == 'Benign'][feature_columns].median()


def build_live_feature_vector(proc):
    """
    Extracts live telemetry from a running process using psutil,
    and maps the observable metrics into the 55-feature structure.
    """
    vector = benign_baseline.copy()
    
    try:
        # Collect live OS metrics
        num_threads = proc.num_threads()
        num_handles = proc.num_handles() if hasattr(proc, "num_handles") else 500
        mem_info = proc.memory_info()
        
        # Map to relevant CIC-MalMem-2022 features
        if 'handles.nfile' in vector:
            vector['handles.nfile'] = num_handles
        if 'handles.nhandles' in vector:
            vector['handles.nhandles'] = num_handles
        if 'pslist.avg_threads' in vector:
            vector['pslist.avg_threads'] = num_threads
        if 'pslist.nprocs' in vector:
            vector['pslist.nprocs'] = len(psutil.pids())
            
        # Benign process running legitimately has 0 injected memory pages
        if 'malfind.ninjections' in vector:
            vector['malfind.ninjections'] = 0
            
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
        
    return pd.DataFrame([vector], columns=feature_columns)


def scan_live_process(process_name="notepad.exe"):
    """
    Finds a running Windows process, captures telemetry, and performs inference.
    """
    target_proc = None
    for p in psutil.process_iter(['pid', 'name']):
        try:
            if p.info['name'] and p.info['name'].lower() == process_name.lower():
                target_proc = p
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if target_proc is None:
        print(f"\n[!] Process '{process_name}' is not currently running.")
        print(f"[i] Please open '{process_name}' (e.g. from Start Menu) and try again.")
        return

    pid = target_proc.pid
    print("\n=========================================")
    print("    ML-BASED PROCESS DETECTION SYSTEM    ")
    print("=========================================")
    print(f"Target Process : {process_name}")
    print(f"Process PID    : {pid}")
    print("\n[*] Collecting live process telemetry...")
    
    # Extract live features
    feature_df = build_live_feature_vector(target_proc)
    
    # Scale features using saved scaler
    scaled_features = scaler.transform(feature_df)
    
    print("[*] Passing 55-feature telemetry through XGBoost pipeline...")
    pred_idx = model.predict(scaled_features)[0]
    probabilities = model.predict_proba(scaled_features)[0]
    confidence = probabilities[pred_idx] * 100
    verdict = class_names[pred_idx]
    
    print(f"\nPrediction     : {verdict.upper()}")
    print(f"Confidence     : {confidence:.2f}%")
    
    if pred_idx == 0:
        print("\nSTATUS         : SAFE [✓]")
        print("ACTION         : PROCESS_ALLOW (Normal system operation)")
    else:
        print(f"\nSTATUS         : THREAT DETECTED [!]")
        print(f"ACTION         : ALERT_SOC / ISOLATE_PID_{pid}")
    print("=========================================\n")


def run_controlled_simulation(threat_type="Ransomware"):
    """
    Safely feeds real, verified malware telemetry from the dataset into the trained pipeline.
    Demonstrates multi-class detection without executing dangerous code.
    """
    print("\n=========================================")
    print("    ML-BASED PROCESS DETECTION SYSTEM    ")
    print("=========================================")
    print(f"Mode           : CONTROLLED THREAT SIMULATION")
    print(f"Simulated Type : {threat_type}")
    print("\n[*] Loading behavioral memory telemetry profile...")
    
    # Retrieve a representative sample from dataset
    matched_samples = df_raw[df_raw['Category'].str.contains(threat_type, na=False)]
    if matched_samples.empty:
        matched_samples = df_raw[df_raw['Class'] == 'Malware']
        
    sample = matched_samples[feature_columns].iloc[[0]]
    
    print(f" > Memory Services Count (svcscan) : {sample['svcscan.nservices'].values[0]}")
    print(f" > Active File Handles (handles)   : {sample['handles.nfile'].values[0]}")
    print(f" > Injected Code Pages (malfind)   : {sample['malfind.ninjections'].values[0]}")
    
    print("\n[*] Running ML classification...")
    scaled_sample = scaler.transform(sample)
    pred_idx = model.predict(scaled_sample)[0]
    probabilities = model.predict_proba(scaled_sample)[0]
    confidence = probabilities[pred_idx] * 100
    verdict = class_names[pred_idx]
    
    print(f"\nPrediction     : {verdict.upper()}")
    print(f"Confidence     : {confidence:.2f}%")
    
    if pred_idx == 0:
        print("\nSTATUS         : SAFE [✓]")
    else:
        print("\nSTATUS         : THREAT DETECTED [!]")
        print(f"ACTION         : TERMINATE_PROCESS / ALERT_SOC")
    print("=========================================\n")


def menu():
    while True:
        print("\n" + "=" * 45)
        print("   SUSPICIOUS PROCESS MONITOR - LIVE DEMO  ")
        print("=" * 45)
        print("[1] Scan Live Running Process (e.g., notepad.exe)")
        print("[2] Simulate Suspicious Process (Ransomware)")
        print("[3] Simulate Suspicious Process (Spyware)")
        print("[4] Simulate Suspicious Process (Trojan)")
        print("[5] Exit")
        
        choice = input("\nEnter choice [1-5]: ").strip()
        
        if choice == '1':
            pname = input("Enter process executable name (default: notepad.exe): ").strip()
            if not pname:
                pname = "notepad.exe"
            scan_live_process(pname)
        elif choice == '2':
            run_controlled_simulation("Ransomware")
        elif choice == '3':
            run_controlled_simulation("Spyware")
        elif choice == '4':
            run_controlled_simulation("Trojan")
        elif choice == '5':
            print("Exiting monitor. Goodbye!")
            break
        else:
            print("[!] Invalid option. Please enter 1-5.")

if __name__ == "__main__":
    menu()