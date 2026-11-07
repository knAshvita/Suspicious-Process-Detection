import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix

# 1. Load Dataset
DATASET_PATH = "Obfuscated-MalMem2022.csv"
print("[*] Loading dataset...")
df = pd.read_csv(DATASET_PATH)

# 2. Target Encoding & Feature Matrix Separation
# Clean text columns to isolate 55 numeric memory features
drop_cols = [c for c in ['Class', 'Category', 'Family'] if c in df.columns]
X = df.drop(columns=drop_cols).select_dtypes(include=[np.number])

# Map to standard multi-class labels (Benign: 0, Ransomware: 1, Spyware: 2, Trojan: 3)
def label_category(row):
    cat = str(row.get('Category', '')).lower()
    cls = str(row.get('Class', '')).lower()
    if 'benign' in cls or 'benign' in cat:
        return 0
    elif 'ransomware' in cat:
        return 1
    elif 'spyware' in cat:
        return 2
    elif 'trojan' in cat:
        return 3
    return 0

y = df.apply(label_category, axis=1)
target_names = ['Benign', 'Ransomware', 'Spyware', 'Trojan']

# 3. Train-Test Split (80/20) with Stratification
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

# 4. Feature Scaling
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 5. Define Individual Baseline Classifiers
clf_xgb = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=6,
    random_state=42,
    eval_metric='mlogloss'
)

clf_rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=12,
    random_state=42,
    n_jobs=-1
)

clf_lr = LogisticRegression(
    max_iter=1000,
    C=1.0,
    random_state=42
)

# 6. Define the 3-Model Hybrid Ensemble
hybrid_model = VotingClassifier(
    estimators=[
        ('xgb', clf_xgb),
        ('rf', clf_rf),
        ('lr', clf_lr)
    ],
    voting='soft',
    weights=[2, 2, 1]  # Weighting: gives higher vote weight to tree models over linear
)

# 7. Train Models & Evaluate Metrics
models = {
    'Logistic Regression': clf_lr,
    'Random Forest': clf_rf,
    'XGBoost': clf_xgb,
    '3-Model Hybrid (XGB + RF + LR)': hybrid_model
}

results = []

print("\n" + "="*50)
print("       EVALUATING INDIVIDUAL VS HYBRID MODELS     ")
print("="*50)

for name, model_instance in models.items():
    print(f"[*] Training {name}...")
    model_instance.fit(X_train_scaled, y_train)
    
    y_pred = model_instance.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred) * 100
    macro_f1 = f1_score(y_test, y_pred, average='macro') * 100
    
    results.append({
        'Model': name,
        'Accuracy (%)': round(acc, 2),
        'Macro F1 (%)': round(macro_f1, 2)
    })
    print(f"    --> Accuracy: {acc:.2f}% | Macro F1: {macro_f1:.2f}%")

# 8. Comparison Table
df_results = pd.DataFrame(results)
print("\n" + "="*50)
print("             FINAL COMPARISON TABLE               ")
print("="*50)
print(df_results.to_string(index=False))

# 9. Save Hybrid Model Artifact
joblib.dump(hybrid_model, "hybrid_process_detector.pkl")
print("\n[✓] Saved hybrid model as 'hybrid_process_detector.pkl'")

# 9. Save Hybrid Model Artifact
joblib.dump(hybrid_model, "hybrid_process_detector.pkl")
print("\n[✓] Saved hybrid model as 'hybrid_process_detector.pkl'")


# 10. Visualization of Benchmark (Step 3: Visual Comparison Matrix)
plt.figure(figsize=(9, 5))
x_pos = np.arange(len(df_results))
width = 0.35

plt.bar(x_pos - width/2, df_results['Accuracy (%)'], width, label='Accuracy (%)', color='#2b5c8f')
plt.bar(x_pos + width/2, df_results['Macro F1 (%)'], width, label='Macro F1 (%)', color='#e26d5c')

plt.xlabel('Model Architecture')
plt.ylabel('Score (%)')
plt.title('Benchmark: Individual Classifiers vs. 3-Model Hybrid Ensemble')
plt.xticks(x_pos, df_results['Model'], rotation=15)
plt.ylim(50, 100)
plt.legend(loc='lower right')
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()

# Saves the chart image to your folder so you can use it in your slides/report
plt.savefig("model_comparison_hybrid.png", dpi=300)
plt.show()