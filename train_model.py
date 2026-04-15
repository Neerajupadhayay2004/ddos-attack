"""
DDoS Detection - ML Model Training
Trains 3 models: Random Forest, XGBoost (via sklearn), Gradient Boosting
Uses CIC-IDS-2017 dataset (DrDoS_LDAP, DrDoS_MSSQL, DrDoS_UDP, Monday-WorkingHours)
"""
import os
import glob
import warnings
import json
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score, f1_score
from sklearn.pipeline import Pipeline

# ─── CONFIG ─────────────────────────────────────────────────────────────────
DATASET_DIR   = "./DDoS"
MODEL_DIR     = "./models"
SAMPLE_SIZE   = 50_000   # rows per file (large files — keep RAM safe)
RANDOM_STATE  = 42

os.makedirs(MODEL_DIR, exist_ok=True)

# ─── FEATURES ───────────────────────────────────────────────────────────────
# CIC-IDS-2017 standard feature set (trimmed to most predictive)
FEATURE_COLS = [
    ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
    'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
    ' Fwd Packet Length Max', ' Fwd Packet Length Min',
    ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
    'Bwd Packet Length Max', ' Bwd Packet Length Min',
    ' Bwd Packet Length Mean', ' Bwd Packet Length Std',
    ' Flow Bytes/s', ' Flow Packets/s',
    ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min',
    'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std',
    ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total',
    ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min',
    ' Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags',
    ' Fwd Header Length', ' Bwd Header Length',
    'Fwd Packets/s', ' Bwd Packets/s',
    ' Min Packet Length', ' Max Packet Length',
    ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
    ' FIN Flag Count', ' SYN Flag Count', ' RST Flag Count',
    ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count',
    ' CWE Flag Count', ' ECE Flag Count',
    ' Down/Up Ratio', ' Average Packet Size', ' Avg Fwd Segment Size',
    ' Avg Bwd Segment Size',
    ' Subflow Fwd Packets', ' Subflow Fwd Bytes',
    ' Subflow Bwd Packets', ' Subflow Bwd Bytes',
    'Init_Win_bytes_forward', ' Init_Win_bytes_backward',
    ' act_data_pkt_fwd', ' min_seg_size_forward',
    'Active Mean', ' Active Std', ' Active Max', ' Active Min',
    'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min',
]
LABEL_COL = ' Label'

# ─── LOAD DATA ───────────────────────────────────────────────────────────────
def load_dataset():
    files = glob.glob(os.path.join(DATASET_DIR, "*.csv"))
    if not files:
        print(f"[!] No CSV files found in {DATASET_DIR}/")
        print("    Generating synthetic demo data for testing...")
        return generate_synthetic_data()
    
    dfs = []
    for f in files:
        print(f"  Loading: {os.path.basename(f)}")
        try:
            df = pd.read_csv(f, low_memory=False, nrows=SAMPLE_SIZE)
            dfs.append(df)
            print(f"    → {len(df)} rows, label dist: {df[LABEL_COL].value_counts().to_dict()}")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    combined = pd.concat(dfs, ignore_index=True)
    print(f"\n[+] Total rows: {len(combined)}")
    return combined


def generate_synthetic_data(n=40000):
    """Fallback synthetic data if CSVs not present"""
    np.random.seed(42)
    n_attack = n // 2
    n_normal = n - n_attack

    def make_normal(n):
        return {c: np.random.normal(0.3, 0.1, n).clip(0, 1) for c in FEATURE_COLS}

    def make_attack(n):
        d = {c: np.random.normal(0.8, 0.15, n).clip(0, 1) for c in FEATURE_COLS}
        # Amplify distinguishing features
        d[' Flow Packets/s'] = np.random.normal(0.95, 0.05, n).clip(0, 1)
        d[' Flow Bytes/s']   = np.random.normal(0.9, 0.08, n).clip(0, 1)
        d[' SYN Flag Count'] = np.random.normal(0.85, 0.1, n).clip(0, 1)
        return d

    normal = pd.DataFrame(make_normal(n_normal))
    normal[LABEL_COL] = 'BENIGN'
    attack = pd.DataFrame(make_attack(n_attack))
    attack[LABEL_COL] = np.random.choice(
        ['DrDoS_LDAP', 'DrDoS_MSSQL', 'DrDoS_UDP'], n_attack
    )
    df = pd.concat([normal, attack], ignore_index=True).sample(frac=1, random_state=42)
    print(f"[+] Synthetic data: {len(df)} rows")
    return df


# ─── PREPROCESS ──────────────────────────────────────────────────────────────
def preprocess(df):
    # Keep only available feature cols
    available = [c for c in FEATURE_COLS if c in df.columns]
    missing   = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"  [!] Missing {len(missing)} features — filling with 0")
    
    X = df[available].copy()
    # Fill missing columns with 0
    for c in missing:
        X[c] = 0.0
    X = X[FEATURE_COLS]  # enforce order

    # Label encoding: BENIGN=0, anything else=1 (binary attack detection)
    y_raw = df[LABEL_COL].str.strip()
    y = (y_raw != 'BENIGN').astype(int)

    # Clean
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    X = X.clip(-1e9, 1e9)

    print(f"  Features: {X.shape[1]}, Samples: {len(X)}")
    print(f"  Label balance — Normal: {(y==0).sum()}, Attack: {(y==1).sum()}")
    return X, y, FEATURE_COLS


# ─── MODELS ──────────────────────────────────────────────────────────────────
MODELS = {
    "RandomForest": RandomForestClassifier(
        n_estimators=100, max_depth=15, n_jobs=-1,
        class_weight='balanced', random_state=RANDOM_STATE
    ),
    "GradientBoosting": GradientBoostingClassifier(
        n_estimators=100, max_depth=5, learning_rate=0.1,
        subsample=0.8, random_state=RANDOM_STATE
    ),
    "SGD_SVM": Pipeline([
        ('scaler', StandardScaler()),
        ('clf', SGDClassifier(
            loss='hinge', max_iter=1000, tol=1e-3,
            class_weight='balanced', random_state=RANDOM_STATE, n_jobs=-1
        ))
    ]),
}


# ─── TRAIN & EVALUATE ────────────────────────────────────────────────────────
def train_all(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    results = {}

    for name, model in MODELS.items():
        print(f"\n  Training {name}...")
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        f1  = f1_score(y_test, y_pred, average='weighted')
        print(f"    Accuracy: {acc:.4f} | F1: {f1:.4f}")
        print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))

        path = os.path.join(MODEL_DIR, f"{name}.pkl")
        joblib.dump(model, path)
        results[name] = {'accuracy': acc, 'f1': f1, 'path': path}

    return results


# ─── PICK BEST & SAVE ────────────────────────────────────────────────────────
def save_best(results, feature_cols):
    best_name = max(results, key=lambda k: results[k]['f1'])
    best      = results[best_name]
    print(f"\n[★] Best model: {best_name} (F1={best['f1']:.4f})")

    # Copy best model as model.pkl
    import shutil
    shutil.copy(best['path'], os.path.join(MODEL_DIR, 'model.pkl'))

    # Save metadata
    meta = {
        'best_model':   best_name,
        'all_results':  {k: {kk: float(vv) if isinstance(vv, float) else vv
                             for kk, vv in v.items()} for k, v in results.items()},
        'feature_cols': feature_cols,
        'label_map':    {'0': 'BENIGN', '1': 'ATTACK'},
    }
    with open(os.path.join(MODEL_DIR, 'meta.json'), 'w') as f:
        json.dump(meta, f, indent=2)

    print(f"[+] Saved: models/model.pkl + models/meta.json")
    return best_name


# ─── MAIN ────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 60)
    print("  DDoS ML Model Trainer")
    print("=" * 60)

    print("\n[1] Loading dataset...")
    df = load_dataset()

    print("\n[2] Preprocessing...")
    X, y, feature_cols = preprocess(df)

    print("\n[3] Training 3 models...")
    results = train_all(X, y)

    print("\n[4] Saving best model...")
    best = save_best(results, feature_cols)

    print("\n✅ Training complete!")
    for name, r in results.items():
        star = " ★" if name == best else ""
        print(f"   {name}{star}: Accuracy={r['accuracy']:.4f}, F1={r['f1']:.4f}")
