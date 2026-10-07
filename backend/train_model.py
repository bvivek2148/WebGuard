import os
import sys
import glob
import csv
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# ============================================================================
# Multi-Class Attack Taxonomy (0 to 6)
# ============================================================================

ATTACK_NAMES = [
    "Benign",
    "SQL Injection",
    "Cross-Site Scripting",
    "Path Traversal",
    "Server-Side Request Forgery",
    "NoSQL Injection",
    "Remote Code Execution"
]

LABEL_MAP = {
    "benign": 0, "normal": 0, "clean": 0, "safe": 0, "0": 0, 0: 0,
    "sqli": 1, "sql": 1, "sql injection": 1, "1": 1, 1: 1,
    "xss": 2, "cross-site scripting": 2, "2": 2, 2: 2,
    "path-traversal": 3, "traversal": 3, "path traversal": 3, "lfi": 3, "3": 3, 3: 3,
    "ssrf": 4, "server-side request forgery": 4, "4": 4, 4: 4,
    "nosql": 5, "nosqli": 5, "nosql injection": 5, "5": 5, 5: 5,
    "rce": 6, "cmdi": 6, "command injection": 6, "remote code execution": 6, "log4j": 6, "6": 6, 6: 6,
}

def load_data_from_directory(data_dir: str):
    """
    Scans data_dir for CSV datasets (e.g., Kaggle, CSIC, or SecLists).
    Detects payload and label columns automatically.
    """
    if not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)
        return [], []

    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    if not csv_files:
        return [], []

    all_texts = []
    all_labels = []

    print(f"\n📂 Scanning dataset directory: {data_dir}")
    print(f"📄 Found {len(csv_files)} CSV file(s):")

    for file_path in csv_files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if not header:
                    continue

                clean_header = [h.strip().lower() for h in header]

                # Identify payload column
                payload_col = 0
                for candidate in ["payload", "query", "text", "request", "input", "sentence"]:
                    if candidate in clean_header:
                        payload_col = clean_header.index(candidate)
                        break

                # Identify label column
                label_col = 1 if len(clean_header) > 1 else None
                for candidate in ["label", "attack_type", "class", "category", "target", "is_attack"]:
                    if candidate in clean_header:
                        label_col = clean_header.index(candidate)
                        break

                count = 0
                for row in reader:
                    if len(row) <= max(payload_col, label_col if label_col is not None else 0):
                        continue
                    text = row[payload_col].strip()
                    if not text:
                        continue

                    raw_label = row[label_col].strip().lower() if label_col is not None else "1"
                    label_num = LABEL_MAP.get(raw_label, 1)

                    all_texts.append(text)
                    all_labels.append(label_num)
                    count += 1

                print(f"  ✓ {os.path.basename(file_path)}: Loaded {count:,} samples.")

        except Exception as e:
            print(f"  ⚠️ Error loading {os.path.basename(file_path)}: {e}")

    return all_texts, all_labels

def train_model():
    print("=" * 60)
    print("🌲 WebGuard Random Forest Model Training Script")
    print("=" * 60)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data")
    texts, labels = load_data_from_directory(data_dir)

    if not texts:
        print("❌ Error: No datasets found in backend/data/*.csv")
        return

    # If small sample set, balance and expand
    if len(texts) < 500:
        texts = texts * 20
        labels = labels * 20

    print(f"\n🎯 Training dataset size: {len(texts):,} samples.")

    # 1. Extract Character N-Gram TF-IDF Features (n=2 to 5)
    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 5),
        max_features=6000,
        sublinear_tf=True
    )
    X = vectorizer.fit_transform(texts)
    y = np.array(labels)

    # 2. Stratified Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 3. Train Random Forest Classifier
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=30,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    # 4. Evaluate Performance
    y_pred = rf_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n✅ Model Training Complete!")
    print(f"🎯 Random Forest Accuracy: {accuracy * 100:.2f}%\n")

    unique_classes = sorted(list(set(y_test) | set(y_pred)))
    target_names = [ATTACK_NAMES[c] if c < len(ATTACK_NAMES) else f"Class {c}" for c in unique_classes]
    print("Classification Report:")
    print(classification_report(y_test, y_pred, labels=unique_classes, target_names=target_names))

    # 5. Save Model Artifacts
    models_dir = os.path.join(base_dir, "models")
    os.makedirs(models_dir, exist_ok=True)

    vectorizer_path = os.path.join(models_dir, "vectorizer.joblib")
    model_path = os.path.join(models_dir, "rf_model.joblib")

    joblib.dump(vectorizer, vectorizer_path)
    joblib.dump(rf_model, model_path)

    print(f"💾 Saved Vectorizer to: {vectorizer_path}")
    print(f"💾 Saved Random Forest Model to: {model_path}")
    print("=" * 60)

if __name__ == "__main__":
    train_model()
