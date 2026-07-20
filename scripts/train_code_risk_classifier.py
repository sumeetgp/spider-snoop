"""
Fine-tune CodeRiskClassifier on data from scan_public_repos.py.

Run after:
  python scripts/scan_public_repos.py

Usage:
  python scripts/train_code_risk_classifier.py

Output: models/code_risk_classifier_finetuned/
"""

import os
import sys
import pandas as pd
from collections import Counter

CSV_FILE     = "code_risk_training_data.csv"
MODEL_OUTPUT = "models/code_risk_classifier_finetuned"
BASE_MODEL   = "sentence-transformers/all-MiniLM-L6-v2"
LABELS       = ["REAL_SECRET", "VULNERABLE_LOGIC", "TEST_MOCK", "SAFE_CODE"]

try:
    from setfit import SetFitModel, Trainer, TrainingArguments
    from datasets import Dataset
except ImportError:
    print("ERROR: pip install setfit datasets")
    sys.exit(1)


def load_data() -> pd.DataFrame:
    if not os.path.exists(CSV_FILE):
        print(f"ERROR: {CSV_FILE} not found. Run scan_public_repos.py first.")
        sys.exit(1)

    df = pd.read_csv(CSV_FILE)
    df = df[df["label"].isin(LABELS)][["text", "label"]].dropna()
    df = df.drop_duplicates(subset=["text"])

    # Merge SECURE_CODE → SAFE_CODE
    df["label"] = df["label"].replace("SECURE_CODE", "SAFE_CODE")

    # Cap dominant classes to 300 to reduce imbalance
    MAX_PER_CLASS = 300
    parts = [
        grp.sample(min(len(grp), MAX_PER_CLASS), random_state=42)
        for _, grp in df.groupby("label")
    ]
    df = pd.concat(parts).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"Loaded {len(df)} examples (capped at {MAX_PER_CLASS} per class)\n")
    dist = Counter(df["label"])
    print("Label distribution:")
    for label in LABELS:
        count = dist.get(label, 0)
        bar = "█" * min(count // 5, 50)
        print(f"  {label:20s}: {count:5d}  {bar}")

    # Warn if any class is very thin
    for label in LABELS:
        if dist.get(label, 0) < 8:
            print(f"\nWARNING: {label} has only {dist.get(label, 0)} examples — consider adding more.")

    return df


def build_datasets(df: pd.DataFrame):
    label2id = {l: i for i, l in enumerate(LABELS)}
    df = df.copy()
    df["label"] = df["label"].map(label2id)

    train_parts, test_parts = [], []
    for lid in label2id.values():
        subset = df[df["label"] == lid].sample(frac=1, random_state=42)
        if len(subset) == 0:
            continue
        split = max(1, int(len(subset) * 0.8))
        train_parts.append(subset.iloc[:split])
        test_parts.append(subset.iloc[split:])

    train_df = pd.concat(train_parts).sample(frac=1, random_state=42)
    test_df  = pd.concat(test_parts).sample(frac=1, random_state=42)

    print(f"\nTrain: {len(train_df)} | Test: {len(test_df)}")
    return (
        Dataset.from_pandas(train_df.reset_index(drop=True)),
        Dataset.from_pandas(test_df.reset_index(drop=True)),
    )


def train(train_ds, test_ds):
    start_from = MODEL_OUTPUT if os.path.isdir(MODEL_OUTPUT) else BASE_MODEL
    print(f"\nStarting from: {start_from}")

    model = SetFitModel.from_pretrained(start_from, labels=LABELS)

    args = TrainingArguments(
        num_epochs=3,
        batch_size=16,
        num_iterations=20,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=test_ds,
        metric="accuracy",
    )

    print("Training...")
    trainer.train()
    metrics = trainer.evaluate()
    print(f"\nTest accuracy: {metrics.get('accuracy', 'N/A'):.4f}")
    return model, metrics


def save(model, metrics):
    import json
    os.makedirs(MODEL_OUTPUT, exist_ok=True)
    model.save_pretrained(MODEL_OUTPUT)

    meta = {
        "base_model": BASE_MODEL,
        "labels": LABELS,
        "test_accuracy": metrics.get("accuracy"),
        "training_sources": ["WebGoat", "DVWA", "truffleHog", "factory_boy", "faker", "pytest", "django", "fastapi"],
    }
    with open(os.path.join(MODEL_OUTPUT, "training_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\nModel saved to {MODEL_OUTPUT}/")

    push = input("\nPush to huggingface.co/spidercob/code-risk-classifier? [y/N]: ").strip().lower()
    if push == "y":
        model.push_to_hub("spidercob/code-risk-classifier")
        print("Pushed to HuggingFace!")


def smoke_test(model):
    tests = [
        ("REAL_SECRET",      "hardcoded_secret",   "AWS_ACCESS_KEY_ID=AKIA4REALKEY123ABC committed to main branch .env file"),
        ("VULNERABLE_LOGIC", "vulnerable_pattern",  "$query = 'SELECT * FROM users WHERE id=' . $_GET['id'];"),
        ("TEST_MOCK",        "test_fixture",        "factory_boy default: user.password = 'testpass123' for pytest fixtures"),
        ("SAFE_CODE",        "clean_code",          "def get_user(db: Session, user_id: int): return db.query(User).filter(User.id == user_id).first()"),
        ("SAFE_CODE",        "secure_implementation","password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))"),
    ]
    print("\nSmoke test:")
    for expected, issue_type, snippet in tests:
        text = f"Analyze this {issue_type}: {snippet}"
        pred = model.predict([text])[0]
        probs = model.predict_proba([text])[0]
        conf = max(probs)
        marker = "✓" if pred == expected else "?"
        print(f"  {marker} [{expected:20s}] → {pred:20s} ({conf:.2f})  '{snippet[:55]}'")


def main():
    df = load_data()
    train_ds, test_ds = build_datasets(df)
    model, metrics = train(train_ds, test_ds)
    save(model, metrics)
    smoke_test(model)

    print("\nDone! Deploy with:")
    print("  rsync -az models/code_risk_classifier_finetuned/ root@hetzner-spider:/root/spider-snoop/models/code_risk_classifier_finetuned/")
    print("  ssh hetzner-spider 'cd /root/spider-snoop && docker compose restart api'")


if __name__ == "__main__":
    main()
