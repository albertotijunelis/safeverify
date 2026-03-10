"""E2E test for ML training pipeline."""
import requests
import time
import json

base = "http://127.0.0.1:8099"

# 1. Check dataset stats
r = requests.get(f"{base}/api/dataset/stats")
stats = r.json()
print(f"Dataset: {stats['total']} samples, {stats['feature_count']} features")

# 2. Start training
form = {"mode": "binary", "algorithm": "random_forest", "test_size": "0.2"}
r = requests.post(f"{base}/api/ml/train", data=form)
print(f"Train start: {r.json()}")

# 3. Poll status
for _ in range(30):
    time.sleep(2)
    r = requests.get(f"{base}/api/ml/status")
    st = r.json()
    print(f"  [{st['progress']}%] {st['status']} - {st['message']}")
    if st["status"] in ("completed", "error"):
        break

# 4. Get model list
r = requests.get(f"{base}/api/ml/models")
models = r.json()
print(f"\nModels: {len(models)}")
if models:
    m = models[0]
    metrics = m.get("metrics", {})
    print(f"  Latest: {m['model_id']}")
    print(f"  Mode: {m['mode']}")
    print(f"  Algorithm: {m['algorithm']}")
    print(f"  Samples: {m['sample_count']}")
    print(f"  Features: {m['feature_count']}")
    print(f"  Classes: {m['classes']}")
    print(f"  Accuracy:  {metrics.get('accuracy', 0) * 100:.1f}%")
    print(f"  Precision: {metrics.get('precision', 0) * 100:.1f}%")
    print(f"  Recall:    {metrics.get('recall', 0) * 100:.1f}%")
    print(f"  F1:        {metrics.get('f1', 0) * 100:.1f}%")
    print(f"  ROC-AUC:   {metrics.get('roc_auc', 0) * 100:.1f}%")
    print(f"  CV Mean:   {metrics.get('cv_accuracy_mean', 0) * 100:.1f}%")
    fi = metrics.get("feature_importance", [])
    print(f"  Top 5 features: {[f['feature'] for f in fi[:5]]}")
    print(f"  Confusion matrix: {metrics.get('confusion_matrix', [])}")
