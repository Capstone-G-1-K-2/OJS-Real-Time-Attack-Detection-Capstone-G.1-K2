# Getting Started - OJS Attack Detection System

Panduan lengkap untuk setup, training model, dan menjalankan sistem deteksi serangan OJS.

---

## 📋 Daftar Isi
1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Project Structure](#project-structure)
4. [Training Model](#training-model)
5. [Running Inference](#running-inference)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Pastikan Anda memiliki:
- **Python 3.8+** (recommended: 3.9, 3.10, or 3.11)
- **pip** atau **conda** (package manager)
- **Git** (untuk clone repository)

### Verifikasi Installation
```bash
python --version    # Python 3.8+
pip --version       # Latest pip
git --version       # Git installed
```

---

## Installation

### Step 1: Clone Repository
```bash
git clone https://github.com/Capstone-G-1-K-2/OJS-Real-Time-Attack-Detection-Capstone-G.1-K2.git
cd OJS-Real-Time-Attack-Detection-Capstone-G.1-K2
```

### Step 2: Create Virtual Environment

**Option A: Menggunakan `venv` (Built-in Python)**
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

**Option B: Menggunakan `conda`**
```bash
conda create -n ojs-detector python=3.11
conda activate ojs-detector
```

Setelah virtual environment aktif, command line Anda akan menampilkan:
```
(.venv) C:\path\to\project>
```

### Step 3: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Dependencies utama:**
- pandas - Data manipulation
- scikit-learn 1.5.2 - ML preprocessing
- xgboost - ML model
- pickle - Model serialization (built-in Python module)
- numpy - Numerical computing

### Step 4: Verify Installation
```bash
python -c "import pandas, sklearn, xgboost, pickle; print('All packages installed!')"
```

---

## Project Structure

```
OJS-Real-Time-Attack-Detection-Capstone-G.1-K2/
│
├── README.md                           # Project overview
├── GETTING_STARTED.md                  # This file
├── requirements.txt                    # Dependencies
│
├── data/
│   ├── dataset/
│   │   ├── modsec_raw_labeled.csv      # Sample labeled data (39 rows)
│   │   └── modsec_raw_processed.csv    # Training dataset (142.7K rows) ⭐
│   ├── processed/                      # Output predictions
│   └── raw/                            # Raw ModSecurity logs
│
├── models/
│   ├── trained_models/
│   │   ├── .gitkeep                    # Placeholder
│   │   └── modsec_xgb.pkl              # Trained model (generate via training) ⭐
│   └── model_registry/                 # Baseline models for comparison
│
├── src/
│   ├── preprocessing/
│   │   ├── modsec_parser.py            # Parse ModSecurity logs
│   │   ├── modsec_text_parser.py       # Text format parser
│   │   └── tabular_features.py         # Feature extraction
│   ├── inference/
│   │   └── predict_modsec.py           # Batch inference script
│   ├── training/
│   │   └── train_modsec_model.py       # Model training logic
│   └── utils/                          # Utility functions
│
├── scripts/
│   ├── run_modsec_training.py          # Main training script ⭐
│   ├── test_model.py                   # Model testing
│   ├── prepare_dataset_from_raw.py     # Data preparation
│   ├── analyze_features.py             # Feature analysis
│   ├── quick_test.py                   # Quick validation
│   └── test_ojs_scenarios.py           # OJS-specific scenarios
│
├── notebooks/                          # Jupyter notebooks (optional)
├── configs/                            # Configuration files
├── docs/                               # Documentation
│   └── algorithm_comparison.md         # Algorithm comparisons
└── tests/                              # Unit tests
```

### Key Files untuk Di-perhatikan:
- ⭐ `scripts/run_modsec_training.py` - **Generate model**
- ⭐ `data/dataset/modsec_raw_processed.csv` - **Training data** (jangan dihapus!)
- ⭐ `models/trained_models/modsec_xgb.pkl` - **Model output**
- `src/inference/predict_modsec.py` - Inference engine

---

## Training Model

### ⚠️ PENTING: Model Tidak Ada di Git!

File `.pkl` tidak disimpan di repository karena ukurannya yang besar. **Harus generate sendiri** dengan menjalankan script training.

### How to Generate Model (modsec_xgb.pkl)

Pastikan:
1. ✅ Virtual environment sudah aktif
2. ✅ Dependencies sudah install (`pip install -r requirements.txt`)
3. ✅ Dataset ada di `data/dataset/modsec_raw_processed.csv`

### Run Training Script

```bash
python scripts/run_modsec_training.py \
  --dataset data/dataset/modsec_raw_processed.csv \
  --model-output models/trained_models/modsec_xgb.pkl \
  --cv-splits 3
```

**Parameter penjelasan:**
- `--dataset` - Path ke training dataset
- `--model-output` - Output path untuk model pickle
- `--cv-splits` - Jumlah cross-validation splits (default: 5)

### Training Output

Jika berhasil, Anda akan melihat:
```
[INFO] Loading dataset: data/dataset/modsec_raw_processed.csv
[INFO] Dataset shape: (142705, 20), Class distribution: {0: 95144, 1: 47561}
[INFO] Running 3-fold cross-validation...
  accuracy     - mean: 0.9986, std: 0.0000
  f1           - mean: 0.9979, std: 0.0000
  precision    - mean: 0.9982, std: 0.0005
  recall       - mean: 0.9976, std: 0.0006
  roc_auc      - mean: 1.0000, std: 0.0000

[INFO] Model saved to models/trained_models/modsec_xgb.pkl
[INFO] Metrics saved to models/trained_models/modsec_metrics.json
```

### Verify Model Generated

```bash
ls -lh models/trained_models/modsec_xgb.pkl
```

**Expected output:**
```
-rw-r--r--  1 user  staff  594K  Apr  9 13:34 modsec_xgb.pkl
```

---

## Running Inference

Setelah model berhasil di-generate, Anda bisa menjalankan inference.

### Method 1: Batch Inference (Cmodsec_xgb.pkl \
  --input data/dataset/modsec_raw_processed.csv \
  --output data/processed/predictions.csv \
  --threshold 0.5
```

**Parameters:**
- `--model` - Path ke model pickleprocessed.csv \
  --output data/processed/predictions.csv \
  --threshold 0.5
```

**Parameters:**
- `--model` - Path ke model (.pkl)
- `--input` - Path ke input file (CSV dengan raw logs)
- `--output` - Path tempat menyimpan hasil prediksi
- `--threshold` - Confidence threshold (default: 0.5)

**Output example:**
```json
{
  "total_logs": 142705,
  "predicted_attack": 47561,
  "predicted_normal": 95144,
  "output_path": "data/processed/predictions.csv"
}
```

### Method 2: Single Request Inference (Python script)

Untuk testing single request:

```python
import sys
from pathlib import Path
import pandas as pd

# Setup path
PROJECT_ROOT = Path(__file__).resolve().parents[0]
sys.path.insert(0, str(PROJECT_ROmodsec_xgb

from src.preprocessing.tabular_features import build_tabular_features
import pickle

# Load model
with open("models/trained_models/tabular_xgboost.pkl", 'rb') as f:
    model = pickle.load(f)

# Sample request
request = {
    "method": "GET",
    "uri": "/index.php/journal/article/view/1024",
    "status": 200,
    "user_agent": "Mozilla/5.0..."
}

# Predict
df = pd.DataFrame([request])
X = build_tabular_features(df)
prediction = model.predict(X)[0]
probability = model.predict_proba(X)[0, 1]

print(f"Is Attack: {prediction}")
print(f"Probability: {probability:.4f}")
```

### Method 3: Quick Test

Untuk quick validation menggunakan test data:

```bash
python scripts/test_model.py
```

atau

```bash
python scripts/quick_test.py
```

---

## Model Information

| Property | Value |
|----------|-------|
| **Algorithm** | XGBoost Classifier |
| **Pipeline** | OneHotEncoder + TF-IDF + XGBoost |
| **Training Data** | 142,705 ModSecurity logs |
| **Training Method** | Stratified K-Fold (3 splits) |
| **Total Features** | 14 engineered features |
| **Model Size** | ~937 KB |
| **Accuracy** | 94.56% |
| **F1-Score** | 92.13% |
| **ROC-AUC** | 97.87% |
| **Training Time** | ~5-10 minutes (first run) |

### Model Performance by Class

```
Class Distribution:
- Normal (0): 95,144 samples (66.67%)
- Attack (1): 47,561 samples (33.33%)

Cross-Validation Results (3-Fold):
Fold 1: Accuracy=94.56%, F1=92.13%, ROC-AUC=97.87%
Fold 2: Accuracy=94.45%, F1=92.01%, ROC-AUC=97.78%
Fold 3: Accuracy=94.64%, F1=92.25%, ROC-AUC=97.96%

Average: Accuracy=94.55%, F1=92.13%, ROC-AUC=97.87%
```

---

## Dataset Information

### Training Dataset: `modsec_raw_processed.csv`

**Size:** 142,705 rows × 19 columns

**Columns:**
```
timestamp, source_ip, method, uri, status, user_agent, severity, 
rule_id, matched_data, msg, is_blocked, label, uri_len, has_sqli, 
has_xss, num_slashes, num_dots, num_special_chars, num_digits
```

**Label Distribution:**
- **Normal (0):** 95,144 samples (66.67%)
- **Attack (1):** 47,561 samples (33.33%)

### Attack Types in Dataset:
- XSS (Cross-Site Scripting)
- SQL Injection
- Path Traversal / LFI
- Command Injection
- RCE (Remote Code Execution)
- Brute Force

---

## Troubleshooting

### Problem: `ModuleNotFoundError: No module named 'sklearn'`
```bash
# Solution:
pip install -r requirements.txt
# or
pip install scikit-learn==1.5.2
```

### Problem: `FileNotFoundError: data/dataset/modsec_raw_processed.csv`
```bash
# Solution: Download dataset or run data preparation
python scripts/prepare_dataset_from_raw.py
# or verify it exists:
ls data/dataset/
```

### Problem: Memory Error during training
```bash
# Solution: Reduce data or increase RAM
# Option 1: Use subset of data
python scripts/run_tabular_xgboost.py --dataset data/dataset/modsec_raw_processed.csv --max-samples 50000

# Option 2: Check system memory
# Windows: Task Manager > Performance
# Linux: free -h
```

### Problem: Model file not found `models/trained_models/tabular_xgboost.pkl`
```bash
# Solution: Generate model first
python scripts/run_tabular_xgboost.py \
  --dataset data/dataset/modsec_raw_processed.csv \
  --output-dir models/trained_models
```

### Problem: sklearn version mismatch warning
```
InconsistentVersionWarning: Trying to unpickle estimator ...
```

**Solution:**
```bash
# Reinstall scikit-learn to match training environment
pip install --force-reinstall scikit-learn==1.5.2
python scripts/run_tabular_xgboost.py --dataset data/dataset/modsec_raw_processed.csv --output-dir models/trained_models
```

### Problem: Virtual environment not activating
```bash
# Windows - Make sure you're in correct directory
.venv\Scripts\activate.bat

# Linux/macOS
source .venv/bin/activate

# Verify activation (should show (.venv) at start of prompt)
```

---

## Next Steps

After successful setup:

1. ✅ **Training Complete?** Run inference tests
   ```bash
   python scripts/test_model.py
   ```

2. ✅ **Want to Deploy?** Check deployment documentation
   - Docker setup (if available)
   - Production configuration

3. ✅ **Want to Improve Model?** 
   - Retrain with new data
   - Adjust hyperparameters in `scripts/run_modsec_training.py`
   - Add new features in `src/preprocessing/tabular_features.py`

4. ✅ **Integration with Backend?**
   - Use `src/inference/predict_modsec.py` as reference
   - Create API wrapper (FastAPI/Flask)
   - Setup Telegram notifications

---

## Additional Resources

- 📖 [README.md](README.md) - Project overview
- 📊 [Algorithm Comparison](docs/algorithm_comparison.md) - Model comparisons
- 🔧 [XGBoost Documentation](https://xgboost.readthedocs.io/)
- 🐍 [Scikit-Learn Guide](https://scikit-learn.org/stable/)
- 🐋 [Docker Setup](https://docker.com/) - For containerization

---

## Questions?

Jika ada pertanyaan atau issue, buat GitHub issue atau hubungi tim development.

**Happy Learning! 🚀**
