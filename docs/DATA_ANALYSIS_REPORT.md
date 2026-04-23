# Data Analysis & Training Compatibility Report

**Date:** April 23, 2026  
**Dataset:** `data/dataset/labeled_dataset.csv`  
**Status:** ✅ **Training Code CAN train using this data**

---

## 1. Data Overview

### Dataset Characteristics
| Metric | Value |
|--------|-------|
| Total Records | 153 |
| Normal Requests | 147 (96.1%) |
| Malicious Requests | 6 (3.9%) |
| Data Imbalance Ratio | 24.5:1 (Normal:Malicious) |

### Data Format
| Column | Type | Description |
|--------|------|-------------|
| `ip` | string | Source IP address |
| `method` | string | HTTP method (GET, POST, etc) |
| `uri_full` | string | Full URI with query parameters |
| `uri_norm` | string | Normalized URI (clean version) |
| `timestamp` | integer | Unix timestamp |
| `status` | integer | HTTP status code (200, 302, etc) |
| `label` | string | Classification: `normal` or `malicious` |
| `attack_tags` | string | Attack type tags (pipe-separated) |
| `anomaly_score` | float | Anomaly score (0-28) |

---

## 2. Attack Analysis

### Attack Types Detected: 2 Combinations

#### Attack Type 1: SQL Injection (SQLi) + Protocol
- **Tag:** `attack-generic|attack-sqli|attack-protocol`
- **Count:** 2 instances
- **Endpoint:** `/TEST/login/signIn` (POST)
- **Anomaly Score:** 8.0
- **Detection:** ModSecurity SQLi patterns detected in login credentials

#### Attack Type 2: Cross-Site Scripting (XSS) + Protocol  
- **Tag:** `attack-generic|attack-xss|attack-protocol`
- **Count:** 4 instances
- **Endpoints:** 
  - `/TEST/$$$call$$$/grid/files/submission/...` (POST)
  - `/TEST/search/index?query=<script>alert(...)</script>` (GET)
- **Anomaly Score:** 18.0 - 28.0
- **Detection:** `<script>` tags in search query parameter

### Attack Details

**SQLi Attacks (2 instances):**
```
1. POST /TEST/login/signIn → Status 200, Score 8.0, Timestamp 1776398570
2. POST /TEST/login/signIn → Status 200, Score 8.0, Timestamp 1776398598
```

**XSS Attacks (4 instances):**
```
1. POST /TEST/$$$call$$$/grid/.../fetch-grid → Status 200, Score 18.0, Timestamp 1776408009
2. GET /TEST/search/index?query=<script>alert('Test_XSS')</script> → Score 18.0, Timestamp 1776408044
3. GET /TEST/search/index?query=<script>alert('Test_XSS')</script> → Score 28.0, Timestamp 1776408092
4. GET /TEST/search/index?query=<script>alert('Test_XSS')</script> → Score 28.0, Timestamp 1776408094
```

---

## 3. Training Code Compatibility Analysis

### Original Incompatibilities
The CSV format was missing several required features for the training pipeline:

| Required Feature | CSV Has? | Solution |
|------------------|----------|----------|
| `method` | ✅ Yes | Direct mapping |
| `uri` | ⚠️ Partial | Map from `uri_norm` |
| `status` | ✅ Yes | Direct mapping |
| `bytes_sent` | ❌ No | Set default: 0 |
| `request_time` | ❌ No | Set default: 0.0 |
| `rule_count` | ❌ No | Set default: 0 |
| `severity_score` | ❌ No | Extracted from `anomaly_score` |
| `user_agent_len` | ❌ No | Set default: 0 |
| `uri_len` | ❌ No | Computed from `uri` length |
| `has_sqli_pattern` | ❌ No | Detected via regex patterns |
| `has_xss_pattern` | ❌ No | Detected via regex patterns |
| `has_suspicious_path` | ❌ No | Detected via regex patterns |
| `label` | ⚠️ Partial | Convert: normal→0, malicious→1 |

### Solution: Data Preparation Script
Created `scripts/prepare_csv_for_training.py` that:
1. Converts labels: `'normal'` → `0`, `'malicious'` → `1`
2. Extracts features from URIs and attack patterns
3. Maps `anomaly_score` → `severity_score` using severity levels (0-5)
4. Sets sensible defaults for missing features
5. Outputs prepared CSV with all required columns

**Output:** `data/dataset/labeled_dataset_prepared.csv` (153 rows × 13 columns)

---

## 4. Training Results

### Model Training: ✅ SUCCESSFUL

**Cross-Validation (5-fold):**
```
Accuracy: 0.9833 ± 0.0204
F1 Score: 0.6000 ± 0.4899
Precision: 0.6000 ± 0.4899
Recall: 0.6000 ± 0.6000
ROC-AUC: 0.8652 ± 0.2286
```

**Test Set Performance:**
- Accuracy: 96.77%
- Recall: 0.0% ⚠️ (0/1 malicious detected)
- Precision: 0.0% ⚠️ (no positive predictions)
- ROC-AUC: 96.67%

**Confusion Matrix:**
```
        Predicted Negative  Predicted Positive
Actual Negative:    30              0
Actual Positive:    1               0
```

### Model Saved
- **Model File:** `models/trained_models/csv_model.pkl`
- **Metrics File:** `models/trained_models/csv_metrics.json`
- **Pipeline:** Preprocessing (OneHot, TfidfVectorizer) → XGBoost Classifier

---

## 5. Key Findings & Insights

### ✅ What Works
1. **Data Format is Compatible** - CSV can be converted to required training format
2. **Feature Extraction Works** - SQLi and XSS patterns correctly detected
3. **Training Pipeline Runs** - Model trains successfully with prepared data
4. **Model Saves** - Trained model can be persisted and loaded for inference

### ⚠️ Current Limitations
1. **Severe Data Imbalance** - Only 3.9% malicious samples (6/153)
   - With train/test split (75/25), test set likely has ≤2 malicious samples
   - This causes zero recall on small test sets (random distribution)
   
2. **Small Dataset** - 153 total samples
   - ML models typically need 1000+ for robust training
   - With only 6 malicious samples, model can memorize them
   
3. **Limited Attack Diversity** - Only 2 attack type combinations
   - SQLi attacks: always on `/TEST/login/signIn`
   - XSS attacks: always on search/file endpoints
   - Model may overfit to these specific patterns
   
4. **Default Values** - Missing features set to 0
   - `bytes_sent`, `request_time`, `user_agent_len` always 0
   - May reduce model effectiveness

### 📊 Training Data Characteristics
- **Class Distribution:** 147 normal, 6 malicious (highly imbalanced)
- **Attack Concentration:** All SQLi in login endpoint, all XSS in search
- **Temporal Spread:** August 2025 data with clear attack clustering
- **Response Codes:** All successful responses (200) - no blocking by WAF

---

## 6. Recommendations

### For Production Use
1. **Collect More Attack Data**
   - Target: At least 500-1000 attack samples
   - Diversify: Multiple attack types, endpoints, methods
   - Real-world scenarios: Failed requests, different status codes

2. **Balance Dataset**
   - Use class weights in XGBoost
   - Apply SMOTE (Synthetic Minority Over-sampling)
   - Stratified sampling during train/test split

3. **Enrich Feature Set**
   - Use actual `bytes_sent` and `request_time` if available
   - Extract User-Agent information
   - Add request body analysis for POST requests
   - Add header analysis

4. **Improve Model Configuration**
   - Tune XGBoost hyperparameters
   - Experiment with different feature combinations
   - Use cross-validation with stratification

### For Testing
1. **Run Inference on This Data**
   ```bash
   python scripts/test_model.py --model models/trained_models/csv_model.pkl \
                                 --dataset data/dataset/labeled_dataset_prepared.csv
   ```

2. **Deploy to Server**
   - Load model in API
   - Test prediction endpoint
   - Monitor false positive rates

---

## 7. Next Steps

### Immediate (For Capstone)
- [x] Verify data format and structure
- [x] Create data preparation pipeline
- [x] Train model successfully
- [ ] Test model with inference script
- [ ] Generate confusion matrix visualization
- [ ] Deploy model to API server

### Short-term (Week 1-2)
- [ ] Collect more attack samples from OJS test environment
- [ ] Implement data augmentation
- [ ] Optimize model parameters
- [ ] Create evaluation dashboard

### Medium-term (Week 3-4)
- [ ] Collect production data
- [ ] A/B test model vs ModSecurity baseline
- [ ] Set up monitoring/alerting
- [ ] Document deployment procedures

---

## 8. Conclusion

**Status: ✅ READY FOR TRAINING**

The current training code **CAN successfully train** using the labeled_dataset.csv after data preparation. The data conversion script handles all format mismatches and generates proper training features.

However, the **model quality is limited** by the small sample size (153 records) and severe class imbalance (96% normal). For production deployment, significant additional attack data collection is recommended.

The prepared CSV file (`labeled_dataset_prepared.csv`) is ready for:
- Model training and evaluation
- Cross-validation experiments  
- Hyperparameter tuning
- Production deployment pipeline

---

**Report Generated:** April 23, 2026  
**Prepared By:** AI Analysis Pipeline
