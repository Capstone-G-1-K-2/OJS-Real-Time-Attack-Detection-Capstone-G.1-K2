# Quick Start - Pipeline Setup

## ⚡ 5-Minute Setup

### 1. Environment Config

```bash
# Copy template
cp .env.example .env

# Optional: Set Telegram (for alerts)
# Edit .env and add:
# TELEGRAM_TOKEN=your-token
# TELEGRAM_CHAT_ID=your-chat-id
```

### 2. Test Locally (No Server)

```bash
# Test model + pipeline
python scripts/test_api.py
```

Expected output:
- ✓ Model loads
- ✓ Single predictions work
- ✓ Batch predictions work

### 3. Start API Server

```bash
# Run development server
python scripts/run_api.py --reload

# Output:
# Host: 0.0.0.0
# Port: 8000
# Docs: http://0.0.0.0:8000/docs
```

### 4. Test API via Swagger

Open in browser: **http://localhost:8000/docs**

Try endpoints:
- `GET /health` → Check model status
- `POST /predict/single` → Predict 1 log
- `POST /predict/batch` → Predict multiple logs

### 5. Call API from Code

```python
import asyncio
from scripts.api_client import APIClient

async def main():
    client = APIClient()
    
    # Check health
    health = await client.health_check()
    print(health)
    
    # Predict
    result = await client.predict_single(
        method="POST",
        uri="/index.php/article/submit",
    )
    print(f"Prediction: {result['prediction']}")
    print(f"Probability: {result['attack_probability']:.4f}")

asyncio.run(main())
```

---

## 📊 Input Format

All endpoints accept generic HTTP logs (no OJS-specific format needed):

```json
{
  "method": "POST",           // HTTP method
  "uri": "/path?query",       // Request URI
  "status": 200,              // HTTP status (optional)
  "bytes_sent": 1024,         // Response size (optional)
  "request_time": 0.15,       // Request duration (optional)
  "user_agent": "Mozilla/",   // User agent (optional)
  "rule_count": 0,            // ModSec rules matched (optional)
  "severity_score": 0.0       // Rule severity (optional)
}
```

---

## 🔧 What's Implemented

✅ **FastAPI Endpoints**
- `/health` - Server status
- `/predict/single` - Single log prediction
- `/predict/batch` - Batch predictions
- `/alert` - Send Telegram notification

✅ **Feature Engineering**
- Pattern detection (SQLi, XSS, suspicious paths)
- TF-IDF text features
- OneHot encoding for categorical

✅ **Model**
- XGBoost classifier
- Accuracy: 99.84%

✅ **Notifications**
- Telegram Bot alerts
- Severity classification

---

## ❓ FAQ

**Q: Do I need OJS to test?**
A: No! Everything is generic. Test with any HTTP log data.

**Q: How to connect to OJS later?**
A: Create parser in `src/data_ingestion/ojs_log_parser.py` to convert OJS logs to the generic format above.

**Q: How to run in production?**
A: 
```bash
python scripts/run_api.py --workers 4
# or use Docker/K8s
```

**Q: Can I integrate with other tools?**
A: Yes! Standard REST API, easy to integrate with SIEM, dashboards, etc.

---

## 📁 File Structure

```
✓ src/api/              - FastAPI app & models
✓ src/pipeline/         - Prediction orchestrator
✓ src/alerts/           - Telegram notifier
✓ src/preprocessing/    - Feature engineering
✓ models/               - Trained XGBoost model
✓ scripts/              - run_api.py, test_api.py, api_client.py
✓ .env.example          - Config template
✓ PIPELINE_SETUP.md     - Detailed docs
```

---

## 🚀 Next

After OJS integration:
- Implement `src/data_ingestion/ojs_log_parser.py`
- Setup log streaming
- Add database for alert history
- Build dashboard
