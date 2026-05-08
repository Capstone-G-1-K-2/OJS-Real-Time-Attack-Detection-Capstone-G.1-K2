FROM python:3.11-slim

WORKDIR /app

COPY docker-ojs/inference/requirements.txt .
RUN pip install --no-cache-dir \
    numpy==2.4.4 \
    pandas==2.2.3 \
    scikit-learn==1.8.0 \
    xgboost==3.2.0 \
    joblib==1.5.3 \
    watchdog==6.0.0 \
    python-dotenv==1.2.2 \
    python-telegram-bot==22.5 \
    httpx==0.28.1 \
    pymysql==1.1.2

# Copy src module supaya pickle bisa load
COPY src/ /app/src/

COPY docker-ojs/inference/model.pkl .
COPY docker-ojs/inference/main.py .

CMD ["python", "-u", "main.py"]
