🚀 Setup Kaggle API untuk Automated Retrain
Tutorial ini buat Windows (PowerShell).
Lokasi repo kamu: D:\KaggleApi\OJS-Real-Time-Attack-Detection-Capstone-G.1-K2
________________________________________
📁 Struktur File yang Harus Ada
Pastikan di dalam repo sudah ada file-file ini:
OJS-Real-Time-Attack-Detection-Capstone-G.1-K2/
├── .kaggle/
│   └── kaggle.json                 ← API token kamu (udah ada)
├── data/raw/audit.log              ← Data training
├── scripts/
│   ├── prepare_dataset_from_raw_json_v2.py
│   ├── run_modsec_training.py
│   ├── kaggle_retrain.py           ← File orkestrator
│   └── backup_manager.py           ← File backup
├── kaggle/training_kernel/
│   ├── kernel_metadata.json        ← Edit username di sini
│   └── train.py                    ← Script jalan di Kaggle
└── config/model_config.json        ← Config training
________________________________________
🔑 Step 1: Setup Environment Variable (Wajib)
Karena token disimpan di dalam repo (bukan di folder user), kamu harus kasih tahu Kaggle CLI lokasinya.
Cara 1: Set Sementara (PowerShell)
Copy-paste ini ke PowerShell setiap kali buka terminal baru:
$env:KAGGLE_CONFIG_DIR = "D:\KaggleApi\OJS-Real-Time-Attack-Detection-Capstone-G.1-K2\.kaggle"
Cara 2: Set Permanen (Windows)
1.	Buka Start Menu → cari “Edit the system environment variables”
2.	Klik Environment Variables…
3.	Di bagian User variables, klik New…
4.	Variable name: KAGGLE_CONFIG_DIR
5.	Variable value: D:\KaggleApi\OJS-Real-Time-Attack-Detection-Capstone-G.1-K2\.kaggle
6.	Klik OK → OK → Restart PowerShell
________________________________________
🧪 Step 2: Test Kaggle API
Masuk ke folder repo:
cd D:\KaggleApi\OJS-Real-Time-Attack-Detection-Capstone-G.1-K2
Set env var (kalau pakai Cara 1):
$env:KAGGLE_CONFIG_DIR = "D:\KaggleApi\OJS-Real-Time-Attack-Detection-Capstone-G.1-K2\.kaggle"
Test API:
kaggle datasets list
Kalau berhasil: akan muncul daftar dataset populer dari Kaggle.
Kalau error: pastikan kaggle.json ada di folder .kaggle dan env var sudah di-set.
________________________________________
⚙️ Step 3: Edit Metadata Kernel
Buka file: kaggle/training_kernel/kernel_metadata.json
Ganti semua Farhathdyt dengan username Kaggle kamu:
{
  "id": "Farhathdyt/modsec-automated-training",
  "title": "ModSec Automated Training",
  "code_file": "train.py",
  "language": "python",
  "kernel_type": "script",
  "is_private": "true",
  "enable_gpu": "true",
  "enable_internet": "false",
  "dataset_sources": [
    "Farhathdyt/modsec-dataset",
    "Farhathdyt/modsec-code"
  ],
  "competition_sources": [],
  "kernel_sources": []
}
⚠️ Jangan lupa ganti username! Kalau salah, upload akan gagal.
________________________________________
🧪 Step 4: Test Dry Run (Lokal Saja)
Dry run = prepare dataset tanpa sentuh Kaggle.
Gunanya buat pastikan data dan script lokal tidak error.
$env:KAGGLE_CONFIG_DIR = "D:\KaggleApi\OJS-Real-Time-Attack-Detection-Capstone-G.1-K2\.kaggle"
cd D:\KaggleApi\OJS-Real-Time-Attack-Detection-Capstone-G.1-K2

python scripts/kaggle_retrain.py --kaggle-user Farhathdyt --dry-run
Kalau berhasil: - File data/dataset/modsec_raw_json_v2.csv terbuat - Log muncul di logs/retrain_YYYYMMDD_HHMMSS.log - Script berhenti tanpa upload ke Kaggle
________________________________________
🚀 Step 5: Full Run (Upload + Training di Kaggle)
Kalau dry run sudah oke, jalankan full pipeline:
$env:KAGGLE_CONFIG_DIR = "D:\KaggleApi\OJS-Real-Time-Attack-Detection-Capstone-G.1-K2\.kaggle"
cd D:\KaggleApi\OJS-Real-Time-Attack-Detection-Capstone-G.1-K2

python scripts/kaggle_retrain.py --kaggle-user Farhathdyt --min-roc-auc 0.85
Apa yang Terjadi?
Step	Kegiatan	Estimasi Waktu
1	Parse audit.log jadi CSV	3-5 detik
2	Upload dataset ke Kaggle	10-30 detik
3	Upload code ke Kaggle	10-30 detik
4	Push kernel training	5-10 detik
5	Polling: nunggu training selesai	15-30 menit
6	Download model & metrics	10-20 detik
7	Validasi ROC-AUC + Deploy	5 detik
Total: ~20-40 menit.
💡 Laptop harus tetap nyala dan terhubung internet selama Step 5 (polling).
________________________________________
📦 Hasil Akhir
Kalau sukses, kamu akan punya:
models/
├── trained_models/
│   ├── modsec_xgb.pkl              ← Model baru (auto-download)
│   └── modsec_metrics.json         ← Metrics test set
└── backup/
    └── modsec_xgb_20260527_230515.pkl  ← Backup model lama
Log tersimpan di: logs/retrain_YYYYMMDD_HHMMSS.log
________________________________________
🆘 Troubleshooting
Error: Authentication required to call the Kaggle API
Solusi: Env var belum di-set. Pastikan ketik ini dulu:
$env:KAGGLE_CONFIG_DIR = "D:\KaggleApi\OJS-Real-Time-Attack-Detection-Capstone-G.1-K2\.kaggle"
Error: Raw log tidak ada: data\raw\audit.log
Solusi: File datanya beda nama. Kalau nama file-nya audit_organic.log, tambahkan flag:
python scripts/kaggle_retrain.py --kaggle-user Farhathdyt --raw-log data/raw/audit_organic.log
Error: Dataset not found atau Kernel not found
Solusi: Username di kernel_metadata.json belum diganti. Pastikan semua Farhathdyt sudah diganti dengan username Kaggle kamu.
Training lama banget / tidak selesai
Solusi: Kaggle GPU free tier terbatas (~30 jam/minggu). Kalau quota habis, kernel otomatis jalan di CPU (lebih lambat). Coba cek status manual di website Kaggle.
________________________________________
🔄 Setup Cron Job (Nanti di VPS)
Kalau sudah jalan di lokal, nanti di VPS tinggal tambahkan ke cron:
0 2 * * 0 cd /path/ke/repo && /usr/bin/python3 scripts/kaggle_retrain.py --kaggle-user Farhathdyt --min-roc-auc 0.85
(0 2 * * 0 = jam 2 pagi, setiap hari Minggu)
________________________________________
✅ Checklist Sebelum Full Run
•	☐ kaggle datasets list jalan tanpa error
•	☐ kernel_metadata.json sudah diganti username
•	☐ data/raw/audit.log (atau file data) tersedia
•	☐ Dry run berhasil (--dry-run)
•	☐ Token kaggle.json ada di .kaggle/
•	☐ Env var KAGGLE_CONFIG_DIR sudah di-set
________________________________________
Selamat mencoba! Kalau stuck, copy-paste error-nya dari PowerShell.
