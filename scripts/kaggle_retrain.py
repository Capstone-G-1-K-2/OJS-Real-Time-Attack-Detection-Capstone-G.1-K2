from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.backup_manager import ModelBackupManager


class KaggleRetrainer:
    STATUS_OK = "complete"
    STATUS_ERR = "error"

    def __init__(
        self,
        raw_log: Path,
        kaggle_user: str,
        kernel_slug: str = "modsec-automated-training",
        data_slug: str = "modsec-raw-logs",
        min_roc_auc: float = 0.85,
        optuna_trials: int = 25,
        keep_backups: int = 5,
        poll_interval: int = 60,
        max_poll_minutes: int = 180,
        post_upload_delay: int = 60,
        push_max_retries: int = 5,
        push_retry_delay: int = 30,
        code_slug: str = "modsec-code",
    ):
        self.raw_log = Path(raw_log)
        self.kaggle_user = kaggle_user
        self.kernel_slug = kernel_slug
        self.data_slug = data_slug
        self.min_roc_auc = min_roc_auc
        self.optuna_trials = optuna_trials
        self.keep_backups = keep_backups
        self.poll_interval = poll_interval
        self.max_poll_minutes = max_poll_minutes
        self.post_upload_delay = post_upload_delay
        self.push_max_retries = push_max_retries
        self.push_retry_delay = push_retry_delay
        self.code_slug = code_slug 

        # Paths
        self.dataset_csv = PROJECT_ROOT / "data/dataset/modsec_raw_json_v2.csv"
        self.model_file = PROJECT_ROOT / "models/trained_models/modsec_xgb.pkl"
        self.metrics_file = PROJECT_ROOT / "models/trained_models/modsec_metrics.json"
        self.backup_dir = PROJECT_ROOT / "models/backup"
        self.log_dir = PROJECT_ROOT / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir = Path(tempfile.mkdtemp(prefix="kaggle_retrain_"))

        # Kernel dir
        self.kernel_dir = PROJECT_ROOT / "kaggle/training_kernel"

        self.logger = self._setup_logger()
        self.backup_mgr = ModelBackupManager(self.model_file, self.backup_dir)

    # ──────────────────────────────────────────────────────────────
    # Logger
    # ──────────────────────────────────────────────────────────────

    def _setup_logger(self) -> logging.Logger:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.log_dir / f"retrain_{ts}.log"
        logger = logging.getLogger(f"retrain_{ts}")
        logger.setLevel(logging.INFO)
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)

        # StreamHandler dengan encoding utf-8 + replace agar tidak crash di Windows
        import io
        utf8_stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
        )
        sh = logging.StreamHandler(utf8_stdout)
        sh.setFormatter(fmt)

        logger.addHandler(fh)
        logger.addHandler(sh)
        return logger

    # ──────────────────────────────────────────────────────────────
    # Helper run subprocess
    # ──────────────────────────────────────────────────────────────

    def _run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        self.logger.info(f"CMD: {' '.join(cmd)}")
        res = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            cwd=str(PROJECT_ROOT),
        )
        if res.stdout:
            self.logger.info(res.stdout.strip())
        if res.stderr:
            self.logger.warning(res.stderr.strip())
        if check and res.returncode != 0:
            raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{res.stderr}")
        return res

    # ──────────────────────────────────────────────────────────────
    # STEP 1 – Prepare dataset
    # ──────────────────────────────────────────────────────────────

    def prepare(self) -> Path:
        self.logger.info("=" * 60)
        self.logger.info("STEP 1: Prepare dataset dari raw JSON")
        self.logger.info("=" * 60)

        if not self.raw_log.exists():
            raise FileNotFoundError(f"Raw log tidak ada: {self.raw_log}")

        script = PROJECT_ROOT / "scripts/prepare_dataset_from_raw_json_v2.py"
        if not script.exists():
            raise FileNotFoundError(f"Script prepare tidak ditemukan: {script}")

        self.dataset_csv.parent.mkdir(parents=True, exist_ok=True)
        self._run([
            sys.executable, str(script),
            "--input", str(self.raw_log),
            "--output", str(self.dataset_csv),
        ])

        if not self.dataset_csv.exists():
            raise RuntimeError("Gagal membuat dataset CSV")
        self.logger.info(f"[OK] Dataset ready: {self.dataset_csv}")
        return self.dataset_csv

    # ──────────────────────────────────────────────────────────────
    # STEP 2 – Upload dataset
    # ──────────────────────────────────────────────────────────────

    def _write_meta(self, folder: Path, slug: str, title: str):
        meta = {
            "title": title,
            "id": f"{self.kaggle_user}/{slug}",
            "licenses": [{"name": "CC0-1.0"}],
        }
        with open(folder / "dataset-metadata.json", "w") as f:
            json.dump(meta, f, indent=2)

    def _dataset_exists(self, slug: str) -> bool:
        """Cek apakah dataset sudah ada di Kaggle milik user ini."""
        res = subprocess.run(
            ["kaggle", "datasets", "list", "--user", self.kaggle_user, "--search", slug],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        return slug.lower() in res.stdout.lower()

    def _upload_dataset(self, folder: Path, slug: str):
        """Upload dataset: version jika sudah ada, create jika belum."""
        full_slug = f"{self.kaggle_user}/{slug}"

        self.logger.info(f"[INFO] Mengecek keberadaan dataset: {full_slug}")
        exists = self._dataset_exists(slug)
        self.logger.info(f"[INFO] Dataset exists: {exists}")

        if exists:
            self.logger.info(f"[INFO] Dataset ada -> update version: {full_slug}")
            res = subprocess.run(
                [
                    "kaggle", "datasets", "version",
                    "-p", str(folder),
                    "-m", f"Auto retrain {datetime.now().isoformat()}",
                    "--dir-mode", "zip",
                ],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            if res.returncode == 0:
                self.logger.info(f"[OK] Dataset version updated: {slug}")
                return
            self.logger.error(f"STDOUT: {res.stdout.strip()}")
            self.logger.error(f"STDERR: {res.stderr.strip()}")
            raise RuntimeError(
                f"Version update gagal (rc={res.returncode}): {res.stderr.strip()}"
            )

        else:
            self.logger.info(f"[INFO] Dataset belum ada -> create baru: {full_slug}")
            res = subprocess.run(
                [
                    "kaggle", "datasets", "create",
                    "-p", str(folder),
                    "--dir-mode", "zip",
                ],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            if res.returncode == 0:
                self.logger.info(f"[OK] Dataset created: {slug}")
                return
            self.logger.error(f"STDOUT: {res.stdout.strip()}")
            self.logger.error(f"STDERR: {res.stderr.strip()}")
            raise RuntimeError(
                f"Create dataset gagal (rc={res.returncode}): {res.stderr.strip()}"
            )

    def upload_data(self):
        self.logger.info("=" * 60)
        self.logger.info("STEP 2: Upload raw log ke Kaggle")
        self.logger.info("=" * 60)

        up = self.temp_dir / "raw_bundle"
        up.mkdir(parents=True, exist_ok=True)

        if not self.raw_log.exists():
            raise FileNotFoundError(f"Raw log tidak ada: {self.raw_log}")

        shutil.copy2(self.raw_log, up / self.raw_log.name)
        self._write_meta(up, self.data_slug, "ModSec Raw Logs")
        self._upload_dataset(up, self.data_slug)  # ← auto create/version

        self.logger.info(
            f"[INFO] Waiting {self.post_upload_delay}s for Kaggle to process dataset..."
        )
        time.sleep(self.post_upload_delay)

    # ──────────────────────────────────────────────────────────────
    # STEP 3 – Push kernel (dengan force-restart jika 409)
    # ──────────────────────────────────────────────────────────────

    def _bundle_code_to_kernel(self):
        """Copy src/, scripts/, config/ ke kernel folder sebelum push."""
        self.logger.info("[INFO] Code akan diambil dari dataset input, skip bundle.")
        pass

    def _update_kernel_meta(self):
        meta_path = self.kernel_dir / "kernel-metadata.json"
        if not meta_path.exists():
            self.logger.warning("[WARN] kernel-metadata.json tidak ditemukan, skip update.")
            return
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)

        meta["dataset_sources"] = [
            f"{self.kaggle_user}/{self.data_slug}",
            f"{self.kaggle_user}/{self.code_slug}",   # ← tambah ini
        ]
        meta["id"] = f"{self.kaggle_user}/{self.kernel_slug}"

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        self.logger.info(f"[OK] kernel-metadata.json updated: {meta}")

    def _try_push_kernel(self) -> subprocess.CompletedProcess:
        """Jalankan kaggle kernels push, return hasil tanpa raise."""
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"           # ← paksa kaggle CLI pakai UTF-8
        env["PYTHONIOENCODING"] = "utf-8"

        return subprocess.run(
            ["kaggle", "kernels", "push", "-p", str(self.kernel_dir)],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            env=env,
        )

    def push_kernel(self):
        self.logger.info("=" * 60)
        self.logger.info("STEP 3: Push training kernel")
        self.logger.info("=" * 60)

        self._bundle_code_to_kernel()
        self._update_kernel_meta()

        # ── Retry loop: paksa push, ulangi jika 409 (kernel masih running) ──
        for attempt in range(1, self.push_max_retries + 1):
            self.logger.info(f"[INFO] Push attempt {attempt}/{self.push_max_retries}...")
            res = self._try_push_kernel()

            stdout = res.stdout.strip()
            stderr = res.stderr.strip()

            if res.returncode == 0:
                self.logger.info(stdout)
                self.logger.info(f"[OK] Kernel pushed: {self.kaggle_user}/{self.kernel_slug}")
                return

            # 409 = kernel lama masih running/queued -> tunggu lalu retry
            if "409" in stderr or "Conflict" in stderr:
                self.logger.warning(
                    f"[WARN] 409 Conflict: kernel lama masih aktif. "
                    f"Tunggu {self.push_retry_delay}s lalu retry... "
                    f"(attempt {attempt}/{self.push_max_retries})"
                )
                self.logger.warning(f"Detail: {stderr}")
                if attempt < self.push_max_retries:
                    time.sleep(self.push_retry_delay)
                    continue

            # Error lain (bukan 409) -> langsung gagal
            self.logger.error(f"STDOUT: {stdout}")
            self.logger.error(f"STDERR: {stderr}")
            raise RuntimeError(
                f"Kernel push gagal setelah {attempt} attempt(s) "
                f"(rc={res.returncode}): {stderr}"
            )

        raise RuntimeError(
            f"Kernel push gagal: kernel lama masih 409 Conflict setelah "
            f"{self.push_max_retries} x {self.push_retry_delay}s retry. "
            "Tunggu kernel lama selesai di Kaggle, lalu jalankan ulang script."
        )

    # ──────────────────────────────────────────────────────────────
    # STEP 4 – Poll status
    # ──────────────────────────────────────────────────────────────

    def _parse_status(self, text: str) -> str:
        """Parse status dari output kaggle CLI."""
        import re
        text_lower = text.lower()

        if "complete" in text_lower:
            return "complete"
        if "error" in text_lower or "failed" in text_lower:
            return "error"
        if "running" in text_lower:
            return "running"
        if "queued" in text_lower or "pending" in text_lower:
            return "queued"

        lines = text.strip().splitlines()
        for line in reversed(lines):
            m = re.search(r"(running|complete|error|queued)", line.lower())
            if m:
                return m.group(1)

        return "unknown"

    def poll(self) -> str:
        self.logger.info("=" * 60)
        self.logger.info("STEP 4: Poll kernel status")
        self.logger.info("=" * 60)

        slug = f"{self.kaggle_user}/{self.kernel_slug}"
        start = time.time()
        max_sec = self.max_poll_minutes * 60

        while True:
            elapsed = time.time() - start
            if elapsed > max_sec:
                raise TimeoutError(f"Timeout polling {self.max_poll_minutes} menit")

            res = subprocess.run(
                ["kaggle", "kernels", "status", slug],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
            )
            out = res.stdout + res.stderr
            status = self._parse_status(out)

            if status == "unknown":
                self.logger.warning(f"Raw status output:\n{out.strip()}")

            self.logger.info(f"Status: {status} | elapsed: {int(elapsed)}s")

            if status == self.STATUS_OK:
                self.logger.info("[OK] Kernel selesai")
                return status
            if status == self.STATUS_ERR:
                raise RuntimeError(f"Kernel error:\n{out}")

            time.sleep(self.poll_interval)

    # ──────────────────────────────────────────────────────────────
    # STEP 5 – Download output
    # ──────────────────────────────────────────────────────────────

    def download(self) -> Path:
        self.logger.info("=" * 60)
        self.logger.info("STEP 5: Download output kernel")
        self.logger.info("=" * 60)

        slug = f"{self.kaggle_user}/{self.kernel_slug}"
        out_dir = self.temp_dir / "kernel_output"
        out_dir.mkdir(parents=True, exist_ok=True)

        # ── FIX: subprocess langsung, check=False ───────────────────
        self.logger.info(f"CMD: kaggle kernels output {slug} -p {out_dir}")
        res = subprocess.run(
            ["kaggle", "kernels", "output", slug, "-p", str(out_dir)],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            cwd=str(PROJECT_ROOT),
        )
        if res.stdout:
            self.logger.info(res.stdout.strip())
        if res.stderr:
            self.logger.warning(res.stderr.strip())

        # ── Validasi berdasarkan file, bukan return code ────────────
        model = out_dir / "modsec_xgb.pkl"
        metrics = out_dir / "modsec_metrics.json"
        if not model.exists() or not metrics.exists():
            raise FileNotFoundError(
                "Output model/metrics tidak ditemukan di output Kaggle. "
                f"Return code: {res.returncode}"
            )

        if res.returncode != 0:
            self.logger.warning(
                f"[WARN] kaggle CLI exit code {res.returncode} "
                "(biasanya encoding bug di Windows), tapi file lengkap. Melanjutkan..."
            )

        self.logger.info(f"[OK] Downloaded ke {out_dir}")
        return out_dir

    # ──────────────────────────────────────────────────────────────
    # STEP 6 – Validasi & Deploy
    # ──────────────────────────────────────────────────────────────

    def validate_and_deploy(self, out_dir: Path):
        self.logger.info("=" * 60)
        self.logger.info("STEP 6: Validasi & Deploy")
        self.logger.info("=" * 60)

        metrics_path = out_dir / "modsec_metrics.json"
        model_path = out_dir / "modsec_xgb.pkl"

        with open(metrics_path, encoding="utf-8") as f:
            metrics = json.load(f)

        test = metrics.get("test_metrics", {})
        roc = test.get("roc_auc", 0.0)
        f1 = test.get("f1", 0.0)
        self.logger.info(f"ROC-AUC: {roc:.4f} | F1: {f1:.4f}")

        if roc < self.min_roc_auc:
            raise RuntimeError(
                f"Kualitas model gagal: ROC-AUC {roc:.4f} < {self.min_roc_auc}. "
                "Deploy dibatalkan, model lama tetap aktif."
            )

        # ── Backup model & metrics dengan timestamp yang sama ─────
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        if self.model_file.exists():
            bpath = self.backup_dir / f"modsec_xgb_{ts}.pkl"
            shutil.copy2(self.model_file, bpath)
            self.logger.info(f"[OK] Backup model lama: {bpath}")

        if self.metrics_file.exists():
            mpath = self.backup_dir / f"modsec_metrics_{ts}.json"
            shutil.copy2(self.metrics_file, mpath)
            self.logger.info(f"[OK] Backup metrics lama: {mpath}")

        # Cleanup backup (hanya model .pkl, metrics .json dibiarkan)
        self.backup_mgr.cleanup(self.keep_backups)

        metric_backups = sorted(
            self.backup_dir.glob("modsec_metrics_*.json"),
            key=lambda p: p.stat().st_mtime
        )
        while len(metric_backups) > self.keep_backups:
            old = metric_backups.pop(0)
            old.unlink()
            self.logger.info(f"[OK] Cleaned old metrics backup: {old}")


        # ── Deploy baru ──────────────────────────────────────────
        self.model_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(model_path, self.model_file)
        shutil.copy2(metrics_path, self.metrics_file)
        self.logger.info(f"[OK] Model baru deploy: {self.model_file}")

        # Smoke test
        import pickle
        with open(self.model_file, "rb") as f:
            pickle.load(f)
        self.logger.info("[OK] Smoke test load model passed")

    # ──────────────────────────────────────────────────────────────
    # Rollback & Cleanup
    # ──────────────────────────────────────────────────────────────

    def rollback(self):
        self.logger.info("ROLLBACK dipicu...")
        ok = self.backup_mgr.rollback()
        self.logger.info("Rollback sukses" if ok else "Rollback gagal: tidak ada backup")

    def cleanup(self):
        self.logger.info("Cleanup temp files")
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            self.logger.info(f"[OK] Temp dir dihapus: {self.temp_dir}")
        # Tidak perlu clean kernel_dir/src, scripts, config
        # karena _bundle_code_to_kernel sudah tidak copy ke sana

    def upload_code(self):
        self.logger.info("=" * 60)
        self.logger.info("STEP 2b: Upload code (src/scripts/config) ke Kaggle")
        self.logger.info("=" * 60)

        bundle = self.temp_dir / "code_bundle"
        bundle.mkdir(parents=True, exist_ok=True)

        for folder in ["src", "scripts", "config"]:
            src = PROJECT_ROOT / folder
            if src.exists():
                shutil.copytree(src, bundle / folder)
                self.logger.info(f"[OK] Bundled {folder}/")

        self._write_meta(bundle, self.code_slug, "ModSec Training Code")
        self._upload_dataset(bundle, self.code_slug)

        self.logger.info(
            f"[INFO] Waiting {self.post_upload_delay}s for code dataset to process..."
        )
        time.sleep(self.post_upload_delay)

    # ──────────────────────────────────────────────────────────────
    # Main pipeline
    # ──────────────────────────────────────────────────────────────

    def run(self):
        try:
            self.prepare()
            self.upload_data()
            self.upload_code() 
            self.push_kernel()
            self.poll()
            out = self.download()
            self.validate_and_deploy(out)
            self.logger.info("=" * 60)
            self.logger.info("RETRAIN SUKSES")
            self.logger.info("=" * 60)
        except Exception:
            self.logger.exception("Pipeline gagal")
            self.rollback()
            raise
        finally:
            self.cleanup()



def main():
    parser = argparse.ArgumentParser(description="Kaggle Auto Retrain")
    parser.add_argument("--raw-log", default="data/raw/audit.log")
    parser.add_argument("--kaggle-user", required=True, help="Username Kaggle")
    parser.add_argument("--kernel-slug", default="modsec-automated-training")
    parser.add_argument("--data-slug", default="modsec-raw-logs")
    parser.add_argument("--min-roc-auc", type=float, default=0.85)
    parser.add_argument("--optuna-trials", type=int, default=25)
    parser.add_argument("--keep-backups", type=int, default=5)
    parser.add_argument("--max-poll-minutes", type=int, default=180)
    parser.add_argument("--post-upload-delay", type=int, default=15,
                        help="Delay (detik) setelah upload dataset sebelum push kernel")
    parser.add_argument("--push-max-retries", type=int, default=5,
                        help="Jumlah retry push kernel jika 409 Conflict")
    parser.add_argument("--push-retry-delay", type=int, default=30,
                        help="Delay (detik) antar retry push kernel")
    parser.add_argument("--dry-run", action="store_true",
                        help="Hanya prepare dataset, tidak upload")
    args = parser.parse_args()

    r = KaggleRetrainer(
        raw_log=args.raw_log,
        kaggle_user=args.kaggle_user,
        kernel_slug=args.kernel_slug,
        data_slug=args.data_slug,
        min_roc_auc=args.min_roc_auc,
        optuna_trials=args.optuna_trials,
        keep_backups=args.keep_backups,
        max_poll_minutes=args.max_poll_minutes,
        post_upload_delay=args.post_upload_delay,
        push_max_retries=args.push_max_retries,
        push_retry_delay=args.push_retry_delay,
    )

    if args.dry_run:
        r.prepare()
        r.logger.info("Dry run selesai.")
        return

    r.run()




if __name__ == "__main__":
    main()