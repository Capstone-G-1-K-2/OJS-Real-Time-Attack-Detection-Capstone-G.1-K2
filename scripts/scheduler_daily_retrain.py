#!/usr/bin/env python3
"""
Scheduler untuk daily retraining.

Script ini berjalan 24/7 dan otomatis trigger retraining setiap hari
pada jam yang ditentukan (default: 02:00 AM).

Alurnya:
1. Script start
2. Schedule: "Setiap hari jam 2 pagi, jalankan daily_retrain.py"
3. Tunggu dalam infinite loop
4. Pada jam 2 pagi, otomatis run retraining
5. Selesai, tunggu hari berikutnya
"""

from __future__ import annotations

import argparse
import logging
import schedule
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [SCHEDULER] - %(message)s",
    handlers=[
        logging.FileHandler("logs/retraining_scheduler.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class RetrainingScheduler:
    """Manage daily retraining schedule."""
    
    def __init__(
        self,
        dataset_path: str,
        output_dir: str = "models/trained_models",
        schedule_time: str = "02:00",
    ):
        """
        Initialize scheduler.
        
        Args:
            dataset_path: Path ke combined dataset (old + new)
            output_dir: Directory untuk save model
            schedule_time: Time untuk trigger retraining (HH:MM format)
                          Default: 02:00 (2 AM)
        """
        self.dataset_path = dataset_path
        self.output_dir = output_dir
        self.schedule_time = schedule_time
        
        logger.info("="*70)
        logger.info("RETRAINING SCHEDULER INITIALIZED")
        logger.info("="*70)
        logger.info(f"Dataset: {self.dataset_path}")
        logger.info(f"Output: {self.output_dir}")
        logger.info(f"Schedule time: Every day at {self.schedule_time} (24-hour format)")
        logger.info(f"Status: WAITING for scheduled time...")
        logger.info("="*70)
    
    def run_retraining(self):
        """Execute retraining script."""
        logger.info("\n" + "🔄 "*35)
        logger.info("TRIGGERED: Starting daily retraining...")
        logger.info("🔄 "*35 + "\n")
        
        try:
            # Build command
            cmd = [
                sys.executable,
                "scripts/daily_retrain.py",
                "--dataset", self.dataset_path,
                "--output-dir", self.output_dir,
            ]
            
            # Run script
            logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Log output
            if result.stdout:
                logger.info("STDOUT:\n" + result.stdout)
            
            if result.returncode == 0:
                logger.info("✓ Retraining completed successfully!")
                logger.info(f"Next scheduled time: Tomorrow at {self.schedule_time}")
            else:
                logger.error("✗ Retraining failed!")
                if result.stderr:
                    logger.error("STDERR:\n" + result.stderr)
        
        except Exception as e:
            logger.error(f"✗ Exception during retraining: {e}")
            import traceback
            traceback.print_exc()
        
        logger.info("\n" + "⏰ "*35)
        logger.info("WAITING for next scheduled time...")
        logger.info("⏰ "*35 + "\n")
    
    def start(self):
        """
        Start scheduler (berjalan forever sampai di-stop).
        
        Workflow:
        1. Schedule task pada waktu yang ditentukan
        2. Loop forever
        3. Setiap detik, check apakah ada task yang harus dijalankan
        4. Kalau ada, run run_retraining()
        5. Tunggu sampai di-Ctrl+C
        """
        # Schedule task
        schedule.every().day.at(self.schedule_time).do(self.run_retraining)
        
        logger.info(f"✓ Scheduled: Daily retraining at {self.schedule_time}\n")
        
        # Infinite loop
        try:
            while True:
                # Check if any task perlu dijalankan
                schedule.run_pending()
                
                # Sleep 60 detik baru check lagi
                # Ini untuk efficiency (gak perlu check setiap millisecond)
                time.sleep(60)
        
        except KeyboardInterrupt:
            logger.info("\n⏹ Scheduler stopped by user (Ctrl+C)")
            logger.info("="*70)
        
        except Exception as e:
            logger.error(f"✗ Scheduler error: {e}")
            import traceback
            traceback.print_exc()


def main():
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Daily retraining scheduler"
    )
    parser.add_argument(
        "--dataset",
        default="data/dataset/modsec_raw_processed_updated.csv",
        help="Path to combined dataset"
    )
    parser.add_argument(
        "--output-dir",
        default="models/trained_models",
        help="Output directory for models"
    )
    parser.add_argument(
        "--time",
        default="02:00",
        help="Schedule time (HH:MM, 24-hour format). Default: 02:00"
    )
    
    args = parser.parse_args()
    
    # Create logs directory
    Path("logs").mkdir(exist_ok=True)
    
    # Validate dataset exists
    if not Path(args.dataset).exists():
        logger.error(f"✗ Dataset not found: {args.dataset}")
        return 1
    
    # Create and start scheduler
    scheduler = RetrainingScheduler(
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        schedule_time=args.time,
    )
    
    scheduler.start()
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
