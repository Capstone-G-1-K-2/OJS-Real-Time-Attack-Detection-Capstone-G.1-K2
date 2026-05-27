"""Model backup dan rollback manager."""
from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path


class ModelBackupManager:
    def __init__(self, model_path: Path | str, backup_dir: Path | str):
        self.model_path = Path(model_path)
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def backup(self) -> Path | None:
        """Backup model aktif dengan timestamp."""
        if not self.model_path.exists():
            return None
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"{self.model_path.stem}_{ts}{self.model_path.suffix}"
        dst = self.backup_dir / name
        shutil.copy2(self.model_path, dst)
        return dst

    def latest_backup(self) -> Path | None:
        pattern = f"{self.model_path.stem}_*{self.model_path.suffix}"
        backups = sorted(self.backup_dir.glob(pattern))
        return backups[-1] if backups else None

    def rollback(self) -> bool:
        """Restore dari backup terakhir."""
        latest = self.latest_backup()
        if not latest:
            return False
        shutil.copy2(latest, self.model_path)
        return True

    def cleanup(self, keep: int = 5) -> int:
        """Hapus backup lama, simpan N terakhir."""
        pattern = f"{self.model_path.stem}_*{self.model_path.suffix}"
        backups = sorted(self.backup_dir.glob(pattern))
        deleted = 0
        for old in backups[:-keep]:
            old.unlink()
            deleted += 1
        return deleted