"""Incremental scan state and checkpoint management for continuous log tailing."""
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union


@dataclass
class Checkpoint:
    """Represents the persisted byte-offset and metadata of a scanned log file."""
    file_path: str
    byte_offset: int
    lines_processed: int
    file_size: int
    mtime: float
    last_scanned: str
    head_checksum: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Checkpoint":
        return cls(
            file_path=data.get("file_path", ""),
            byte_offset=int(data.get("byte_offset", 0)),
            lines_processed=int(data.get("lines_processed", 0)),
            file_size=int(data.get("file_size", 0)),
            mtime=float(data.get("mtime", 0.0)),
            last_scanned=data.get("last_scanned", ""),
            head_checksum=data.get("head_checksum", ""),
        )


def compute_head_checksum(file_path: Path, sample_bytes: int = 4096) -> str:
    """Compute SHA256 checksum of the initial byte range to identify log rotation."""
    if not file_path.exists() or file_path.stat().st_size == 0:
        return ""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(sample_bytes)
            return hashlib.sha256(chunk).hexdigest()
    except Exception:
        return ""


class CheckpointManager:
    """Manages reading and writing incremental scan checkpoint states."""

    def __init__(self, checkpoint_path: Optional[Union[str, Path]] = None):
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else Path(".scan_checkpoint.json")

    def load(self, target_log_path: Union[str, Path]) -> Optional[Checkpoint]:
        """Load checkpoint matching target log path, verifying no rotation occurred."""
        if not self.checkpoint_path.exists():
            return None

        target_path_str = str(Path(target_log_path).resolve())
        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            entry_data = data.get(target_path_str) or data.get(str(target_log_path))
            if not entry_data:
                return None

            cp = Checkpoint.from_dict(entry_data)
            log_p = Path(target_log_path)
            if not log_p.exists():
                return cp

            stat = log_p.stat()
            # If current file is smaller than previous offset -> truncated/rotated
            if stat.st_size < cp.byte_offset:
                return None

            # If head checksum changed -> log was rewritten/rotated
            current_head = compute_head_checksum(log_p)
            if cp.head_checksum and current_head and cp.head_checksum != current_head:
                return None

            return cp
        except Exception:
            return None

    def save(
        self,
        target_log_path: Union[str, Path],
        byte_offset: int,
        lines_processed: int,
    ) -> Checkpoint:
        """Save updated byte offset and file metadata to checkpoint store."""
        target_path = Path(target_log_path).resolve()
        stat = target_path.stat() if target_path.exists() else None
        file_size = stat.st_size if stat else byte_offset
        mtime = stat.st_mtime if stat else 0.0
        head_cs = compute_head_checksum(target_path) if target_path.exists() else ""

        cp = Checkpoint(
            file_path=str(target_path),
            byte_offset=byte_offset,
            lines_processed=lines_processed,
            file_size=file_size,
            mtime=mtime,
            last_scanned=datetime.now(timezone.utc).isoformat(),
            head_checksum=head_cs,
        )

        # Merge with existing checkpoint dictionary
        all_checkpoints: Dict[str, Any] = {}
        if self.checkpoint_path.exists():
            try:
                with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                    all_checkpoints = json.load(f)
            except Exception:
                all_checkpoints = {}

        all_checkpoints[str(target_path)] = cp.to_dict()

        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.checkpoint_path, "w", encoding="utf-8") as f:
            json.dump(all_checkpoints, f, indent=2)

        return cp
