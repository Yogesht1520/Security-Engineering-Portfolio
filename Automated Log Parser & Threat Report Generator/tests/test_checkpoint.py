"""Tests for checkpoint state management and incremental log processing."""
from pathlib import Path
from analyzer.checkpoint import CheckpointManager, compute_head_checksum
from analyzer.readers import stream_lines_with_offsets


def test_checkpoint_save_and_load(tmp_path: Path):
    cp_file = tmp_path / "checkpoint.json"
    mgr = CheckpointManager(cp_file)

    log_file = tmp_path / "test.log"
    log_file.write_text("line1\nline2\nline3\n", encoding="utf-8")

    mgr.save(log_file, byte_offset=12, lines_processed=2)

    loaded = mgr.load(log_file)
    assert loaded is not None
    assert loaded.byte_offset == 12
    assert loaded.lines_processed == 2


def test_checkpoint_rotation_detection(tmp_path: Path):
    cp_file = tmp_path / "checkpoint.json"
    mgr = CheckpointManager(cp_file)

    log_file = tmp_path / "app.log"
    log_file.write_text("Initial log content line 1\nInitial line 2\n", encoding="utf-8")

    mgr.save(log_file, byte_offset=30, lines_processed=2)

    # Truncate/rotate file to a smaller size
    log_file.write_text("Rotated line 1\n", encoding="utf-8")

    # Load should detect rotation and return None (resetting to 0)
    loaded = mgr.load(log_file)
    assert loaded is None


def test_stream_lines_with_offsets(tmp_path: Path):
    log_file = tmp_path / "stream.log"
    log_file.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")

    chunks = list(stream_lines_with_offsets(log_file))
    assert len(chunks) == 3
    assert chunks[0][0] == 1
    assert chunks[0][1] == "alpha"
    assert chunks[0][2] > 0

    # Resume from offset of alpha
    resume_offset = chunks[0][2]
    resumed_chunks = list(stream_lines_with_offsets(log_file, start_offset=resume_offset))
    assert len(resumed_chunks) == 2
    assert resumed_chunks[0][1] == "beta"
    assert resumed_chunks[1][1] == "gamma"
