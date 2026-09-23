"""Streaming file readers for large web access log files."""
import gzip
from pathlib import Path
from typing import Generator, Tuple, Union


def stream_lines(
    file_path: Union[str, Path],
    encoding: str = "utf-8",
    chunk_size: int = 65536
) -> Generator[Tuple[int, str], None, None]:
    """
    Stream a log file line by line without loading the entire file into memory.
    Supports both plaintext (.log, .txt, etc.) and gzip-compressed (.gz) files.

    Yields:
        Tuple[int, str]: (1-indexed line_number, raw_line_string_without_trailing_newline)
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    is_gz = path.suffix.lower() == ".gz"

    if is_gz:
        open_fn = lambda: gzip.open(path, mode="rt", encoding=encoding, errors="replace")
    else:
        open_fn = lambda: open(path, mode="r", encoding=encoding, errors="replace", buffering=chunk_size)

    with open_fn() as file_obj:
        for line_num, line in enumerate(file_obj, start=1):
            yield line_num, line.rstrip("\r\n")
