"""Streaming file readers for large web access log files."""
import gzip
from pathlib import Path
from typing import Generator, Optional, Tuple, Union


def stream_lines(
    file_path: Union[str, Path],
    encoding: str = "utf-8",
    chunk_size: int = 65536,
    start_offset: int = 0,
) -> Generator[Tuple[int, str], None, None]:
    """
    Stream a log file line by line without loading the entire file into memory.
    Supports both plaintext (.log, .txt, etc.) and gzip-compressed (.gz) files.

    Args:
        file_path: Path to log file
        encoding: File character encoding
        chunk_size: Read buffer size in bytes
        start_offset: Byte offset to seek to before reading (plaintext only)

    Yields:
        Tuple[int, str]: (1-indexed line_number, raw_line_string_without_trailing_newline)
    """
    for line_num, line_str, _ in stream_lines_with_offsets(
        file_path=file_path,
        encoding=encoding,
        chunk_size=chunk_size,
        start_offset=start_offset,
    ):
        yield line_num, line_str


def stream_lines_with_offsets(
    file_path: Union[str, Path],
    encoding: str = "utf-8",
    chunk_size: int = 65536,
    start_offset: int = 0,
) -> Generator[Tuple[int, str, int], None, None]:
    """
    Stream a log file yielding (line_number, line_str, end_byte_offset).
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    is_gz = path.suffix.lower() == ".gz"

    if is_gz:
        with gzip.open(path, mode="rt", encoding=encoding, errors="replace") as file_obj:
            line_num = 0
            for line in file_obj:
                line_num += 1
                yield line_num, line.rstrip("\r\n"), 0
    else:
        with open(path, mode="r", encoding=encoding, errors="replace", buffering=chunk_size) as file_obj:
            if start_offset > 0:
                file_obj.seek(start_offset)

            line_num = 0
            while True:
                line = file_obj.readline()
                if not line:
                    break
                line_num += 1
                current_offset = file_obj.tell()
                yield line_num, line.rstrip("\r\n"), current_offset
