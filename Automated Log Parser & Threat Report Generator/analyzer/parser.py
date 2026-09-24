"""High-performance streaming log parser for Nginx and Apache access logs."""
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Iterable, Optional, Tuple, Union

from .models import LogEntry, ParserStats
from .readers import stream_lines

logger = logging.getLogger(__name__)

# Regular expression for Nginx Combined / Apache Combined log format:
# IP - USER [TIMESTAMP] "METHOD PATH PROTOCOL" STATUS BYTES "REFERRER" "USER_AGENT"
COMBINED_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+'                # Remote host IP / name
    r'(?P<ident>\S+)\s+'             # Identd (usually '-')
    r'(?P<user>\S+)\s+'              # Auth user (usually '-')
    r'\[(?P<timestamp>[^\]]+)\]\s+'  # Timestamp [dd/MMM/yyyy:HH:mm:ss +zzzz]
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+' # Request line
    r'(?P<status>\d{3})\s+'          # HTTP status code
    r'(?P<bytes>\S+)'                # Bytes sent (number or '-')
    r'(?:\s+"(?P<referrer>(?:[^"\\]|\\.)*)")?'  # Referrer
    r'(?:\s+"(?P<user_agent>(?:[^"\\]|\\.)*)")?' # User-Agent
    r'.*$'
)

# Regular expression for Apache Common log format:
COMMON_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\S+)'
    r'.*$'
)


def parse_datetime(ts_str: str) -> Optional[datetime]:
    """
    Parse web server timestamp string (e.g. '24/Sep/2026:01:21:29 +0530') into datetime.
    Returns None if timestamp cannot be reliably parsed.
    """
    if not ts_str:
        return None

    try:
        # Standard Apache/Nginx format
        return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        pass

    # Common fallback formats
    for fmt in (
        "%d/%b/%Y:%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    # Return None so unparseable or corrupt dates are treated as malformed lines
    return None


def parse_request_line(request: str) -> Tuple[str, str, str]:
    """
    Safely split HTTP request line into (method, path, protocol).
    Handles edge cases, scanner junk, and malformed strings gracefully.
    """
    parts = request.split()
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    elif len(parts) == 2:
        return parts[0], parts[1], "HTTP/1.1"
    elif len(parts) == 1 and parts[0] != "-":
        return "UNKNOWN", parts[0], "HTTP/1.0"
    return "UNKNOWN", "-", "HTTP/1.0"


class LogParser:
    """Parser capable of streaming and structured parsing of Nginx and Apache access logs."""

    def __init__(self, log_format: str = "auto"):
        """
        Args:
            log_format: One of 'auto', 'combined', or 'common'.
        """
        self.log_format = log_format.lower()

    def parse_line(self, line: str, line_number: int = 0) -> Optional[LogEntry]:
        """
        Parse a single log line into a LogEntry. Returns None if line is malformed/unparseable.
        """
        if not line or line.isspace():
            return None

        match = None
        if self.log_format in ("auto", "combined"):
            match = COMBINED_LOG_REGEX.match(line)
        if match is None and self.log_format in ("auto", "common"):
            match = COMMON_LOG_REGEX.match(line)

        if not match:
            return None

        data = match.groupdict()
        ip = data.get("ip", "")
        raw_ts = data.get("timestamp", "")
        raw_req = data.get("request", "")
        raw_status = data.get("status", "0")
        raw_bytes = data.get("bytes", "0")
        referrer = data.get("referrer") or "-"
        user_agent = data.get("user_agent") or "-"

        timestamp = parse_datetime(raw_ts)
        if timestamp is None:
            return None

        # Clean escaped quotes in request/referrer/user_agent if present
        raw_req = raw_req.replace('\\"', '"')
        referrer = referrer.replace('\\"', '"')
        user_agent = user_agent.replace('\\"', '"')

        method, path, protocol = parse_request_line(raw_req)

        try:
            status = int(raw_status)
        except ValueError:
            status = 0

        try:
            bytes_sent = int(raw_bytes) if raw_bytes != "-" else 0
        except ValueError:
            bytes_sent = 0

        return LogEntry(
            ip=ip,
            timestamp=timestamp,
            method=method,
            path=path,
            protocol=protocol,
            status=status,
            bytes_sent=bytes_sent,
            referrer=referrer,
            user_agent=user_agent,
            raw=line,
            line_number=line_number,
        )

    def parse_stream(
        self,
        source: Union[str, Path, Iterable[Tuple[int, str]]],
        stats: Optional[ParserStats] = None,
        start_offset: int = 0,
    ) -> Generator[LogEntry, None, None]:
        """
        Generator yielding LogEntry objects from a file path or an iterable of (line_num, line).
        Updates `stats` in-place as parsing progresses.
        """
        if stats is None:
            stats = ParserStats()

        stats.start_time = datetime.now(timezone.utc)
        stats.format_detected = self.log_format

        line_stream: Iterable[Tuple[int, str]]
        if isinstance(source, (str, Path)):
            line_stream = stream_lines(source, start_offset=start_offset)
        else:
            line_stream = source

        for line_num, raw_line in line_stream:
            # Skip completely empty lines without counting them as malformed
            if not raw_line or raw_line.isspace():
                continue

            stats.total_lines += 1
            entry = self.parse_line(raw_line, line_number=line_num)
            if entry is not None:
                stats.parsed_lines += 1
                yield entry
            else:
                stats.malformed_lines += 1
                logger.debug("Skipped malformed line %d: %s", line_num, raw_line[:120])

        stats.end_time = datetime.now(timezone.utc)
