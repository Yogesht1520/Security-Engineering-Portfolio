import gzip
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path if executed directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from analyzer.models import LogEntry, ParserStats
from analyzer.readers import stream_lines
from analyzer.parser import LogParser, parse_datetime, parse_request_line


NGINX_COMBINED_SAMPLE = (
    '192.168.1.50 - frank [24/Sep/2026:14:32:10 +0000] "GET /admin/dashboard.php?user=1 HTTP/1.1" '
    '200 4512 "https://example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)

APACHE_COMMON_SAMPLE = (
    '10.0.0.15 - - [10/Oct/2026:13:55:36 -0700] "POST /api/v1/auth HTTP/1.0" 401 532'
)

SQLI_LINE_SAMPLE = (
    '203.0.113.42 - - [24/Sep/2026:15:00:01 +0000] '
    '"GET /products?id=1%27+UNION+SELECT+null,username,password+FROM+users-- HTTP/1.1" '
    '500 120 "-" "sqlmap/1.7.2#stable"'
)


def test_parse_datetime_standard():
    dt = parse_datetime("24/Sep/2026:14:32:10 +0000")
    assert dt.year == 2026
    assert dt.month == 9
    assert dt.day == 24
    assert dt.hour == 14
    assert dt.minute == 32
    assert dt.second == 10
    assert dt.tzinfo is not None


def test_parse_request_line():
    method, path, proto = parse_request_line("GET /index.html HTTP/1.1")
    assert method == "GET"
    assert path == "/index.html"
    assert proto == "HTTP/1.1"

    method2, path2, proto2 = parse_request_line("POST /login")
    assert method2 == "POST"
    assert path2 == "/login"
    assert proto2 == "HTTP/1.1"

    method3, path3, proto3 = parse_request_line("MALFORMED_GARBAGE")
    assert method3 == "UNKNOWN"
    assert path3 == "MALFORMED_GARBAGE"


def test_parse_nginx_combined_line():
    parser = LogParser()
    entry = parser.parse_line(NGINX_COMBINED_SAMPLE, line_number=1)
    assert entry is not None
    assert entry.ip == "192.168.1.50"
    assert entry.method == "GET"
    assert entry.path == "/admin/dashboard.php?user=1"
    assert entry.protocol == "HTTP/1.1"
    assert entry.status == 200
    assert entry.bytes_sent == 4512
    assert entry.referrer == "https://example.com/login"
    assert "Mozilla/5.0" in entry.user_agent
    assert entry.line_number == 1


def test_parse_apache_common_line():
    parser = LogParser(log_format="common")
    entry = parser.parse_line(APACHE_COMMON_SAMPLE, line_number=2)
    assert entry is not None
    assert entry.ip == "10.0.0.15"
    assert entry.method == "POST"
    assert entry.path == "/api/v1/auth"
    assert entry.status == 401
    assert entry.bytes_sent == 532


def test_parse_sqli_line():
    parser = LogParser()
    entry = parser.parse_line(SQLI_LINE_SAMPLE, line_number=3)
    assert entry is not None
    assert entry.ip == "203.0.113.42"
    assert entry.status == 500
    assert "UNION+SELECT" in entry.path
    assert "sqlmap" in entry.user_agent


def test_malformed_lines_graceful_handling():
    parser = LogParser()
    assert parser.parse_line("") is None
    assert parser.parse_line("   \n") is None
    assert parser.parse_line("This is not a log line at all.") is None
    assert parser.parse_line("192.168.1.1 - - [bad-date] broken request") is None


def test_stream_lines_plain_and_gzip(tmp_path: Path):
    plain_file = tmp_path / "test.log"
    plain_file.write_text("line1\nline2\nline3\n", encoding="utf-8")

    lines = list(stream_lines(plain_file))
    assert len(lines) == 3
    assert lines[0] == (1, "line1")
    assert lines[2] == (3, "line3")

    gz_file = tmp_path / "test.log.gz"
    with gzip.open(gz_file, "wt", encoding="utf-8") as f:
        f.write("gzline1\ngzline2\n")

    gz_lines = list(stream_lines(gz_file))
    assert len(gz_lines) == 2
    assert gz_lines[0] == (1, "gzline1")
    assert gz_lines[1] == (2, "gzline2")


def test_parse_stream_with_stats(tmp_path: Path):
    log_file = tmp_path / "mixed.log"
    content = f"{NGINX_COMBINED_SAMPLE}\nCORRUPT LINE\n{SQLI_LINE_SAMPLE}\n\n"
    log_file.write_text(content, encoding="utf-8")

    parser = LogParser()
    stats = ParserStats()
    entries = list(parser.parse_stream(log_file, stats=stats))

    assert len(entries) == 2
    assert stats.total_lines == 3  # 2 valid + 1 corrupt (empty line rstrip doesn't yield if file reader ignores or yields empty)
    assert stats.parsed_lines == 2
    assert stats.malformed_lines == 1
    assert stats.duration_seconds >= 0.0


def test_synthetic_10k_lines_stress(tmp_path: Path):
    """Verify parsing 10,000 synthetic lines with zero crashes and high throughput."""
    sample_file = tmp_path / "stress_10k.log"
    with open(sample_file, "w", encoding="utf-8") as f:
        for i in range(10000):
            if i % 100 == 0:
                f.write("GARBAGE MALFORMED LINE\n")
            else:
                f.write(
                    f'192.168.1.{(i % 254) + 1} - - [24/Sep/2026:12:00:{i % 60:02d} +0000] '
                    f'"GET /item/{i} HTTP/1.1" 200 {100 + (i % 500)} "-" "StressTestBot/1.0"\n'
                )

    parser = LogParser()
    stats = ParserStats()
    entries = list(parser.parse_stream(sample_file, stats=stats))

    assert stats.total_lines == 10000
    assert stats.malformed_lines == 100
    assert stats.parsed_lines == 9900
    assert len(entries) == 9900
    assert stats.lines_per_second > 1000  # Should easily process >1,000 lines/sec in pure Python


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))
