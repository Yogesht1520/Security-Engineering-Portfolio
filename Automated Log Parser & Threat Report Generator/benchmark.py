"""Benchmark throughput for parser and detection engine."""
import time
from pathlib import Path
from analyzer.parser import LogParser
from analyzer.detectors import DetectionEngine
from analyzer.models import ParserStats

def run_benchmark(num_lines: int = 50000):
    temp_log = Path("benchmark_temp.log")
    sample_line = (
        '192.168.1.1 - - [24/Sep/2026:12:00:00 +0000] "GET /products/view?item=123 HTTP/1.1" 200 1450 "-" "Mozilla/5.0"\n'
    )
    
    with open(temp_log, "w", encoding="utf-8") as f:
        for _ in range(num_lines):
            f.write(sample_line)
            
    parser = LogParser()
    engine = DetectionEngine()
    stats = ParserStats()
    
    t0 = time.perf_counter()
    entries = parser.parse_stream(temp_log, stats=stats)
    findings = engine.process_stream(entries)
    elapsed = time.perf_counter() - t0
    
    temp_log.unlink()
    rate = num_lines / elapsed
    print(f"RESULT: Processed {num_lines:,} lines in {elapsed:.3f}s -> {rate:,.0f} lines/sec on single core")

if __name__ == "__main__":
    run_benchmark(50000)
