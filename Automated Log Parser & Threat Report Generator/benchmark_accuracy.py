"""Statistical accuracy benchmark measuring Precision, Recall, F1-Score, and Confusion Matrix."""
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyzer.detectors import DetectionEngine
from analyzer.models import LogEntry, ParserStats
from analyzer.parser import LogParser


def generate_accuracy_corpus() -> List[Tuple[str, bool]]:
    """
    Generate labeled dataset: (raw_log_line, is_malicious).
    Returns a balanced dataset of benign and malicious log entries.
    """
    random.seed(1337)
    base_time = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    corpus: List[Tuple[str, bool]] = []

    benign_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    ]

    benign_paths = [
        "/",
        "/index.html",
        "/about-us",
        "/contact-sales",
        "/products/list?category=security&page=2",
        "/search?q=cybersecurity+training",
        "/static/css/styles.min.css",
        "/static/js/app.bundle.js",
        "/assets/images/header-logo.png",
        "/docs/v2/api-reference",
        "/blog/2026/how-we-secured-our-infra",
    ]

    # 1. Generate 500 Benign lines
    for i in range(500):
        dt = base_time + timedelta(seconds=i * 2)
        ts_str = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = f"198.51.100.{(i % 200) + 1}"
        path = random.choice(benign_paths)
        ua = random.choice(benign_agents)
        line = f'{ip} - - [{ts_str}] "GET {path} HTTP/1.1" 200 {random.randint(500, 15000)} "https://google.com/" "{ua}"'
        corpus.append((line, False))

    # 2. Generate 500 Malicious lines across diverse categories
    malicious_templates = [
        # SQL Injection variants
        ("GET", "/products?id=1%20UNION%20SELECT%20null,password,email%20FROM%20users--", 500, "Mozilla/5.0"),
        ("GET", "/search?term=admin'%20OR%20'1'='1", 200, "Mozilla/5.0"),
        ("GET", "/api/item?id=1%20AND%20SLEEP(5)", 500, "Mozilla/5.0"),
        ("GET", "/catalog?id=10%20AND%20(SELECT%20COUNT(*)%20FROM%20information_schema.tables)--", 500, "Mozilla/5.0"),
        ("GET", "/query?data=test';%20DROP%20TABLE%20users--", 500, "Mozilla/5.0"),
        # Path Traversal variants
        ("GET", "/view?file=../../../../etc/passwd", 403, "Mozilla/5.0"),
        ("GET", "/download?path=..%2f..%2f..%2fetc%2fshadow", 403, "Mozilla/5.0"),
        ("GET", "/assets?name=..%252e%252e%252f..%252e%252e%252fwin.ini", 403, "Mozilla/5.0"),
        ("GET", "/read?doc=C:\\Windows\\win.ini", 403, "Mozilla/5.0"),
        ("GET", "/debug?file=/proc/self/environ", 403, "Mozilla/5.0"),
        # Scanner & Recon tools
        ("GET", "/test.php", 404, "sqlmap/1.7.2#stable"),
        ("GET", "/nikto-check.html", 404, "Mozilla/5.00 (Nikto/2.1.6)"),
        ("GET", "/api-fuzz", 404, "Nuclei - Open-source project"),
        ("GET", "/login", 404, "Nmap Scripting Engine"),
        ("GET", "/hidden", 404, "DirBuster-1.0.0-RC1"),
        ("GET", "/secret", 404, "-"),  # Missing UA
    ]

    for i in range(500):
        dt = base_time + timedelta(seconds=i * 2 + 1)
        ts_str = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = f"203.0.113.{(i % 100) + 1}"
        method, path, status, ua = random.choice(malicious_templates)
        line = f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {random.randint(100, 800)} "-" "{ua}"'
        corpus.append((line, True))

    random.shuffle(corpus)
    return corpus


def run_benchmark():
    print("=" * 65)
    print("🎯 Synthetic Corpus Detection Benchmark — Precision / Recall / F1")
    print("=" * 65)
    print("Note: Corpus is generated to match the defined rule signatures.")
    print("This measures classification performance on the synthetic baseline")
    print("corpus — NOT real-world detection rate against novel or evaded input.")
    print()
    print("[*] Generating labeled ground-truth corpus (1,000 total events)...")

    corpus = generate_accuracy_corpus()
    parser = LogParser()
    engine = DetectionEngine()

    tp = 0  # Malicious correctly flagged
    fp = 0  # Benign incorrectly flagged
    tn = 0  # Benign correctly ignored
    fn = 0  # Malicious missed

    t0 = time.perf_counter()
    for raw_line, is_malicious in corpus:
        entry = parser.parse_line(raw_line)
        if entry is None:
            continue

        findings = engine.process_entry(entry)
        has_findings = len(findings) > 0

        if is_malicious and has_findings:
            tp += 1
        elif is_malicious and not has_findings:
            fn += 1
        elif not is_malicious and not has_findings:
            tn += 1
        elif not is_malicious and has_findings:
            fp += 1

    elapsed = time.perf_counter() - t0

    # Calculate metrics
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"[*] Processed {total:,} labeled lines in {elapsed:.3f}s ({total/elapsed:,.0f} lines/sec)\n")

    print("📊 CONFUSION MATRIX:")
    print("┌──────────────────────────┬────────────────────┬────────────────────┐")
    print("│                          │ Predicted POSITIVE │ Predicted NEGATIVE │")
    print("├──────────────────────────┼────────────────────┼────────────────────┤")
    print(f"│ Actual MALICIOUS (500)   │ TP = {tp:<13} │ FN = {fn:<13} │")
    print(f"│ Actual BENIGN (500)      │ FP = {fp:<13} │ TN = {tn:<13} │")
    print("└──────────────────────────┴────────────────────┴────────────────────┘\n")

    print("📈 CLASSIFICATION SCORES (synthetic baseline corpus):")
    print(f"  • Accuracy    : {accuracy * 100:.2f}%  (Correct classifications / total events)")
    print(f"  • Precision   : {precision * 100:.2f}%  (Alerts that are true positives)")
    print(f"  • Recall      : {recall * 100:.2f}%  (Known attacks correctly detected)")
    print(f"  • Specificity : {specificity * 100:.2f}%  (Benign traffic correctly ignored)")
    print(f"  • F1-Score    : {f1 * 100:.2f}%  (Harmonic mean of precision & recall)")
    print("=" * 65)
    print("⚠  Caveat: malicious samples are constructed to match rule signatures.")
    print("   Evasion, encoding variants, and novel payloads are not measured here.")

    assert recall == 1.0, f"Expected 100% recall on known signatures, got {recall}"
    assert precision == 1.0, f"Expected 100% precision on benign traffic, got {precision}"


if __name__ == "__main__":
    run_benchmark()
