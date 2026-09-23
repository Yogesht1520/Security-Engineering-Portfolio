"""Synthetic web access log generator with injected ground-truth attack scenarios."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple
import random

# Seed for reproducible synthetic log generation
random.seed(42)

BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
]

BENIGN_PATHS = [
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/products",
    "/products/item-123",
    "/static/css/main.css",
    "/static/js/bundle.js",
    "/assets/images/logo.png",
    "/blog/security-updates",
    "/pricing",
    "/faq",
]

BENIGN_IPS = [
    "198.51.100.12",
    "198.51.100.45",
    "198.51.100.89",
    "203.0.113.10",
    "203.0.113.25",
]


def format_log_line(
    ip: str,
    dt: datetime,
    method: str,
    path: str,
    status: int,
    bytes_sent: int,
    referrer: str,
    user_agent: str,
) -> str:
    """Format fields into Nginx Combined log line format."""
    ts_str = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "{referrer}" "{user_agent}"'


def generate_demo_dataset(base_time: datetime) -> Tuple[List[str], Dict[str, int]]:
    """
    Generate synthetic log lines and return (lines, ground_truth_counts).
    """
    lines: List[str] = []
    current_time = base_time
    ground_truth = {
        "SQL Injection": 0,
        "Path Traversal": 0,
        "Scanner Reconnaissance": 0,
        "Brute-Force Attack": 0,
        "Status-Code Burst Anomaly": 0,
    }

    # Helper to add benign line
    def add_benign():
        nonlocal current_time
        current_time += timedelta(seconds=random.randint(1, 4))
        ip = random.choice(BENIGN_IPS)
        path = random.choice(BENIGN_PATHS)
        ua = random.choice(BENIGN_USER_AGENTS)
        line = format_log_line(
            ip=ip,
            dt=current_time,
            method="GET",
            path=path,
            status=200,
            bytes_sent=random.randint(400, 8500),
            referrer="https://example.com/",
            user_agent=ua,
        )
        lines.append(line)

    # Initial benign traffic
    for _ in range(50):
        add_benign()

    # Scenario 1: SQL Injection Attacks (IP: 185.220.101.5)
    sqli_ip = "185.220.101.5"
    sqli_payloads = [
        "/products?category=books'%20UNION%20SELECT%20null,username,password%20FROM%20users--",
        "/search?q=test'%20OR%20'1'='1",
        "/api/items?id=1%20AND%20SLEEP(5)",
        "/catalog?filter=electronics'%20AND%20(SELECT%20COUNT(*)%20FROM%20information_schema.tables)--",
    ]
    for payload in sqli_payloads:
        current_time += timedelta(seconds=2)
        lines.append(
            format_log_line(
                ip=sqli_ip,
                dt=current_time,
                method="GET",
                path=payload,
                status=500,
                bytes_sent=230,
                referrer="-",
                user_agent=random.choice(BENIGN_USER_AGENTS),
            )
        )
        ground_truth["SQL Injection"] += 1

    # Interspersed benign traffic
    for _ in range(30):
        add_benign()

    # Scenario 2: Path Traversal Attempts (IP: 45.33.32.156)
    traversal_ip = "45.33.32.156"
    traversal_payloads = [
        "/view?file=../../../../etc/passwd",
        "/download?path=..%2f..%2f..%2fetc%2fshadow",
        "/static/img?doc=..%252e%252e%252f..%252e%252e%252fetc%2fpasswd",
        "/read?file=C:\\Windows\\win.ini",
    ]
    for payload in traversal_payloads:
        current_time += timedelta(seconds=2)
        lines.append(
            format_log_line(
                ip=traversal_ip,
                dt=current_time,
                method="GET",
                path=payload,
                status=403,
                bytes_sent=154,
                referrer="-",
                user_agent="Mozilla/5.0",
            )
        )
        ground_truth["Path Traversal"] += 1

    # Interspersed benign traffic
    for _ in range(30):
        add_benign()

    # Scenario 3: Automated Scanner User-Agents (IP: 194.26.29.112)
    scanner_ip = "194.26.29.112"
    scanner_traffic = [
        ("GET", "/index.php", "sqlmap/1.7.2#stable"),
        ("GET", "/test.cgi", "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"),
        ("GET", "/api", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"),
        ("GET", "/login", "Nmap Scripting Engine"),
        ("GET", "/secret", "-"),  # Missing User-Agent
    ]
    for method, path, ua in scanner_traffic:
        current_time += timedelta(seconds=1)
        lines.append(
            format_log_line(
                ip=scanner_ip,
                dt=current_time,
                method=method,
                path=path,
                status=404 if path != "/api" else 200,
                bytes_sent=180,
                referrer="-",
                user_agent=ua,
            )
        )
        ground_truth["Scanner Reconnaissance"] += 1

    # Interspersed benign traffic
    for _ in range(30):
        add_benign()

    # Scenario 4: Authentication Brute Force (IP: 91.240.118.80)
    brute_ip = "91.240.118.80"
    for i in range(15):  # 15 failed attempts in 30 seconds -> triggers 1 brute force alert
        current_time += timedelta(seconds=2)
        lines.append(
            format_log_line(
                ip=brute_ip,
                dt=current_time,
                method="POST",
                path="/wp-login.php",
                status=401,
                bytes_sent=320,
                referrer="https://example.com/wp-login.php",
                user_agent=BENIGN_USER_AGENTS[0],
            )
        )
    ground_truth["Brute-Force Attack"] += 1

    # Interspersed benign traffic
    for _ in range(30):
        add_benign()

    # Scenario 5: Directory Fuzzing Status Code Burst (IP: 103.203.57.18)
    burst_ip = "103.203.57.18"
    for i in range(25):  # 25 rapid 404s in 25 seconds -> triggers 1 status burst alert
        current_time += timedelta(seconds=1)
        lines.append(
            format_log_line(
                ip=burst_ip,
                dt=current_time,
                method="GET",
                path=f"/fuzz/path_{i}_{random.randint(1000, 9999)}",
                status=404,
                bytes_sent=140,
                referrer="-",
                user_agent="CustomFuzzer/1.0",
            )
        )
    ground_truth["Status-Code Burst Anomaly"] += 1

    # Final benign traffic
    for _ in range(50):
        add_benign()

    return lines, ground_truth


def generate_demo_log_file(output_path: Path) -> Dict[str, int]:
    """Generate sample attack demo log file and return ground-truth counts."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    base_time = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)
    lines, ground_truth = generate_demo_dataset(base_time)

    with open(output_path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")

    return ground_truth


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "attack_demo.log"
    gt = generate_demo_log_file(out)
    print(f"Generated {out} with ground truth:")
    for k, v in gt.items():
        print(f"  {k}: {v}")
