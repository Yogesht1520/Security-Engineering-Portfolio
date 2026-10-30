#!/usr/bin/env python3
"""
test_geoip_cache.py — Unit Tests for GeoIP Bounded LRU, Thread-Safe TTL Cache
"""

import sys
import time
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from incident_management.enrichment.geoip import GeoIPCache

def test_bounded_lru_and_ttl():
    print("=" * 65)
    print("      GeoIP Cache Bounded LRU, Thread Safety & TTL Suite      ")
    print("=" * 65)

    # 1. Bounded Size (LRU eviction)
    cache = GeoIPCache(max_size=3, ttl_seconds=5)
    cache.set("1.1.1.1", {"country": "A"})
    cache.set("2.2.2.2", {"country": "B"})
    cache.set("3.3.3.3", {"country": "C"})
    assert len(cache) == 3, f"Expected 3 entries, got {len(cache)}"

    # Access 1.1.1.1 so 2.2.2.2 becomes the oldest LRU
    val = cache.get("1.1.1.1")
    assert val == {"country": "A"}

    # Add 4th entry -> 2.2.2.2 should be evicted
    cache.set("4.4.4.4", {"country": "D"})
    assert len(cache) == 3
    assert cache.get("2.2.2.2") is None, "Expected 2.2.2.2 to be evicted via LRU policy"
    assert cache.get("1.1.1.1") == {"country": "A"}
    assert cache.get("3.3.3.3") == {"country": "C"}
    assert cache.get("4.4.4.4") == {"country": "D"}
    print("  [✓] Bounded capacity (max_size=3) and LRU eviction PASSED.")

    # 2. TTL Expiry
    short_cache = GeoIPCache(max_size=10, ttl_seconds=1)
    short_cache.set("10.0.0.1", {"status": "valid"})
    assert short_cache.get("10.0.0.1") == {"status": "valid"}
    time.sleep(1.2)
    assert short_cache.get("10.0.0.1") is None, "Expected entry to be expired after TTL"
    print("  [✓] TTL expiration (ttl_seconds=1) PASSED.")

    # 3. Thread Safety under Concurrent Reads & Writes
    concurrent_cache = GeoIPCache(max_size=50, ttl_seconds=10)
    errors = []

    def worker(worker_id):
        try:
            for i in range(50):
                ip = f"192.168.1.{i}"
                concurrent_cache.set(ip, {"worker": worker_id, "i": i})
                val = concurrent_cache.get(ip)
                if val is not None:
                    assert "worker" in val
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Concurrent thread errors detected: {errors}"
    print(f"  [✓] Thread-safe concurrent execution (5 threads, 250 ops) PASSED.")
    print("=" * 65)
    print("[+] All GeoIP cache assertions PASSED.")
    print("=" * 65)

if __name__ == "__main__":
    test_bounded_lru_and_ttl()

