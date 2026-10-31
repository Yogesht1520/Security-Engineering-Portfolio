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

from incident_management.enrichment.geoip import GeoIPCache, SingleFlight, lookup_ip, _GEOIP_CACHE
import io
import json
from unittest.mock import patch

def test_constructor_validation():
    print("[*] Testing GeoIPCache constructor bounds validation...")
    try:
        GeoIPCache(max_size=0, ttl_seconds=10)
        assert False, "Expected ValueError for max_size=0"
    except ValueError:
        pass

    try:
        GeoIPCache(max_size=-5, ttl_seconds=10)
        assert False, "Expected ValueError for negative max_size"
    except ValueError:
        pass

    try:
        GeoIPCache(max_size=10, ttl_seconds=0)
        assert False, "Expected ValueError for ttl_seconds=0"
    except ValueError:
        pass
    print("  [✓] Constructor parameter validation (positive bounds) PASSED.")

def test_cache_immutability_defensive_copy():
    print("[*] Testing cache record immutability (defensive copy)...")
    cache = GeoIPCache(max_size=10, ttl_seconds=60)
    original = {"country": "Switzerland", "city": "Zurich"}
    cache.set("209.99.190.186", original)

    retrieved = cache.get("209.99.190.186")
    assert retrieved == original

    # Attempt to mutate caller's copy
    retrieved["country"] = "MUTATED_COUNTRY"

    second_fetch = cache.get("209.99.190.186")
    assert second_fetch["country"] == "Switzerland", "CRITICAL: Internal cache was mutated by external caller!"
    print("  [✓] Cache record mutation isolation verified: get() returned an independent copy.")

def test_single_flight_timeout():
    print("[*] Testing SingleFlight timeout handling on stalled leader...")
    sf = SingleFlight()
    leader_started = threading.Event()

    def stalled_fetch():
        leader_started.set()
        time.sleep(1.0)
        return {"result": "late"}

    def leader():
        sf.do("stall_key", stalled_fetch)

    t_lead = threading.Thread(target=leader)
    t_lead.start()
    leader_started.wait()

    # Follower with a very short timeout (0.05s) should raise TimeoutError
    try:
        sf.do("stall_key", lambda: {"result": "fallback"}, timeout=0.05)
        assert False, "Expected TimeoutError when leader stalled"
    except TimeoutError:
        print("  [✓] SingleFlight bounded timeout correctly aborted follower after leader stall.")
    finally:
        t_lead.join()

def test_lookup_ip_mocked_http_coalescing():
    print("[*] Testing lookup_ip() integration with mocked urllib.request.urlopen...")
    _GEOIP_CACHE.clear()

    http_call_count = 0
    mock_lock = threading.Lock()

    def fake_urlopen(req, timeout=5):
        nonlocal http_call_count
        with mock_lock:
            http_call_count += 1
        time.sleep(0.1) # Simulate network latency
        fake_response = json.dumps({
            "status": "success",
            "country": "Switzerland",
            "city": "Zurich",
            "regionName": "Zurich",
            "isp": "SKN Subnet",
            "as": "AS402253",
            "query": "209.99.190.186"
        }).encode("utf-8")
        return io.BytesIO(fake_response)

    threads = []
    results = []

    def client_worker():
        res = lookup_ip("209.99.190.186")
        results.append(res)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        for _ in range(10):
            t = threading.Thread(target=client_worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    assert len(results) == 10
    assert all(r.get("country") == "Switzerland" for r in results)
    assert http_call_count == 1, f"CRITICAL: Expected exactly 1 external HTTP request, got {http_call_count}!"
    print(f"  [✓] Integration Mock: 10 concurrent lookup_ip() requests triggered exactly {http_call_count} HTTP call.")

def test_single_flight_coalescing():
    print("[*] Testing Single-Flight duplicate request coalescing...")
    sf = SingleFlight()
    execution_count = 0
    lock = threading.Lock()

    def slow_external_fetch():
        nonlocal execution_count
        with lock:
            execution_count += 1
        time.sleep(0.15)
        return {"data": "unique_network_response"}

    results = []
    threads = []

    def caller():
        res = sf.do("203.0.113.55", slow_external_fetch)
        results.append(res)

    # Launch 10 simultaneous threads requesting the same uncached key
    for _ in range(10):
        t = threading.Thread(target=caller)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(results) == 10, f"Expected 10 results, got {len(results)}"
    assert all(r == {"data": "unique_network_response"} for r in results), "Not all callers received identical payload"
    assert execution_count == 1, f"CRITICAL: Expected exactly 1 network execution, got {execution_count}!"
    print(f"  [✓] Single-Flight coalesced 10 concurrent requests into exactly {execution_count} execution.")

def test_bounded_lru_and_ttl():
    print("=" * 65)
    print("      GeoIP Cache Bounded LRU, Thread Safety & TTL Suite      ")
    print("=" * 65)

    test_constructor_validation()
    test_cache_immutability_defensive_copy()
    test_single_flight_coalescing()
    test_single_flight_timeout()
    test_lookup_ip_mocked_http_coalescing()

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

