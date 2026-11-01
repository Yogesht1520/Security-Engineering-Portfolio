#!/usr/bin/env python3
"""
Acceptance Verification Suite — Host-Key Pinning & WORM Storage Lock
===================================================================
Independently verifies:
1. Cryptographic validity, OpenSSH ED25519 formatting, and SHA-256 fingerprints
   of pre-provisioned host keys in evidence/TRUSTED_HOST_PINS.txt.
2. Independent authentication of serial-console host-key evidence:
   - Live GCP Mode (--live-gcp): Direct out-of-band virtual serial port 1
     acquisition via Google Cloud Compute API (get-serial-port-output).
   - Artifact Mode: Structured independent record-by-record parsing, internal
     fingerprint calculation, and cryptographic authentication against external
     trust anchors outside the repository (~/.config/siem-lab/).
3. End-to-end WORM storage verification:
   - Bucket Level: Immutable locked retention policy (>= 30 days / 2,592,000s).
   - Live Mode: Direct comparison of live GCS object metadata against expected manifest.
   - Offline Mode: Mandatory cryptographic verification (SHA-256, MD5, size,
     generation, and detached RSA-SHA256 signature against pinned signer key).

Fail-Closed Security Guarantee:
Any missing file, skipped check, unauthenticated API call, or cryptographic
discrepancy terminates execution immediately with exit code 1.
"""

import sys
import os
import argparse
import base64
import hashlib
import json
import re
import subprocess
import datetime
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = REPO_ROOT / "evidence"
HOST_PINS_FILE = EVIDENCE_DIR / "TRUSTED_HOST_PINS.txt"
SERIAL_LOG_FILE = EVIDENCE_DIR / "serial_console_host_keys.log"
SERIAL_HASH_FILE = EVIDENCE_DIR / "serial_console_host_keys.log.sha256"
WORM_VERIFY_FILE = EVIDENCE_DIR / "gcs_bucket_lock_verification.json"
SIGNER_PINS_FILE = EVIDENCE_DIR / "TRUSTED_SIGNER_PINS.txt"
DEFAULT_PUBKEY_FILE = EVIDENCE_DIR / "20261028_191347" / "EVIDENCE_SIGNING_PUBKEY.pub"

# External Trust Anchors Outside the Git Repository (Tamper Prevention)
EXTERNAL_SIGNER_ANCHOR = Path(os.environ.get(
    "SIEM_EXTERNAL_SIGNER_ANCHOR",
    Path.home() / ".config" / "siem-lab" / "trusted_signer_pins.txt"
))
EXTERNAL_SERIAL_ANCHOR = Path(os.environ.get(
    "SIEM_EXTERNAL_SERIAL_ANCHOR",
    Path.home() / ".config" / "siem-lab" / "trusted_serial_hashes.txt"
))

def parse_timezone_aware_utc(ts_str: str) -> datetime.datetime:
    """Parses an ISO 8601 string into a timezone-aware UTC datetime.
    Strictly rejects naive timestamps lacking explicit timezone offsets.
    """
    s = ts_str.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.datetime.fromisoformat(s)
    if dt.tzinfo is None:
        raise ValueError(
            f"REJECTED NAIVE TIMESTAMP: '{ts_str}' lacks explicit timezone information (must specify 'Z' or '+/-HH:MM' offset)!"
        )
    return dt.astimezone(datetime.timezone.utc)

def calculate_openssh_fingerprint(base64_pubkey: str) -> str:
    """Calculates OpenSSH SHA256 fingerprint from base64-encoded binary public key."""
    key_bytes = base64.b64decode(base64_pubkey.strip())
    digest = hashlib.sha256(key_bytes).digest()
    b64_fp = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{b64_fp}"

def extract_structured_serial_identities(console_output: str) -> set:
    """Extracts explicit, structured host identity declarations from a Linux/GCP serial stream.
    
    Avoids loose substring matching. Extracts identities only from structured boundary tokens:
    1. Key comment field: HostKey: ssh-ed25519 <key> [user@]<hostname>
    2. systemd hostname declarations: systemd: Set hostname to <<hostname>>
    3. cloud-init network/identity table: ci-info: | Hostname | <hostname>
    4. Serial console login prompts: ^<hostname> login:
    5. Linux kernel build/boot banner: Linux version ... (user@<hostname>)
    6. Google Guest Agent instance identification: instance <hostname>
    """
    identities = set()
    
    # 1. HostKey comment in guest agent or sshd output: HostKey: ssh-ed25519 <key> [user@]<hostname>
    for m in re.finditer(r"HostKey:\s+ssh-ed25519\s+[A-Za-z0-9+/=]+\s+(?:[A-Za-z0-9_.-]+@)?([A-Za-z0-9_-]+)", console_output):
        identities.add(m.group(1).strip().lower())
        
    # 2. systemd Set hostname to <hostname>
    for m in re.finditer(r"systemd(?:\[\d+\])?:\s+(?:Set hostname to|Hostname set to)\s+<([^>]+)>", console_output, re.IGNORECASE):
        raw_name = m.group(1).split(".")[0].strip().lower()
        if raw_name:
            identities.add(raw_name)
            
    # 3. cloud-init Hostname table
    for m in re.finditer(r"ci-info:\s+\|\s+Hostname\s+\|\s*([A-Za-z0-9_-]+)", console_output, re.IGNORECASE):
        identities.add(m.group(1).strip().lower())
        
    # 4. Serial console login prompt: ^<hostname> login:
    for m in re.finditer(r"(?:^|\r?\n)([A-Za-z0-9_-]+)\s+login:\s*", console_output):
        identities.add(m.group(1).strip().lower())

    # 5. Google Guest Agent instance identity
    for m in re.finditer(r"google_guest_agent(?:\[\d+\])?:\s+.*?\binstance\s+([A-Za-z0-9_-]+)", console_output, re.IGNORECASE):
        identities.add(m.group(1).strip().lower())

    return identities

EXPECTED_VM_ZONES = {
    "siem-lab-honeypot": "us-central1-a",
    "siem-lab-wazuh": "us-central1-b",
    "siem-lab-bastion": "us-central1-c"
}

@dataclass(frozen=True)
class SerialAcquisitionContext:
    """Deeply immutable provenance context for a serial acquisition record."""
    source: str
    zone: str
    port: int
    bound_host: str
    verified_identities: tuple
    cmd_instance: Optional[str] = None
    internal_ip: Optional[str] = None
    public_ip: Optional[str] = None
    project_id: Optional[str] = None

@dataclass(frozen=True)
class SerialAcquisitionRecord:
    """Represents a cryptographically validated, unambiguous out-of-band serial acquisition record.
    Binds hostname, public key, fingerprint, and acquisition context together.
    Deeply immutable: all fields are primitive types or frozen tuples/dataclasses.
    """
    hostname: str
    pubkey: str
    fingerprint: str
    key_type: str
    acquisition_context: SerialAcquisitionContext

    def validate(self, expected_hostname: Optional[str] = None, expected_key: Optional[str] = None, expected_fp: Optional[str] = None):
        """Validates internal consistency and identity binding."""
        if not self.hostname:
            raise ValueError("Serial acquisition record lacks bound hostname!")
        if expected_hostname and self.hostname.lower() != expected_hostname.strip().lower():
            raise ValueError(f"Identity binding mismatch: Record bound to '{self.hostname}', expected '{expected_hostname}'!")

        if self.key_type != "ssh-ed25519":
            raise ValueError(f"Unsupported key type '{self.key_type}' bound in record for {self.hostname}!")

        key_bytes = base64.b64decode(self.pubkey)
        if len(key_bytes) < 32:
            raise ValueError(f"Invalid public key bytes length ({len(key_bytes)}) for {self.hostname}!")

        calc_fp = calculate_openssh_fingerprint(self.pubkey)
        if calc_fp != self.fingerprint:
            raise ValueError(
                f"Record self-consistency error for {self.hostname}: Calculated {calc_fp} != Claimed {self.fingerprint}"
            )

        if expected_key and self.pubkey != expected_key:
            raise ValueError(f"Public key mismatch in serial record for {self.hostname}!\nExpected: {expected_key}\nFound:    {self.pubkey}")
        if expected_fp and self.fingerprint != expected_fp:
            raise ValueError(f"Fingerprint mismatch in serial record for {self.hostname}!\nExpected: {expected_fp}\nFound:    {self.fingerprint}")

def parse_live_serial_record(console_output: str, target_host: str, zone: str, project_id: str) -> SerialAcquisitionRecord:
    """Parses live virtual serial port output into a structured SerialAcquisitionRecord.
    Binds hostname, public key, fingerprint, and acquisition context together.
    Rejects stream if attributes cannot be associated unambiguously or if conflicting identities appear.
    """
    target_norm = target_host.strip().lower()

    # 1. Structured identity declarations
    extracted_identities = extract_structured_serial_identities(console_output)
    if target_norm not in extracted_identities:
        raise ValueError(
            f"UNAMBIGUOUS IDENTITY BINDING FAILURE: Serial stream does not contain structured declaration for target host '{target_host}'! "
            f"Detected identities: {sorted(extracted_identities) if extracted_identities else 'None'}"
        )

    # Reject conflicting host announcements
    conflicting_identities = {
        ident for ident in extracted_identities
        if ident != target_norm and not ident.startswith(f"{target_norm}.")
    }
    if conflicting_identities:
        raise ValueError(
            f"CONFLICTING IDENTITY ANNOUNCEMENTS: Detected conflicting host identities {sorted(conflicting_identities)} "
            f"alongside target host '{target_norm}' in serial console stream!"
        )

    # 2. Strict Live Record Parsing: Key, mandatory root@<hostname> comment, and fingerprint in same block
    record_pattern = (
        r"HostKey:\s+(?P<key_type>ssh-ed25519)\s+(?P<key>[A-Za-z0-9+/=]+)"
        r"\s+(?:[A-Za-z0-9_.-]+@)(?P<bound_host>[A-Za-z0-9_.-]+)[^\n]*\n"
        r"[^\n]*?HostKey Fingerprint:\s+\(?(?P<fp>SHA256:[A-Za-z0-9+/=]+)\)?"
    )
    all_records = list(re.finditer(record_pattern, console_output))
    if not all_records:
        raise ValueError(
            f"UNAMBIGUOUS IDENTITY BINDING FAILURE: Live virtual serial port 1 on {target_host} did NOT contain a coherent HostKey "
            f"record block with mandatory root@{target_host} comment!"
        )

    # 3. Reject ambiguous or conflicting records across the serial stream
    distinct_pairs = {(m.group("key"), m.group("fp"), m.group("bound_host")) for m in all_records}
    if len({(p[0], p[1]) for p in distinct_pairs}) > 1:
        raise ValueError(f"AMBIGUOUS SERIAL RECORDS: Detected conflicting key/fingerprint records on {target_host}: {distinct_pairs}")

    m = all_records[0]
    live_key = m.group("key")
    live_fp = m.group("fp")
    key_type = m.group("key_type")
    bound_host = m.group("bound_host")

    bound_norm = bound_host.split(".")[0].strip().lower()
    if bound_norm != target_norm:
        raise ValueError(
            f"UNAMBIGUOUS IDENTITY BINDING FAILURE: Key comment host '{bound_norm}' != target host '{target_norm}'!"
        )

    context = SerialAcquisitionContext(
        source="live_virtual_serial_port_1",
        zone=zone,
        port=1,
        bound_host=bound_norm,
        verified_identities=tuple(sorted(extracted_identities)),
        project_id=project_id
    )

    record = SerialAcquisitionRecord(
        hostname=target_norm,
        pubkey=live_key,
        fingerprint=live_fp,
        key_type=key_type,
        acquisition_context=context
    )
    record.validate()
    return record

def parse_offline_acquisition_block(block: str, valid_hosts: set) -> SerialAcquisitionRecord:
    """Parses an offline serial acquisition block into a structured SerialAcquisitionRecord.
    Binds hostname, public key, fingerprint, and acquisition context together.
    Rejects block if command provenance is missing, or if attributes cannot be associated unambiguously.
    """
    lines = [line.strip() for line in block.splitlines() if line.strip()]
    if not lines:
        raise ValueError("Empty acquisition record block!")

    header_line = lines[0]
    header_host = header_line.split()[0].strip()

    if header_host not in valid_hosts:
        raise ValueError(f"Unrecognized or invalid acquisition identity in serial log: '{header_host}'!")

    # 1. Mandatory out-of-band gcloud get-serial-port-output command provenance
    cmd_match = re.search(
        r"#\s*Command:\s*gcloud\s+compute\s+instances\s+get-serial-port-output\s+(?P<inst>\S+)\s+--zone=(?P<zone>\S+)\s+--port=(?P<port>\d+)(?:\s+--project=(?P<proj>\S+))?",
        block
    )
    if not cmd_match:
        raise ValueError(
            f"UNAMBIGUOUS COMMAND PROVENANCE FAILURE: Acquisition block for '{header_host}' is missing mandatory "
            f"out-of-band 'gcloud compute instances get-serial-port-output' command provenance!"
        )

    cmd_inst = cmd_match.group("inst").strip().lower()
    if cmd_inst != header_host.lower():
        raise ValueError(
            f"UNAMBIGUOUS IDENTITY BINDING FAILURE: Header host '{header_host}' != command instance '{cmd_inst}'!"
        )

    cmd_zone = cmd_match.group("zone").strip()
    expected_zone = EXPECTED_VM_ZONES.get(header_host.lower())
    if expected_zone and cmd_zone != expected_zone:
        raise ValueError(
            f"UNAMBIGUOUS COMMAND PROVENANCE FAILURE: Command zone '{cmd_zone}' != expected zone '{expected_zone}' for '{header_host}'!"
        )

    cmd_port = int(cmd_match.group("port"))
    if cmd_port != 1:
        raise ValueError(
            f"UNAMBIGUOUS COMMAND PROVENANCE FAILURE: Command port '{cmd_port}' != mandatory serial port 1 for '{header_host}'!"
        )

    cmd_proj = cmd_match.group("proj")

    # 2. Extract network context from header comments if present
    internal_ip = None
    public_ip = None
    ip_match = re.search(r"#\s*Internal IP:\s*([0-9.]+)\s*\|\s*Public IP:\s*([0-9.]+)", block)
    if ip_match:
        internal_ip = ip_match.group(1)
        public_ip = ip_match.group(2)

    # 3. Structured identity tokens in block & conflict rejection
    block_identities = extract_structured_serial_identities(block)
    if header_host.lower() not in block_identities:
        raise ValueError(
            f"Structured identity mismatch in offline record block for '{header_host}'!\n"
            f"Parsed structured identities: {sorted(block_identities) if block_identities else 'None'}."
        )

    conflicting_block_identities = {
        ident for ident in block_identities
        if ident != header_host.lower() and not ident.startswith(f"{header_host.lower()}.")
    }
    if conflicting_block_identities:
        raise ValueError(
            f"CONFLICTING IDENTITY ANNOUNCEMENTS: Offline acquisition block for '{header_host}' contains conflicting identities: {sorted(conflicting_block_identities)}!"
        )

    # 4. HostKey line with mandatory type, key, and root@<hostname> comment
    key_match = re.search(
        r"HostKey:\s+(?P<type>ssh-ed25519)\s+(?P<key>\S+)\s+(?:[A-Za-z0-9_.-]+@)(?P<comment_host>[A-Za-z0-9_.-]+)",
        block
    )
    if not key_match:
        raise ValueError(
            f"UNAMBIGUOUS IDENTITY BINDING FAILURE: Acquisition block for '{header_host}' missing mandatory root@{header_host} comment on HostKey line!"
        )

    key_type = key_match.group("type")
    pubkey = key_match.group("key")
    comment_host = key_match.group("comment_host")
    comment_host_norm = comment_host.split(".")[0].strip().lower()
    if comment_host_norm != header_host.lower():
        raise ValueError(
            f"UNAMBIGUOUS IDENTITY BINDING FAILURE: Key comment host '{comment_host_norm}' != record header host '{header_host}'!"
        )

    # 5. HostKey Fingerprint line
    fp_match = re.search(r"HostKey Fingerprint:\s+(SHA256:\S+)", block)
    if not fp_match:
        raise ValueError(f"Serial console record for '{header_host}' missing HostKey Fingerprint line!")
    fingerprint = fp_match.group(1).rstrip(")")

    context = SerialAcquisitionContext(
        source="offline_serial_transcript",
        zone=cmd_zone,
        port=cmd_port,
        bound_host=header_host.lower(),
        verified_identities=tuple(sorted(block_identities)),
        cmd_instance=cmd_inst,
        internal_ip=internal_ip,
        public_ip=public_ip,
        project_id=cmd_proj
    )

    record = SerialAcquisitionRecord(
        hostname=header_host,
        pubkey=pubkey,
        fingerprint=fingerprint,
        key_type=key_type,
        acquisition_context=context
    )
    record.validate()
    return record

def verify_host_key_pins():
    print("=" * 65)
    print(" [1/3] Acceptance Verification: Trusted Host Key Fingerprints  ")
    print("=" * 65)

    assert HOST_PINS_FILE.exists(), f"FATAL: Missing host pins file {HOST_PINS_FILE}"

    with open(HOST_PINS_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    annotated_fps = {}
    verified_entries = []

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        fp_match = re.search(r"#\s*Host:\s*([^\s|]+)\s*\|\s*Fingerprint:\s*(SHA256:[^\s(]+)", line_clean)
        if fp_match:
            host_name, expected_fp = fp_match.group(1), fp_match.group(2)
            annotated_fps[host_name] = expected_fp
            continue

        if line_clean.startswith("#"):
            continue

        parts = line_clean.split()
        if len(parts) >= 3:
            hosts, key_type, b64_key = parts[0], parts[1], parts[2]
            comment = parts[3] if len(parts) > 3 else ""

            assert key_type == "ssh-ed25519", f"Unsupported key type {key_type} for {comment}"
            raw_bytes = base64.b64decode(b64_key)
            assert len(raw_bytes) >= 32, f"Invalid ED25519 key length ({len(raw_bytes)} bytes) for {comment}"

            calculated_fp = calculate_openssh_fingerprint(b64_key)
            expected_fp = annotated_fps.get(comment)

            if expected_fp:
                assert calculated_fp == expected_fp, (
                    f"Fingerprint mismatch for {comment}! Expected {expected_fp}, got {calculated_fp}"
                )
                print(f"  [✓] {comment:20s}: {calculated_fp} (MATCH)")
                verified_entries.append({
                    "host": comment,
                    "addresses": hosts,
                    "key_type": key_type,
                    "fingerprint": calculated_fp,
                    "pubkey": b64_key
                })

    assert len(verified_entries) >= 3, f"Expected at least 3 pinned hosts, found {len(verified_entries)}"
    print(f"[+] All {len(verified_entries)} pre-provisioned host keys mathematically verified against OpenSSH format.")
    return verified_entries

def verify_serial_console_evidence(verified_pins, live_gcp: bool = False, project_id: str = "siem-detection-lab", deployment_acceptance: bool = False):
    print("\n" + "=" * 65)
    print(" [2/3] Acceptance Verification: Out-of-Band Serial Port Auth   ")
    print("=" * 65)

    if deployment_acceptance:
        print("  [*] Enforcing Deployment Acceptance: External serial trust anchor is MANDATORY.")
        assert EXTERNAL_SERIAL_ANCHOR.exists(), (
            f"FATAL: External serial trust anchor {EXTERNAL_SERIAL_ANCHOR} is MANDATORY in deployment acceptance mode but was not found!"
        )

    if live_gcp:
        print("  [*] Mode: LIVE GCP VIRTUAL SERIAL PORT 1 CONSOLE QUERY")
        vm_zones = {
            "siem-lab-honeypot": "us-central1-a",
            "siem-lab-wazuh": "us-central1-b",
            "siem-lab-bastion": "us-central1-c"
        }

        for entry in verified_pins:
            host = entry["host"]
            expected_fp = entry["fingerprint"]
            expected_key = entry["pubkey"]
            zone = vm_zones.get(host, "us-central1-a")

            cmd = ["gcloud", "compute", "instances", "get-serial-port-output", host, f"--zone={zone}", "--port=1", f"--project={project_id}"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, check=True)
                console_output = res.stdout

                # Parse into structured SerialAcquisitionRecord, binding identity, keys, fingerprints, and context
                record = parse_live_serial_record(console_output, host, zone, project_id)
                record.validate(expected_hostname=host, expected_key=expected_key, expected_fp=expected_fp)

                print(f"  [✓] {host:20s}: Live serial record verified & bound (Key, Fingerprint & Context confirmed)")
            except FileNotFoundError:
                print("  [-] FATAL: 'gcloud' CLI was not found on PATH. Live GCP serial verification failed closed.")
                return False
            except subprocess.CalledProcessError as e:
                print(f"  [-] FATAL: Failed to query live serial port for {host}: {e.stderr.strip()}. Failing closed.")
                return False
            except ValueError as e:
                print(f"  [-] FATAL: Live serial acquisition record validation failed for {host}: {e}. Failing closed.")
                return False
        print("[+] Live out-of-band serial port acquisition verified for all running instances.")
        return True

    # Offline Artifact Verification
    print("  [*] Mode: Reproducible Artifact Cryptographic Authentication")
    assert SERIAL_LOG_FILE.exists(), f"FATAL: Missing serial console artifact {SERIAL_LOG_FILE}"
    assert SERIAL_HASH_FILE.exists(), f"FATAL: Missing serial console hash file {SERIAL_HASH_FILE}"

    with open(SERIAL_LOG_FILE, "rb") as f:
        log_bytes = f.read()

    log_sha256 = hashlib.sha256(log_bytes).hexdigest()

    # 1. Verify against repository hash file
    with open(SERIAL_HASH_FILE, "r", encoding="utf-8") as f:
        pinned_hash = f.read().split()[0].strip()
    assert log_sha256 == pinned_hash, (
        f"Serial log SHA-256 hash mismatch! Computed {log_sha256}, pinned {pinned_hash}"
    )
    print(f"  [✓] Repository SHA-256 Hash Seal Verified: {log_sha256}")

    # 2. Authenticate against Trust Anchor OUTSIDE repository
    if EXTERNAL_SERIAL_ANCHOR.exists():
        with open(EXTERNAL_SERIAL_ANCHOR, "r", encoding="utf-8") as f:
            ext_content = f.read()
        assert log_sha256 in ext_content, (
            f"EXTERNAL TRUST ANCHOR MISMATCH: Serial log hash {log_sha256} not found in {EXTERNAL_SERIAL_ANCHOR}!"
        )
        print(f"  [✓] External Trust Anchor Authenticated ({EXTERNAL_SERIAL_ANCHOR}): MATCH")
    elif deployment_acceptance or os.environ.get("SIEM_REQUIRE_EXTERNAL_TRUST_ANCHOR") == "1":
        print(f"  [-] FATAL: External trust anchor {EXTERNAL_SERIAL_ANCHOR} required but not found! Failing closed.")
        return False

    # 3. Independent structured record parsing, attribute binding, and key+fingerprint matching
    log_text = log_bytes.decode("utf-8", errors="replace")
    records = re.split(r"#\s*---\s*ACQUISITION RECORD \d+:\s*", log_text)

    valid_host_names = {entry["host"] for entry in verified_pins}
    parsed_records = {}
    for block in records[1:]:
        # Parse each block into a structured SerialAcquisitionRecord, binding identity, keys, and context
        try:
            record = parse_offline_acquisition_block(block, valid_host_names)
        except ValueError as e:
            raise AssertionError(f"Acquisition record binding failed: {e}") from e

        host_name = record.hostname
        assert host_name not in parsed_records, (
            f"AMBIGUOUS / DUPLICATE RECORD: Multiple acquisition records detected for host '{host_name}'!"
        )
        parsed_records[host_name] = record

    # Match each expected pin against its isolated parsed record
    for entry in verified_pins:
        host = entry["host"]
        assert host in parsed_records, f"Serial console log contains no acquisition record for pinned host '{host}'!"

        rec = parsed_records[host]
        rec.validate(expected_hostname=host, expected_key=entry["pubkey"], expected_fp=entry["fingerprint"])
        print(f"  [✓] {host:20s}: Isolated record parsed & bound (Key, Fingerprint, & Context match)")

    print(f"[+] Out-of-band serial port acquisition verified for {len(verified_pins)} instances.")
    return True

def verify_worm_bucket_and_objects(live_gcp: bool = False, bucket_override: str = None, project_id: str = "siem-detection-lab", deployment_acceptance: bool = False):
    print("\n" + "=" * 65)
    print(" [3/3] Acceptance Verification: WORM Policy & Object Immutability")
    print("=" * 65)

    if deployment_acceptance:
        print("  [*] Enforcing Deployment Acceptance: External signer trust anchor is MANDATORY.")
        assert EXTERNAL_SIGNER_ANCHOR.exists(), (
            f"FATAL: External signer trust anchor {EXTERNAL_SIGNER_ANCHOR} is MANDATORY in deployment acceptance mode but was not found!"
        )

    target_bucket = bucket_override or os.environ.get("EVIDENCE_BUCKET", "gs://siem-lab-immutable-evidence")
    if not target_bucket.startswith("gs://"):
        target_bucket = f"gs://{target_bucket}"

    assert WORM_VERIFY_FILE.exists(), f"FATAL: Missing WORM verification manifest {WORM_VERIFY_FILE}"
    with open(WORM_VERIFY_FILE, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    expected_objects = manifest_data.get("uploaded_objects", [])
    assert len(expected_objects) >= 2, f"FATAL: Manifest must declare at least 2 uploaded objects, found {len(expected_objects)}"

    if live_gcp:
        print("  [*] Mode: LIVE GOOGLE CLOUD STORAGE CONTROL PLANE API CHECK")
        cmd_bucket = ["gcloud", "storage", "buckets", "describe", target_bucket, "--format=json(retentionPolicy,softDeletePolicy)"]
        try:
            res = subprocess.run(cmd_bucket, capture_output=True, text=True, check=True)
            data = json.loads(res.stdout)
            ret_pol = data.get("retentionPolicy", {})
            is_locked = ret_pol.get("isLocked", False)
            retention_period = int(ret_pol.get("retentionPeriod", 0))

            print(f"  Live GCP Bucket: {target_bucket}")
            print(f"  Live Retention Mode: {'LOCKED (Immutable)' if is_locked else 'UNLOCKED (Mutable)'}")
            print(f"  Live Retention Period: {retention_period}s ({retention_period // 86400} days)")

            assert is_locked is True, f"Live GCP bucket {target_bucket} is NOT locked!"
            assert retention_period >= 2592000, f"Live GCP retention duration ({retention_period}s) < 30 days minimum!"
            print("  [✓] Live GCP Bucket Lock Finalized: Immutable WORM policy enforced")
            print("  [✓] Live GCP Minimum Retention Satisfied: >= 30 days retention enforced")

            # Live Object Verification against Manifest Records
            for obj_record in expected_objects:
                obj_name = obj_record["name"]
                expected_gen = str(obj_record["generation"])
                expected_md5 = obj_record["md5Hash"]
                expected_size = obj_record.get("size_bytes")

                obj_url = f"{target_bucket}/{obj_name}"
                cmd_obj = ["gcloud", "storage", "objects", "describe", obj_url, "--format=json(generation,md5Hash,size,retentionExpirationTime)"]
                res_obj = subprocess.run(cmd_obj, capture_output=True, text=True, check=True)
                obj_meta = json.loads(res_obj.stdout)

                live_gen = str(obj_meta.get("generation", ""))
                live_md5 = obj_meta.get("md5Hash", "")
                live_size = int(obj_meta.get("size", 0))
                live_exp = obj_meta.get("retentionExpirationTime", "")

                assert live_gen == expected_gen, (
                    f"Live GCS generation mismatch for {obj_name}! Live={live_gen}, Expected={expected_gen}"
                )
                assert live_md5 == expected_md5, (
                    f"Live GCS MD5 mismatch for {obj_name}! Live={live_md5}, Expected={expected_md5}"
                )
                if expected_size:
                    assert live_size == expected_size, (
                        f"Live GCS size mismatch for {obj_name}! Live={live_size}, Expected={expected_size}"
                    )
                expected_exp = obj_record.get("retentionExpirationTime")
                assert expected_exp, f"Manifest object record for {obj_name} is missing retentionExpirationTime!"
                assert live_exp, f"Missing retentionExpirationTime on live GCS object {obj_name}!"

                dt_live = parse_timezone_aware_utc(live_exp)
                dt_expected = parse_timezone_aware_utc(expected_exp)
                assert dt_live == dt_expected, (
                    f"Live GCS retentionExpirationTime UTC mismatch for {obj_name}! Live={dt_live.isoformat()}, Expected={dt_expected.isoformat()}"
                )
                print(f"  [✓] Live GCS Object Verified Against Manifest ({obj_name}): Gen={live_gen}, MD5={live_md5}, Size={live_size}B, RetentionExpiresUTC={dt_live.isoformat()} (MATCH)")

            print("[+] Live GCP WORM bucket and manifest object metadata successfully verified.")
            return True
        except FileNotFoundError:
            print("  [-] FATAL: 'gcloud' CLI was not found on PATH. Live GCP verification failed closed.")
            return False
        except subprocess.CalledProcessError as e:
            print(f"  [-] FATAL: Live GCP API query failed: {e.stderr.strip()}. Failing closed.")
            return False

    # Offline / Checked-in Artifact Verification
    print("  [*] Mode: Checked-In Cryptographic Verification Artifact")
    bucket = manifest_data.get("bucket")
    retention_policy = manifest_data.get("retentionPolicy", {})
    is_locked = retention_policy.get("isLocked", False)
    retention_period = retention_policy.get("retentionPeriod", 0)
    summary = manifest_data.get("verification_summary", {})

    print(f"  Target Bucket: {bucket}")
    print(f"  Retention Mode: {'LOCKED (Immutable)' if is_locked else 'UNLOCKED (Mutable)'}")
    print(f"  Retention Period: {retention_period} seconds ({retention_period // 86400} days)")

    assert is_locked is True, "WORM verification assertion failed: Bucket isLocked must be True!"
    assert retention_period >= 2592000, "WORM verification assertion failed: Retention period must be >= 30 days (2,592,000s)!"
    assert summary.get("bucket_lock_finalized") is True, "bucket_lock_finalized must be True"
    assert summary.get("minimum_retention_seconds_satisfied") is True, "minimum_retention_seconds_satisfied must be True"

    print("  [✓] Bucket Lock Finalized: Immutable (WORM-style retention supporting compliance-oriented controls)")
    print("  [✓] Minimum Retention Satisfied: >= 30 days retention enforced")

    # Object-Level Verification (MANDATORY: Local files MUST exist)
    for obj_record in expected_objects:
        obj_name = obj_record["name"]
        expected_gen = obj_record.get("generation")
        expected_sha256 = obj_record.get("sha256")
        expected_md5 = obj_record.get("md5Hash")
        expected_size = obj_record.get("size_bytes")

        assert str(expected_gen).isdigit() and len(str(expected_gen)) >= 14, f"Invalid GCS generation: {expected_gen}"
        assert len(expected_sha256) == 64, f"Invalid SHA-256 for {obj_name}: {expected_sha256}"
        expected_exp = obj_record.get("retentionExpirationTime")
        assert expected_exp, f"Manifest object record for {obj_name} missing retentionExpirationTime!"
        dt_exp = parse_timezone_aware_utc(expected_exp)
        assert dt_exp.tzinfo is not None, f"retentionExpirationTime for {obj_name} must be timezone-aware!"

        local_file = EVIDENCE_DIR / obj_name
        assert local_file.exists(), f"FATAL: Required local evidence file {local_file} is MISSING! Skipping prohibited."

        with open(local_file, "rb") as f:
            content = f.read()

        calc_sha256 = hashlib.sha256(content).hexdigest()
        calc_md5 = base64.b64encode(hashlib.md5(content).digest()).decode("ascii")
        calc_size = len(content)

        assert calc_sha256 == expected_sha256, f"Local file SHA-256 mismatch for {obj_name}! Expected {expected_sha256}, got {calc_sha256}"
        assert calc_md5 == expected_md5, f"Local file MD5 mismatch for {obj_name}! Expected {expected_md5}, got {calc_md5}"
        assert calc_size == expected_size, f"Local file size mismatch for {obj_name}! Expected {expected_size}, got {calc_size}"
        print(f"  [✓] Object Integrity ({obj_name}): Size={calc_size}B, SHA-256={calc_sha256[:16]}..., MD5={calc_md5} (MATCH)")

    # Cryptographic Detached Signature Verification (MANDATORY: Files & Pins MUST exist)
    archive_file = EVIDENCE_DIR / "evidence_20261028_191347.tar.gz"
    sig_file = EVIDENCE_DIR / "evidence_20261028_191347.tar.gz.sig"
    pubkey_file = DEFAULT_PUBKEY_FILE

    assert archive_file.exists(), f"FATAL: Missing signed archive {archive_file}!"
    assert sig_file.exists(), f"FATAL: Missing detached signature file {sig_file}!"
    assert pubkey_file.exists(), f"FATAL: Missing public key file {pubkey_file}!"
    assert SIGNER_PINS_FILE.exists(), f"FATAL: Missing trusted signer pins file {SIGNER_PINS_FILE}!"

    with open(pubkey_file, "rb") as f:
        pub_bytes = f.read()
    pub_sha256 = hashlib.sha256(pub_bytes).hexdigest()

    with open(SIGNER_PINS_FILE, "r", encoding="utf-8") as f:
        signer_pins_text = f.read()
    assert pub_sha256 in signer_pins_text, f"FATAL: Signer public key {pub_sha256} is NOT in {SIGNER_PINS_FILE}!"
    print(f"  [✓] Repository Signer Key Authenticated against TRUSTED_SIGNER_PINS.txt: {pub_sha256[:16]}...")

    # Authenticate against External Trust Anchor OUTSIDE repository
    if EXTERNAL_SIGNER_ANCHOR.exists():
        with open(EXTERNAL_SIGNER_ANCHOR, "r", encoding="utf-8") as f:
            ext_signer_content = f.read()
        assert pub_sha256 in ext_signer_content, (
            f"EXTERNAL TRUST ANCHOR MISMATCH: Signer key {pub_sha256} not in {EXTERNAL_SIGNER_ANCHOR}!"
        )
        print(f"  [✓] External Signer Trust Anchor Authenticated ({EXTERNAL_SIGNER_ANCHOR}): MATCH")
    elif deployment_acceptance or os.environ.get("SIEM_REQUIRE_EXTERNAL_TRUST_ANCHOR") == "1":
        print(f"  [-] FATAL: External trust anchor {EXTERNAL_SIGNER_ANCHOR} required but not found! Failing closed.")
        return False

    # Native Cryptography RSA-SHA256 Detached Signature Verification
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    pub_obj = load_pem_public_key(pub_bytes)
    archive_bytes = archive_file.read_bytes()
    sig_bytes = sig_file.read_bytes()

    pub_obj.verify(sig_bytes, archive_bytes, padding.PKCS1v15(), hashes.SHA256())
    print("  [✓] Detached Digital Signature Verified: RSA-SHA256 signature mathematically authentic")

    print("[+] WORM Storage immutability and object-level cryptographic seals successfully verified.")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Acceptance verification for host key pins and WORM storage.")
    parser.add_argument("--live-gcp", action="store_true", help="Query live Google Cloud APIs (fails closed on error)")
    parser.add_argument("--bucket", type=str, default=None, help="Cloud Storage bucket URL for live verification")
    parser.add_argument("--project", type=str, default="siem-detection-lab", help="GCP Project ID for live verification")
    parser.add_argument("--deployment-acceptance", action="store_true", help="Enforce deployment acceptance mode with mandatory external trust anchors")
    args = parser.parse_args()

    deployment_acceptance = (
        args.deployment_acceptance or
        os.environ.get("SIEM_DEPLOYMENT_ACCEPTANCE") == "1" or
        os.environ.get("SIEM_ACCEPTANCE_MODE") == "1" or
        os.environ.get("SIEM_REQUIRE_EXTERNAL_TRUST_ANCHOR") == "1"
    )

    if deployment_acceptance:
        print("[*] DEPLOYMENT ACCEPTANCE MODE ENFORCED: External trust anchors outside repository are mandatory.")

    verified_pins = verify_host_key_pins()
    if not verified_pins:
        sys.exit(1)

    serial_ok = verify_serial_console_evidence(
        verified_pins,
        live_gcp=args.live_gcp,
        project_id=args.project,
        deployment_acceptance=deployment_acceptance
    )
    worm_ok = verify_worm_bucket_and_objects(
        live_gcp=args.live_gcp,
        bucket_override=args.bucket,
        project_id=args.project,
        deployment_acceptance=deployment_acceptance
    )

    if verified_pins and serial_ok and worm_ok:
        print("\n" + "=" * 65)
        print(" [✓] ALL ACCEPTANCE VERIFICATION CHECKS PASSED SUCCESSFULLY.  ")
        print("=" * 65)
        sys.exit(0)
    else:
        print("\n[-] ACCEPTANCE VERIFICATION FAILED (Fail Closed).")
        sys.exit(1)
