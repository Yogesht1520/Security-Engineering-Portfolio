#!/usr/bin/env python3
"""
package_and_sign.py — Offline / Direct Evidence Signing and Bundle Generator

Implements the forensic packaging and digital signature pipeline specified in
preserve_evidence.sh v3.5.0:
1. Exports / generates RSA-3072 signing key.
2. Exports public key into the evidence directory BEFORE manifest generation.
3. Records public key fingerprint in trusted independent pins stores:
   - ~/.config/siem-lab/trusted_signer_pins.txt
   - evidence/TRUSTED_SIGNER_PINS.txt
4. Generates SHA256SUMS.txt covering all artifacts AND the public key.
5. Generates EVIDENCE_MANIFEST.json with full cryptographic metadata.
6. Generates detached RSA-SHA256 digital signatures:
   - EVIDENCE_MANIFEST.json.sig
   - SHA256SUMS.txt.sig
7. Builds complete tarball bundle: evidence_<TIMESTAMP>.tar.gz
8. Computes archive SHA-256 and generates detached signature:
   - evidence_<TIMESTAMP>.tar.gz.sha256
   - evidence_<TIMESTAMP>.tar.gz.sig
9. Verifies all signatures and checksums.
"""

import os
import sys
import glob
import json
import tarfile
import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_or_load_key(key_path: str):
    os.makedirs(os.path.dirname(os.path.abspath(key_path)), exist_ok=True)
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
            return private_key
    
    print(f"[*] Generating new RSA-3072 evidence signing key at {key_path}...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(key_path, "wb") as f:
        f.write(pem)
    return private_key

def package_and_sign(evidence_dir: str, key_path: str):
    if not os.path.isdir(evidence_dir):
        print(f"Error: Evidence directory {evidence_dir} does not exist.")
        sys.exit(1)
        
    abs_evidence_dir = os.path.abspath(evidence_dir)
    dir_name = os.path.basename(abs_evidence_dir.rstrip("/\\"))
    base_evidence_dir = os.path.dirname(abs_evidence_dir)
    
    # 1. Load / generate private key
    priv_key = generate_or_load_key(key_path)
    pub_key = priv_key.public_key()
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    pubkey_path = os.path.join(abs_evidence_dir, "EVIDENCE_SIGNING_PUBKEY.pub")
    with open(pubkey_path, "wb") as f:
        f.write(pub_bytes)
        
    pubkey_sha256 = hashlib.sha256(pub_bytes).hexdigest()
    print(f"[*] Exported public key. Fingerprint: SHA256:{pubkey_sha256}")
    
    # 2. Pin fingerprint in independent records
    user_home = os.path.expanduser("~")
    ext_pin_file = os.path.join(user_home, ".config", "siem-lab", "trusted_signer_pins.txt")
    os.makedirs(os.path.dirname(ext_pin_file), exist_ok=True)
    
    trusted_pin_file = os.path.join(base_evidence_dir, "TRUSTED_SIGNER_PINS.txt")
    
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pin_entry = f"{now_utc} | soc-analyst@siem-lab | SHA256:{pubkey_sha256} | EVIDENCE_SIGNING_PUBKEY.pub\n"
    
    with open(ext_pin_file, "a", encoding="utf-8") as f:
        f.write(pin_entry)
    with open(trusted_pin_file, "a", encoding="utf-8") as f:
        f.write(pin_entry)
        
    print(f"[✓] Pinned fingerprint in:\n    - {ext_pin_file}\n    - {trusted_pin_file}")
    
    # Clean prior signature & metadata files
    for stale in ["SHA256SUMS.txt", "SHA256SUMS.txt.sig", "EVIDENCE_MANIFEST.json", "EVIDENCE_MANIFEST.json.sig"]:
        p = os.path.join(abs_evidence_dir, stale)
        if os.path.exists(p):
            os.remove(p)
            
    # 3. Calculate checksums of all artifacts + public key
    entries = []
    file_hashes = {}
    for fname in sorted(os.listdir(abs_evidence_dir)):
        fpath = os.path.join(abs_evidence_dir, fname)
        if not os.path.isfile(fpath):
            continue
        if fname in ["SHA256SUMS.txt", "EVIDENCE_MANIFEST.json"] or fname.endswith(".sig") or fname.endswith(".tar.gz") or fname.endswith(".sha256"):
            continue
        with open(fpath, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        file_hashes[fname] = h
        entries.append(f"{h}  {fname}")
        
    sha256sums_path = os.path.join(abs_evidence_dir, "SHA256SUMS.txt")
    with open(sha256sums_path, "w", encoding="utf-8") as f:
        f.write("\n".join(entries) + "\n")
    print(f"[✓] Generated SHA256SUMS.txt covering {len(entries)} artifacts (including public key)")
    
    # 4. Generate JSON Manifest
    manifest_data = {
        "provenance": {
            "collector": "soc-analyst@siem-lab",
            "collection_start_utc": "2026-10-28T19:13:47Z",
            "collection_end_utc": now_utc,
            "runbook_version": "3.5.0",
            "preservation_mode": "local",
            "target_honeypot_ip": "34.121.64.158",
            "target_siem_ip": "34.71.182.95",
            "gcp_disk_snapshot": "snapshot-honeypot-disk-20261028-191347",
            "custody_notice": "Cryptographic hashes and asymmetric digital signatures guarantee tamper detection from recorded collection point forward."
        },
        "cryptography": {
            "digest_algorithm": "SHA-256",
            "signature_algorithm": "SHA256withRSA-PKCS#1v1.5",
            "public_key_file": "EVIDENCE_SIGNING_PUBKEY.pub",
            "public_key_sha256": pubkey_sha256,
            "trusted_pins_record": "evidence/TRUSTED_SIGNER_PINS.txt"
        },
        "artifacts": []
    }
    
    for fname, h in sorted(file_hashes.items()):
        fpath = os.path.join(abs_evidence_dir, fname)
        manifest_data["artifacts"].append({
            "filename": fname,
            "size_bytes": os.path.getsize(fpath),
            "sha256": h
        })
        
    manifest_path = os.path.join(abs_evidence_dir, "EVIDENCE_MANIFEST.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)
    print(f"[✓] Generated EVIDENCE_MANIFEST.json")
    
    # 5. Sign Manifest and SHA256SUMS.txt
    with open(manifest_path, "rb") as f:
        manifest_sig = priv_key.sign(
            f.read(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    with open(manifest_path + ".sig", "wb") as f:
        f.write(manifest_sig)
        
    with open(sha256sums_path, "rb") as f:
        sums_sig = priv_key.sign(
            f.read(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    with open(sha256sums_path + ".sig", "wb") as f:
        f.write(sums_sig)
        
    # Verify internal signatures
    pub_key.verify(manifest_sig, open(manifest_path, "rb").read(), padding.PKCS1v15(), hashes.SHA256())
    pub_key.verify(sums_sig, open(sha256sums_path, "rb").read(), padding.PKCS1v15(), hashes.SHA256())
    print(f"[✓] Internal digital signatures generated and verified")
    
    # 6. Build archive
    archive_name = f"evidence_{dir_name}.tar.gz"
    archive_path = os.path.join(base_evidence_dir, archive_name)
    
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(abs_evidence_dir, arcname=dir_name)
    print(f"[✓] Packaged tarball: {archive_path}")
    
    # 7. Compute archive SHA-256 and sign archive
    with open(archive_path, "rb") as f:
        archive_bytes = f.read()
        archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
        
    with open(archive_path + ".sha256", "w", encoding="utf-8") as f:
        f.write(f"{archive_sha256}  {archive_name}\n")
        
    archive_sig = priv_key.sign(
        archive_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    with open(archive_path + ".sig", "wb") as f:
        f.write(archive_sig)
        
    # Verify archive signature
    pub_key.verify(archive_sig, archive_bytes, padding.PKCS1v15(), hashes.SHA256())
    print(f"[✓] Archive digital signature generated and verified: {archive_path}.sig")
    print(f"    Archive SHA-256: {archive_sha256}")

if __name__ == "__main__":
    key = os.path.expanduser("~/.ssh/evidence_signing_key")
    edir = "evidence/20261028_191347"
    if len(sys.argv) > 1:
        edir = sys.argv[1]
    if len(sys.argv) > 2:
        key = sys.argv[2]
    package_and_sign(edir, key)

