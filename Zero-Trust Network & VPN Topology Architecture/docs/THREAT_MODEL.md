# Threat Model

> **Project:** Zero-Trust Network & VPN Topology Architecture  
> **Framework:** STRIDE + NIST SP 800-207 §3.3  
> **Scope:** WireGuard ZTNA gateway + three-segment lab topology

---

## 1. Assets and Trust Boundaries

```
[ Internet ]
     │  (UDP 51820 only)
     ▼
[ Gateway VM ]  ← trust boundary: WireGuard decrypts + nftables enforces
     │
  ┌──┼──────────────────────┐
  ▼  ▼                      ▼
[Dev]  [Prod]            [Corp-HR]   ← trust boundary: separate namespaces/subnets
```

**Assets ranked by sensitivity:**

| Asset | Sensitivity | Breach Impact |
|-------|-------------|---------------|
| Corp-HR data | Critical | GDPR violation, reputational damage |
| Prod service | High | Service disruption, data exposure |
| Dev environment | Medium | IP theft, pivot to Prod |
| Gateway keys (private) | Critical | Full VPN compromise, MitM possible |
| Peer private keys | High | Impersonation of that peer's VPN identity |

---

## 2. STRIDE Threat Analysis

### S — Spoofing

| Threat | Description | Mitigation |
|--------|-------------|------------|
| Peer key spoofing | Attacker presents a valid public key to gain peer's network access | WireGuard's cryptographic binding: private key never leaves the peer device; server validates against known public key list in `wg0.conf` |
| Source IP spoofing inside tunnel | Peer sends packets with a different source VPN IP (e.g., claims to be Admin) | WireGuard associates each packet with the peer's public key — source IP inside the tunnel is set by the gateway based on which peer's key the packet decrypted from, not by what the peer claims |

### T — Tampering

| Threat | Description | Mitigation |
|--------|-------------|------------|
| Packet modification in transit | Attacker modifies traffic between peer and gateway | WireGuard uses ChaCha20-Poly1305 AEAD — any modification invalidates the authentication tag; packet is silently discarded |
| Config file tampering | Attacker with local access modifies `wg0.conf` or `nftables.conf` | OS-level file permissions (`chmod 0600`); root-only write access; file integrity monitoring (e.g., `aide`) recommended |

### R — Repudiation

| Threat | Description | Mitigation |
|--------|-------------|------------|
| Peer denies making a connection | No audit trail of peer connections | `wg show` logs latest-handshake timestamps; nftables DENY+LOG provides evidence of unauthorized *attempts*; recommended: ship logs to immutable SIEM |
| Log tampering | Attacker with root access deletes deny logs | Forward logs to remote SIEM immediately; use append-only log store |

### I — Information Disclosure

| Threat | Description | Mitigation |
|--------|-------------|------------|
| Traffic analysis on WireGuard UDP | Observer sees peer talking to gateway, timing/volume metadata | WireGuard has no traffic padding; timing side-channels are a known limitation. Acceptable for lab; in production: obfuscate with wstunnel or Tor |
| Segment discovery via error messages | ICMP unreachables reveal segment topology | nftables DROP (not REJECT) on deny rules — no ICMP unreachable generated; attacker learns nothing about segment existence |
| Private key exposure | Key in plaintext in `.conf` file | Phase 1 sets `chmod 0600` on all key files; in production: use `wg-key-guardian` or hardware HSM |

### D — Denial of Service

| Threat | Description | Mitigation |
|--------|-------------|------------|
| WireGuard UDP flood | Attacker floods port 51820 with fake handshake packets | WireGuard's crypto handshake is asymmetrically expensive for attacker (Noise protocol); rate-limiting rule: `limit rate 10/second burst 20` on input chain (add to nftables input chain) |
| Segment host resource exhaustion | Contractor floods Dev segment port 8080 | Contractor IS authorized to reach Dev — authorized DoS is out of scope for zero-trust; layer-7 rate limiting needed at application level |

### E — Elevation of Privilege

| Threat | Description | Mitigation |
|--------|-------------|------------|
| **AllowedIPs widening** ⭐ | Admin error or compromised endpoint widens contractor AllowedIPs from `10.10.1.0/24` to `10.0.0.0/8`, giving tunnel route to all segments | **This is the Phase 3 test.** nftables DENY+LOG rules on the gateway are fully independent of AllowedIPs. Server sees post-decryption source IP 10.0.0.4 and blocks Prod/HR regardless |
| Peer key theft | Attacker steals contractor's private key, impersonates contractor | Same VPN access as contractor — still limited to Dev by nftables. Mitigations: hardware token storage, immediate revocation procedure |
| Gateway root compromise | Attacker gains root on gateway VM | Game over for VPN layer; mitigations: minimal attack surface (only SSH + WireGuard exposed), regular patching, cloud provider MFA |

---

## 3. Risk Register

| ID | Threat | Likelihood | Impact | Risk | Mitigated By |
|----|--------|-----------|--------|------|--------------|
| R1 | AllowedIPs misconfiguration | Medium | High | **High** | nftables Layer 2 (Phase 3) |
| R2 | Peer private key theft | Low | High | **Medium** | Hardware token; revocation procedure |
| R3 | Gateway root compromise | Low | Critical | **Medium** | Minimal exposure; patching cadence |
| R4 | Log tampering | Low | Medium | **Low** | Remote SIEM forwarding |
| R5 | UDP flood on 51820 | Medium | Medium | **Medium** | WireGuard crypto asymmetry + rate limit |
| R6 | Traffic timing analysis | High | Low | **Low** | Acceptable for lab; obfuscate in production |

---

## 4. Residual Risk Acceptance

| Risk | Accepted? | Reason |
|------|-----------|--------|
| Traffic volume metadata | ✅ Yes | Lab scope; no sensitive data in transit |
| No MFA for peer authentication | ✅ Yes | WireGuard uses cryptographic key = strong authentication; MFA adds complexity without clear benefit in this model |
| Gateway is single point of failure | ✅ Yes | Lab topology; production would use HA gateway pair |
