# Segmentation Policy

> **Project:** Zero-Trust Network & VPN Topology Architecture  
> **Author:** Yogesh T  
> **Version:** 1.0  
> **Last Updated:** 2026-09-26  
> **Standard:** NIST SP 800-207 (Zero Trust Architecture)

---

## 1. Policy Statement

This document defines the explicit, per-peer segment authorization policy for the Zero-Trust WireGuard lab. Access is **deny-by-default**; each peer must be explicitly authorized to reach each network segment. Authorization is enforced at **two independent layers** — failure or misconfiguration of either layer alone does not grant access.

---

## 2. Access Authorization Matrix

| Peer | VPN IP | Dev (10.10.1.0/24) | Prod (10.10.2.0/24) | Corp-HR (10.10.3.0/24) | Rationale |
|------|--------|--------------------|---------------------|------------------------|-----------|
| **Admin** | 10.0.0.2 | ✅ ALLOW | ✅ ALLOW | ✅ ALLOW | Platform administrator; requires cross-segment visibility for incident response and infrastructure management. Key stored in hardware token; rotated quarterly. |
| **Developer** | 10.0.0.3 | ✅ ALLOW | ❌ DENY+LOG | ❌ DENY+LOG | Dev engineers need access to development environments only. Prod access follows change-management process; HR data is out of scope by GDPR/privacy policy. |
| **Contractor** | 10.0.0.4 | ✅ ALLOW | ❌ DENY+LOG | ❌ DENY+LOG | External contractor with limited engagement scope (Dev environment only). Third-party access to Prod or HR systems prohibited by vendor access policy. |

**Legend:**  
✅ ALLOW = explicit firewall accept rule  
❌ DENY+LOG = explicit firewall drop rule with `log prefix "ZT-DENY-..."` — generates an audit event

---

## 3. Dual-Enforcement Layers

### Layer 1 — WireGuard AllowedIPs (Client-side)

`AllowedIPs` in each peer's `.conf` file controls which destination CIDRs the WireGuard kernel module will route through the tunnel on the **client device**. A peer without a CIDR in `AllowedIPs` has no routing path to that segment — traffic never reaches the gateway.

| Peer | AllowedIPs (client config) | Effect |
|------|---------------------------|--------|
| Admin | `10.0.0.0/8` | All segments routed through tunnel |
| Developer | `10.0.0.0/24, 10.10.1.0/24` | Only VPN subnet + Dev segment |
| Contractor | `10.0.0.0/24, 10.10.1.0/24` | Only VPN subnet + Dev segment |

**Limitation:** `AllowedIPs` is a client-side setting. An administrator error, a compromised endpoint, or a custom WireGuard client could widen this value. This is why Layer 2 exists.

### Layer 2 — nftables (Server-side, independent)

`firewall/nftables.conf` applies on the **gateway** after WireGuard decrypts each tunnel packet. The firewall sees the peer's real VPN IP address (post-decryption) and applies policy independently — it has no knowledge of what the peer's `AllowedIPs` says. Even if a peer's `AllowedIPs` is widened to `10.0.0.0/8`, these rules still DENY and LOG unauthorized segment access.

```
# Example: Contractor → Prod (DENIED regardless of AllowedIPs)
ip saddr 10.0.0.4 ip daddr 10.10.2.0/24
  log prefix "ZT-DENY-CONTRACTOR-PROD: " flags all
  drop
```

---

## 4. Enforcement Evidence Requirements

Each DENY event must generate a log entry visible in:

1. **`journalctl -k`** — kernel ring buffer (real-time)  
2. **`/var/log/zt-evidence/firewall-denies.log`** — rsyslog-routed dedicated deny log  
3. **`TEST_EVIDENCE.md`** — screenshot + log paste for portfolio audit trail

---

## 5. Zero-Trust Principles Applied

| ZT Principle (NIST SP 800-207) | Implementation |
|---------------------------------|----------------|
| **Verify explicitly** | Identity = WireGuard Ed25519 public key, not a username, IP, or "being on the VPN" |
| **Use least-privilege access** | Each peer is authorized only for the minimum segments required for their role |
| **Assume breach** | Dual-layer enforcement means no single misconfiguration grants access; every DENY is logged |
| **Never trust the network position** | "Connected to VPN ≠ access to everything" — the firewall enforces segmentation *inside* the VPN |

---

## 6. Commercial Equivalents

This open-source implementation replicates the pattern behind commercial ZTNA products:

| Commercial Product | This Lab's Equivalent |
|--------------------|----------------------|
| Zscaler Private Access (ZPA) | WireGuard + nftables |
| Cloudflare Access | WireGuard + nftables |
| HashiCorp Boundary | `AllowedIPs` scoping |
| Per-resource firewall policy | `nftables` forward chain rules |

The core difference: commercial products add a policy management plane, SSO integration, and automatic certificate rotation. The underlying *network enforcement model* is identical.

---

## 7. Policy Review Schedule

| Event | Action |
|-------|--------|
| Contractor engagement ends | Immediately revoke keypair from `wg0.conf`, reload WireGuard |
| Admin key rotation | Quarterly — generate new keypair, update server `[Peer]` block |
| Segment IP change | Update `nftables.conf` named sets + all affected peer `AllowedIPs` |
| New peer onboarded | Run `generate_peer.sh`, add matching nftables rules FIRST |

> [!IMPORTANT]
> Never distribute a new peer config before adding the corresponding nftables rules. A peer with an AllowedIPs gap but no DENY rule falls through to the `ZT-DENY-UNMATCHED` catch-all — effective, but the missing explicit rule is a policy gap that should be remediated.
