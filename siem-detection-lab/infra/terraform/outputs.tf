# ============================================================
# SIEM Detection Lab — Terraform Outputs
# Run: terraform output   (after apply)
# ============================================================

output "honeypot_public_ip" {
  description = "Public IP of the Honeypot VM — SSH exposed to internet intentionally"
  value       = google_compute_instance.honeypot.network_interface[0].access_config[0].nat_ip
}

output "honeypot_private_ip" {
  description = "Private IP of the Honeypot VM in DMZ Subnet (10.0.10.0/24)"
  value       = google_compute_instance.honeypot.network_interface[0].network_ip
}

output "siem_private_ip" {
  description = "Private IP of the SIEM VM in Core Subnet (10.0.20.0/24) — No public IP"
  value       = google_compute_instance.siem.network_interface[0].network_ip
}

output "bastion_public_ip" {
  description = "Public IP of the Admin Bastion jumpbox in Admin Subnet (10.0.30.0/24)"
  value       = google_compute_instance.bastion.network_interface[0].access_config[0].nat_ip
}

output "ssh_honeypot" {
  description = "Direct SSH command for Honeypot VM"
  value       = "ssh -i ~/.ssh/siem_lab_key ubuntu@${google_compute_instance.honeypot.network_interface[0].access_config[0].nat_ip}"
}

output "ssh_bastion" {
  description = "SSH command for Admin Bastion jumpbox"
  value       = "ssh -i ~/.ssh/siem_lab_key ubuntu@${google_compute_instance.bastion.network_interface[0].access_config[0].nat_ip}"
}

output "ssh_siem" {
  description = "Secure SSH command for SIEM VM routed through Bastion jumpbox"
  value       = "ssh -i ~/.ssh/siem_lab_key -J ubuntu@${google_compute_instance.bastion.network_interface[0].access_config[0].nat_ip} ubuntu@${google_compute_instance.siem.network_interface[0].network_ip}"
}

output "wazuh_dashboard_tunnel" {
  description = "SSH local port forwarding command to access Wazuh Dashboard securely through Bastion"
  value       = "ssh -i ~/.ssh/siem_lab_key -N -L 8443:${google_compute_instance.siem.network_interface[0].network_ip}:443 ubuntu@${google_compute_instance.bastion.network_interface[0].access_config[0].nat_ip}"
}

output "wazuh_dashboard_url" {
  description = "Local tunnel URL for Wazuh Dashboard after opening SSH tunnel"
  value       = "https://localhost:8443"
}

output "security_posture_summary" {
  description = "Human-readable summary of the firewall posture and tier isolation"
  value       = <<-EOT
    ╔══════════════════════════════════════════════════════════════╗
    ║           SIEM Lab — Security Posture Summary                ║
    ╠══════════════════════════════════════════════════════════════╣
    ║ TIER 1: HONEYPOT VM (DMZ Subnet: 10.0.10.0/24)
    ║   • Public IP: ${google_compute_instance.honeypot.network_interface[0].access_config[0].nat_ip}
    ║   • TCP 22  → 0.0.0.0/0      ← INTENTIONAL HONEYPOT        ║
    ║   • Egress  → Default DENY (priority 65534)                  ║
    ╠══════════════════════════════════════════════════════════════╣
    ║ TIER 2: SIEM CORE VM (Core Subnet: 10.0.20.0/24)
    ║   • Private IP: ${google_compute_instance.siem.network_interface[0].network_ip} (NO PUBLIC IP)
    ║   • TCP 22, 443 → Admin Subnet only (via Bastion)            ║
    ║   • TCP 1514/1515 → Honeypot VM (10.0.10.2 only)             ║
    ║   • Internet Egress → Cloud NAT (No ingress from internet)   ║
    ╠══════════════════════════════════════════════════════════════╣
    ║ TIER 3: ADMIN BASTION (Admin Subnet: 10.0.30.0/24)
    ║   • Public IP: ${google_compute_instance.bastion.network_interface[0].access_config[0].nat_ip}
    ║   • TCP 22  → ${var.your_public_ip} (Analyst IP only)        ║
    ╚══════════════════════════════════════════════════════════════╝
  EOT
}
