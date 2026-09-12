# ============================================================
# SIEM Detection Lab — Terraform Outputs
# Run: terraform output   (after apply)
# ============================================================

output "honeypot_public_ip" {
  description = "Public IP of the Honeypot VM — SSH exposed to internet intentionally"
  value       = google_compute_instance.honeypot.network_interface[0].access_config[0].nat_ip
}

output "honeypot_private_ip" {
  description = "Private IP of the Honeypot VM"
  value       = google_compute_instance.honeypot.network_interface[0].network_ip
}

output "siem_public_ip" {
  description = "Public IP of the SIEM VM — access restricted to your IP only"
  value       = google_compute_instance.siem.network_interface[0].access_config[0].nat_ip
}

output "siem_private_ip" {
  description = "Private IP of the SIEM VM"
  value       = google_compute_instance.siem.network_interface[0].network_ip
}

output "ssh_honeypot" {
  description = "SSH command for Honeypot VM"
  value       = "ssh -i ~/.ssh/siem_lab_key ubuntu@${google_compute_instance.honeypot.network_interface[0].access_config[0].nat_ip}"
}

output "ssh_siem" {
  description = "SSH command for SIEM VM"
  value       = "ssh -i ~/.ssh/siem_lab_key ubuntu@${google_compute_instance.siem.network_interface[0].access_config[0].nat_ip}"
}

output "wazuh_dashboard_url" {
  description = "Wazuh Dashboard URL (accessible only from your IP — Phase 1)"
  value       = "https://${google_compute_instance.siem.network_interface[0].access_config[0].nat_ip}"
}

output "security_posture_summary" {
  description = "Human-readable summary of the firewall posture"
  value = <<-EOT
    ╔══════════════════════════════════════════════════════════════╗
    ║           SIEM Lab — Security Posture Summary                ║
    ╠══════════════════════════════════════════════════════════════╣
    ║ HONEYPOT VM: ${google_compute_instance.honeypot.network_interface[0].access_config[0].nat_ip}
    ║   • TCP 22  → 0.0.0.0/0      ← INTENTIONAL HONEYPOT        ║
    ╠══════════════════════════════════════════════════════════════╣
    ║ SIEM VM: ${google_compute_instance.siem.network_interface[0].access_config[0].nat_ip}
    ║   • TCP 22  → ${var.your_public_ip} (your IP only)
    ║   • TCP 443 → ${var.your_public_ip} (your IP only)
    ║   • TCP 1514→ ${google_compute_instance.honeypot.network_interface[0].network_ip} (honeypot only)
    ║   • TCP 1515→ ${google_compute_instance.honeypot.network_interface[0].network_ip} (honeypot only)
    ╚══════════════════════════════════════════════════════════════╝
  EOT
}
