# ============================================================
# SIEM Detection Lab — Terraform Variables
# Cloud: Google Cloud Platform (GCP)
# ============================================================

variable "project_id" {
  description = "GCP Project ID (not the project name)"
  type        = string
}

variable "region" {
  description = "GCP Region (e.g. us-central1)"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP Zone (e.g. us-central1-a)"
  type        = string
  default     = "us-central1-a"
}

variable "credentials_file" {
  description = "Path to the GCP Service Account JSON key"
  type        = string
  default     = "~/.gcp/terraform-sa.json"
}

variable "your_public_ip" {
  description = "Your home/work public IP in CIDR notation (e.g. 1.2.3.4/32). Locks SIEM dashboard + SSH to your IP only."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.your_public_ip))
    error_message = "your_public_ip must be a valid CIDR block, e.g. 1.2.3.4/32"
  }
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key to inject into both VMs"
  type        = string
  default     = "~/.ssh/siem_lab_key.pub"
}

# ── VM sizing ────────────────────────────────────────────────────────────────
# Honeypot uses Always Free e2-micro. SIEM uses e2-standard-2 from the $300 credit.

variable "honeypot_machine_type" {
  description = "Machine type for Honeypot VM"
  type        = string
  default     = "e2-micro"
}

variable "siem_machine_type" {
  description = "Machine type for SIEM VM"
  type        = string
  default     = "e2-standard-2"
}

variable "image_family" {
  description = "OS Image Family"
  type        = string
  default     = "ubuntu-2204-lts"
}

variable "image_project" {
  description = "OS Image Project"
  type        = string
  default     = "ubuntu-os-cloud"
}
