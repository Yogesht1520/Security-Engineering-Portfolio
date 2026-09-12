# ============================================================
# SIEM Detection Lab — Terraform Main
# Cloud: Google Cloud Platform (GCP)
# ============================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  credentials = file(var.credentials_file)
  project     = var.project_id
  region      = var.region
  zone        = var.zone
}

# ── Local helpers ─────────────────────────────────────────────────────────────

locals {
  ssh_public_key = file(var.ssh_public_key_path)
}

# ══════════════════════════════════════════════════════════════════════════════
# NETWORKING — VPC & Subnet
# ══════════════════════════════════════════════════════════════════════════════

resource "google_compute_network" "siem_lab_vpc" {
  name                    = "siem-lab-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "public_subnet" {
  name          = "siem-lab-public-subnet"
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = google_compute_network.siem_lab_vpc.id
}

# ══════════════════════════════════════════════════════════════════════════════
# FIREWALL RULES
# ══════════════════════════════════════════════════════════════════════════════

# ── Honeypot: SSH Exposed to 0.0.0.0/0 ────────────────────────────────────────
resource "google_compute_firewall" "honeypot_allow_ssh_public" {
  name    = "honeypot-allow-ssh-public"
  network = google_compute_network.siem_lab_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["honeypot"]
  description   = "HONEYPOT: SSH intentionally exposed to the internet"
}

# ── SIEM: Management Ports (Your IP Only) ─────────────────────────────────────
resource "google_compute_firewall" "siem_allow_mgmt" {
  name    = "siem-allow-mgmt"
  network = google_compute_network.siem_lab_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22", "443"]
  }

  source_ranges = [var.your_public_ip]
  target_tags   = ["siem"]
  description   = "SIEM: SSH and Dashboard restricted to your IP only"
}

# ── SIEM: Agent Ports (Internal Only) ─────────────────────────────────────────
resource "google_compute_firewall" "siem_allow_agent" {
  name    = "siem-allow-agent"
  network = google_compute_network.siem_lab_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["1514", "1515"]
  }

  source_tags = ["honeypot"]
  target_tags = ["siem"]
  description = "SIEM: Wazuh agent ports allowed only from Honeypot VM"
}

# ══════════════════════════════════════════════════════════════════════════════
# COMPUTE — Honeypot VM
# ══════════════════════════════════════════════════════════════════════════════

resource "google_compute_instance" "honeypot" {
  name         = "siem-lab-honeypot"
  machine_type = var.honeypot_machine_type
  zone         = var.zone
  tags         = ["honeypot"]

  boot_disk {
    initialize_params {
      image = "${var.image_project}/${var.image_family}"
      size  = 30
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.public_subnet.id
    access_config {
      # Ephemeral public IP
    }
  }

  metadata = {
    ssh-keys       = "ubuntu:${local.ssh_public_key}"
    startup-script = file("${path.module}/../setup_honeypot.sh")
  }
}

# ══════════════════════════════════════════════════════════════════════════════
# COMPUTE — SIEM VM
# ══════════════════════════════════════════════════════════════════════════════

resource "google_compute_instance" "siem" {
  name         = "siem-lab-wazuh"
  machine_type = var.siem_machine_type
  zone         = var.zone
  tags         = ["siem"]

  boot_disk {
    initialize_params {
      image = "${var.image_project}/${var.image_family}"
      size  = 100
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.public_subnet.id
    access_config {
      # Ephemeral public IP
    }
  }

  metadata = {
    ssh-keys = "ubuntu:${local.ssh_public_key}"
  }
}
