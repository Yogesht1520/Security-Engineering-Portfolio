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

# ── Primary Operational Subnet ────────────────────────────────────────────────
resource "google_compute_subnetwork" "public_subnet" {
  name          = "siem-lab-public-subnet"
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = google_compute_network.siem_lab_vpc.id
}

# ── Tier 1: Honeypot DMZ Subnet (Isolated Threat Zone) ────────────────────────
resource "google_compute_subnetwork" "dmz_subnet" {
  name          = "siem-lab-dmz-subnet"
  ip_cidr_range = "10.0.10.0/24"
  region        = var.region
  network       = google_compute_network.siem_lab_vpc.id
  description   = "DMZ subnet strictly isolated for internet-facing honeypots"
}

# ── Tier 2: SIEM Core Services Subnet (Hardened Security Plane) ───────────────
resource "google_compute_subnetwork" "siem_subnet" {
  name          = "siem-lab-siem-subnet"
  ip_cidr_range = "10.0.20.0/24"
  region        = var.region
  network       = google_compute_network.siem_lab_vpc.id
  description   = "Internal security operations subnet for Wazuh Manager & Indexer"
}

# ── Tier 3: Administrative Access Subnet (Management Plane) ───────────────────
resource "google_compute_subnetwork" "admin_subnet" {
  name          = "siem-lab-admin-subnet"
  ip_cidr_range = "10.0.30.0/24"
  region        = var.region
  network       = google_compute_network.siem_lab_vpc.id
  description   = "Restricted management subnet for bastion/jumpbox access"
}

# ══════════════════════════════════════════════════════════════════════════════
# SERVICE ACCOUNTS — Least-Privilege IAM Boundaries
# ══════════════════════════════════════════════════════════════════════════════

# NOTE: To attach a dedicated zero-privilege service account, enable iam.googleapis.com
# and provision google_service_account.honeypot_sa. The host-level kernel iptables
# REJECT and GCP firewall egress rule provide defense-in-depth metadata isolation.

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

# ── Honeypot: Explicit block for GCP Metadata Server (169.254.169.254) ────────
resource "google_compute_firewall" "honeypot_deny_metadata_egress" {
  name               = "honeypot-deny-metadata-egress"
  network            = google_compute_network.siem_lab_vpc.name
  direction          = "EGRESS"
  priority           = 900
  deny {
    protocol = "all"
  }
  destination_ranges = ["169.254.169.254/32"]
  target_tags        = ["honeypot"]
  description        = "CRITICAL: Block all egress from honeypot to GCP metadata server (169.254.169.254)"
}

# ── Honeypot: Deny all outbound egress by default ─────────────────────────────
resource "google_compute_firewall" "honeypot_deny_all_egress" {
  name      = "honeypot-deny-all-egress"
  network   = google_compute_network.siem_lab_vpc.name
  direction = "EGRESS"
  priority  = 65534
  deny {
    protocol = "all"
  }
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["honeypot"]
  description        = "HONEYPOT: Block all outbound connections by default"
}

# ── Honeypot: Allow internal Wazuh agent traffic to SIEM ──────────────────────
resource "google_compute_firewall" "honeypot_allow_wazuh_egress" {
  name      = "honeypot-allow-wazuh-egress"
  network   = google_compute_network.siem_lab_vpc.name
  direction = "EGRESS"
  priority  = 1000
  allow {
    protocol = "tcp"
    ports    = ["1514", "1515"]
  }
  destination_ranges = ["10.0.1.0/24", "10.0.20.0/24"]
  target_tags        = ["honeypot"]
  description        = "HONEYPOT: Allow telemetry shipping to Wazuh Manager"
}

# ── Honeypot: Allow package updates & DNS during setup ────────────────────────
resource "google_compute_firewall" "honeypot_allow_pkg_egress" {
  name      = "honeypot-allow-pkg-egress"
  network   = google_compute_network.siem_lab_vpc.name
  direction = "EGRESS"
  priority  = 1100
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
  allow {
    protocol = "udp"
    ports    = ["53"]
  }
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["honeypot"]
  description        = "HONEYPOT: Allow package repository and DNS access for bootstrap"
}

# ── SIEM: Explicit public block for OpenSearch Indexer ────────────────────────
resource "google_compute_firewall" "siem_deny_indexer_public" {
  name      = "siem-deny-indexer-public"
  network   = google_compute_network.siem_lab_vpc.name
  direction = "INGRESS"
  priority  = 800
  deny {
    protocol = "tcp"
    ports    = ["9200", "9300"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["siem"]
  description   = "SIEM: Defense-in-depth block for OpenSearch API from public internet"
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
