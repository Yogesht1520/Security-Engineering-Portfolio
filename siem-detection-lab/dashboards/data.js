// Auto-generated live telemetry data bundle for Interactive SOC Portal
const LIVE_DATA = {
  "case": {
    "case_id": "CASE-2026-001",
    "title": "Automated SSH Brute Force - Switzerland Scanner",
    "status": "contained",
    "severity": "high",
    "opened_at": "2026-10-26T19:38:03Z",
    "closed_at": null,
    "source_ip": "209.99.190.186",
    "geo": {
      "country": "Switzerland",
      "city": "Zurich",
      "asn": "AS402253 SKN Subnet & Telecom Ltd",
      "isp": "SKN Subnet & Telecom Ltd"
    },
    "reputation": {
      "abuseipdb_score": 100,
      "total_reports": 850,
      "last_reported_at": "2026-10-26T19:30:00Z"
    },
    "wazuh_alert_ids": [
      "1793042855.1468602",
      "1793042965.1469146",
      "1793043067.1469690",
      "1793043175.1470234",
      "1793043281.1470778",
      "1793043383.1471322",
      "1793043492.1471867",
      "1793043616.1472412",
      "1793043714.1477621",
      "1793043730.1479924",
      "1793043842.1484989"
    ],
    "target_users": [
      "ubuntu",
      "sysadmin",
      "var",
      "vor",
      "vr",
      "tmp",
      "www"
    ],
    "timeline": [
      {
        "timestamp": "2026-10-26T19:38:03Z",
        "event": "Case opened with severity HIGH targeting IP 209.99.190.186"
      },
      {
        "timestamp": "2026-10-26T19:44:34Z",
        "event": "Evidence preservation runbook executed. Artifacts captured to evidence/20261026_194434/"
      },
      {
        "timestamp": "2026-10-26T19:45:10Z",
        "event": "Forensic audit confirmed 0 successful sessions. SHA256 cryptographic manifest verified."
      },
      {
        "timestamp": "2026-10-26T19:46:00Z",
        "event": "Case transitioned to CONTAINED. Hardened egress controls verified intact."
      }
    ],
    "containment_actions": [
      "Preserved host auth.log, audit.log, volatile network sockets, and Wazuh alerts",
      "Verified honeypot outbound egress deny firewall rule (priority 65534) prevents lateral movement or reverse C2",
      "Verified password authentication rejected across all targeted accounts"
    ],
    "evidence_preserved": true,
    "analyst": "SOC Lead / Detection Engineering",
    "root_cause": "Opportunistic automated cloud botnet probing standard Unix and service accounts via paced dictionary attack.",
    "lessons_learned": "Scanner paced connection attempts to 1 every 60-120 seconds to evade burst thresholds. Wazuh rule 100012 (low-and-slow threshold) and rule 100014 (account targeting) are critical to capturing this profile."
  },
  "total_alerts_captured": 781,
  "alerts": [
    {
      "timestamp": "2026-10-26T19:04:01.830+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 5,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041441.1429646",
      "full_log": "Oct 26 19:04:01 siem-lab-wazuh sshd[67790]: Accepted publickey for ubuntu from 58.84.61.15 port 28772 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:04:01",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "28772",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:04:01.831+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 8,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041441.1430157",
      "full_log": "Oct 26 19:04:01 siem-lab-wazuh sshd[67790]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:04:01",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:04:03.832+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 4,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041443.1430602",
      "full_log": "Oct 26 19:04:02 siem-lab-wazuh sudo[67849]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/var/ossec/bin/wazuh-logtest",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:04:02",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/var/ossec/bin/wazuh-logtest"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:04:03.833+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 9,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041443.1431115",
      "full_log": "Oct 26 19:04:02 siem-lab-wazuh sudo[67849]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:04:02",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:04:05.835+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 10,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041445.1431556",
      "full_log": "Oct 26 19:04:03 siem-lab-wazuh sudo[67849]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:04:03",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:04:05.835+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 11,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041445.1431936",
      "full_log": "Oct 26 19:04:04 siem-lab-wazuh sshd[67790]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:04:04",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:04:21.851+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 10,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041461.1432320",
      "full_log": "Oct 26 19:04:19 siem-lab-wazuh sshd[67873]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:04:19",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:04:21.851+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 11,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041461.1432765",
      "full_log": "Oct 26 19:04:20 siem-lab-wazuh sudo[67920]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:04:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:04:21.851+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 5,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041461.1433206",
      "full_log": "Oct 26 19:04:20 siem-lab-wazuh sudo[67920]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/grep -A 10 'rule id=.550.' /var/ossec/ruleset/rules/0015-ossec_rules.xml",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:04:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/grep -A 10 'rule id=.550.' /var/ossec/ruleset/rules/0015-ossec_rules.xml"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:04:21.851+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 6,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041461.1433825",
      "full_log": "Oct 26 19:04:19 siem-lab-wazuh sshd[67873]: Accepted publickey for ubuntu from 58.84.61.15 port 16332 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:04:19",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "16332",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:04:21.851+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 12,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041461.1434336",
      "full_log": "Oct 26 19:04:20 siem-lab-wazuh sudo[67920]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:04:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:04:21.851+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 13,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041461.1434716",
      "full_log": "Oct 26 19:04:21 siem-lab-wazuh sshd[67873]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:04:21",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:11:44.311+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 12,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041904.1435100",
      "full_log": "Oct 26 19:11:43 siem-lab-wazuh sshd[67942]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:11:43",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:11:44.311+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 7,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041904.1435545",
      "full_log": "Oct 26 19:11:43 siem-lab-wazuh sshd[67942]: Accepted publickey for ubuntu from 58.84.61.15 port 10700 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:11:43",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "10700",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:11:48.315+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 14,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041908.1436056",
      "full_log": "Oct 26 19:11:47 siem-lab-wazuh sshd[67942]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:11:47",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:11:50.317+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 13,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041910.1436440",
      "full_log": "Oct 26 19:11:49 siem-lab-wazuh sshd[68005]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:11:49",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:11:50.317+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 8,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041910.1436885",
      "full_log": "Oct 26 19:11:49 siem-lab-wazuh sshd[68005]: Accepted publickey for ubuntu from 58.84.61.15 port 26327 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:11:49",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "26327",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:11:52.320+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 15,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041912.1437396",
      "full_log": "Oct 26 19:11:51 siem-lab-wazuh sshd[68005]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:11:51",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:14.342+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 14,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041934.1437780",
      "full_log": "Oct 26 19:12:14 siem-lab-wazuh sshd[68054]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:12:14",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:14.342+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 9,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041934.1438225",
      "full_log": "Oct 26 19:12:14 siem-lab-wazuh sshd[68054]: Accepted publickey for ubuntu from 58.84.61.15 port 27430 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:12:14",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "27430",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:18.346+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 16,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041938.1438736",
      "full_log": "Oct 26 19:12:17 siem-lab-wazuh sshd[68054]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:12:17",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:20.348+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 15,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041940.1439120",
      "full_log": "Oct 26 19:12:19 siem-lab-wazuh sshd[68103]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:12:19",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:20.348+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 10,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041940.1439565",
      "full_log": "Oct 26 19:12:19 siem-lab-wazuh sshd[68103]: Accepted publickey for ubuntu from 58.84.61.15 port 31436 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:12:19",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "31436",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:22.350+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 6,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041942.1440076",
      "full_log": "Oct 26 19:12:20 siem-lab-wazuh sudo[68150]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/bash /home/ubuntu/run_rule_unit_tests.sh",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/bash /home/ubuntu/run_rule_unit_tests.sh"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:22.350+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 16,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041942.1440631",
      "full_log": "Oct 26 19:12:20 siem-lab-wazuh sudo[68150]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:22.350+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 17,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041942.1441072",
      "full_log": "Oct 26 19:12:20 siem-lab-wazuh sudo[68152]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=0)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:22.350+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 17,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041942.1441507",
      "full_log": "Oct 26 19:12:20 siem-lab-wazuh sudo[68152]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:22.350+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 7,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041942.1441887",
      "full_log": "Oct 26 19:12:20 siem-lab-wazuh sudo[68158]:     root : PWD=/home/ubuntu ; USER=root ; COMMAND=/var/ossec/bin/wazuh-logtest",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "root",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/var/ossec/bin/wazuh-logtest"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:22.350+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 18,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041942.1442400",
      "full_log": "Oct 26 19:12:20 siem-lab-wazuh sudo[68158]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=0)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:22.350+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 18,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041942.1442835",
      "full_log": "Oct 26 19:12:22 siem-lab-wazuh sudo[68158]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:22",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:22.350+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 8,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041942.1443215",
      "full_log": "Oct 26 19:12:22 siem-lab-wazuh sudo[68185]:     root : PWD=/home/ubuntu ; USER=root ; COMMAND=/var/ossec/bin/wazuh-logtest",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:22",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "root",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/var/ossec/bin/wazuh-logtest"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:22.350+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 19,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041942.1443728",
      "full_log": "Oct 26 19:12:22 siem-lab-wazuh sudo[68185]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=0)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:22",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:22.350+0000",
      "rule": {
        "level": 4,
        "description": "First time user executed sudo.",
        "id": "5403",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 1,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041942.1444163",
      "full_log": "Oct 26 19:12:20 siem-lab-wazuh sudo[68152]:     root : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/test -x /var/ossec/bin/wazuh-logtest",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "root",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/test -x /var/ossec/bin/wazuh-logtest"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:24.352+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 19,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041944.1444535",
      "full_log": "Oct 26 19:12:23 siem-lab-wazuh sudo[68185]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:23",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:24.352+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 9,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041944.1444915",
      "full_log": "Oct 26 19:12:23 siem-lab-wazuh sudo[68212]:     root : PWD=/home/ubuntu ; USER=root ; COMMAND=/var/ossec/bin/wazuh-logtest",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:23",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "root",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/var/ossec/bin/wazuh-logtest"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:24.352+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 20,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041944.1445428",
      "full_log": "Oct 26 19:12:23 siem-lab-wazuh sudo[68212]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=0)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:23",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:26.354+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 20,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041946.1445863",
      "full_log": "Oct 26 19:12:24 siem-lab-wazuh sudo[68212]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:24",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:26.354+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 10,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041946.1446243",
      "full_log": "Oct 26 19:12:24 siem-lab-wazuh sudo[68239]:     root : PWD=/home/ubuntu ; USER=root ; COMMAND=/var/ossec/bin/wazuh-logtest",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:24",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "root",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/var/ossec/bin/wazuh-logtest"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:26.355+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 21,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041946.1446756",
      "full_log": "Oct 26 19:12:24 siem-lab-wazuh sudo[68239]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=0)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:24",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:26.355+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 21,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041946.1447191",
      "full_log": "Oct 26 19:12:25 siem-lab-wazuh sudo[68239]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:25",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:26.355+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 11,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041946.1447571",
      "full_log": "Oct 26 19:12:25 siem-lab-wazuh sudo[68266]:     root : PWD=/home/ubuntu ; USER=root ; COMMAND=/var/ossec/bin/wazuh-logtest",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:25",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "root",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/var/ossec/bin/wazuh-logtest"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:26.355+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 22,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041946.1448084",
      "full_log": "Oct 26 19:12:25 siem-lab-wazuh sudo[68266]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=0)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:25",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:28.356+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 22,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041948.1448519",
      "full_log": "Oct 26 19:12:26 siem-lab-wazuh sudo[68266]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:26",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:28.356+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 12,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041948.1448899",
      "full_log": "Oct 26 19:12:26 siem-lab-wazuh sudo[68293]:     root : PWD=/home/ubuntu ; USER=root ; COMMAND=/var/ossec/bin/wazuh-logtest",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:26",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "root",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/var/ossec/bin/wazuh-logtest"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:28.357+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 23,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041948.1449412",
      "full_log": "Oct 26 19:12:26 siem-lab-wazuh sudo[68293]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=0)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:26",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:28.357+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 23,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041948.1449847",
      "full_log": "Oct 26 19:12:27 siem-lab-wazuh sudo[68293]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:27",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:28.357+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 24,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041948.1450227",
      "full_log": "Oct 26 19:12:27 siem-lab-wazuh sudo[68150]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:12:27",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:12:28.357+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 25,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041948.1450607",
      "full_log": "Oct 26 19:12:28 siem-lab-wazuh sshd[68103]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:12:28",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:13:12.403+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 24,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041992.1450991",
      "full_log": "Oct 26 19:13:10 siem-lab-wazuh sshd[68318]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:13:10",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:13:12.403+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 11,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041992.1451436",
      "full_log": "Oct 26 19:13:10 siem-lab-wazuh sshd[68318]: Accepted publickey for ubuntu from 58.84.61.15 port 12763 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:13:10",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "12763",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:13:16.407+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 26,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793041996.1451947",
      "full_log": "Oct 26 19:13:15 siem-lab-wazuh sshd[68318]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:13:15",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:13:26.418+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 25,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042006.1452331",
      "full_log": "Oct 26 19:13:24 siem-lab-wazuh sshd[68378]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:13:24",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:13:26.418+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 12,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042006.1452776",
      "full_log": "Oct 26 19:13:24 siem-lab-wazuh sshd[68378]: Accepted publickey for ubuntu from 58.84.61.15 port 26377 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:13:24",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "26377",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:13:26.418+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 27,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042006.1453287",
      "full_log": "Oct 26 19:13:26 siem-lab-wazuh sshd[68378]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:13:26",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:13:46.440+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 13,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042026.1453671",
      "full_log": "Oct 26 19:13:44 siem-lab-wazuh sshd[68427]: Accepted publickey for ubuntu from 58.84.61.15 port 14892 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:13:44",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "14892",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:13:46.440+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 26,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042026.1454182",
      "full_log": "Oct 26 19:13:44 siem-lab-wazuh sshd[68427]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:13:44",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:13:50.443+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 28,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042030.1454627",
      "full_log": "Oct 26 19:13:48 siem-lab-wazuh sshd[68427]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:13:48",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:14:08.462+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 14,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042048.1455011",
      "full_log": "Oct 26 19:14:06 siem-lab-wazuh sshd[68476]: Accepted publickey for ubuntu from 58.84.61.15 port 6431 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:14:06",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "6431",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:14:08.462+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 27,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042048.1455520",
      "full_log": "Oct 26 19:14:06 siem-lab-wazuh sshd[68476]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:14:06",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:14:12.467+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 29,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042052.1455965",
      "full_log": "Oct 26 19:14:11 siem-lab-wazuh sshd[68476]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:14:11",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:24:39.085+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 28,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042679.1456349",
      "full_log": "Oct 26 19:24:39 siem-lab-wazuh sshd[68567]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:24:39",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:24:39.085+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 15,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042679.1456794",
      "full_log": "Oct 26 19:24:39 siem-lab-wazuh sshd[68567]: Accepted publickey for ubuntu from 58.84.61.15 port 14877 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:24:39",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "14877",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:24:41.087+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 13,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042681.1457305",
      "full_log": "Oct 26 19:24:40 siem-lab-wazuh sudo[68624]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/tail -n 20 /var/ossec/logs/alerts/alerts.json",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:24:40",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/tail -n 20 /var/ossec/logs/alerts/alerts.json"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:24:41.087+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 29,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042681.1457870",
      "full_log": "Oct 26 19:24:40 siem-lab-wazuh sudo[68624]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:24:40",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:24:41.087+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 30,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042681.1458311",
      "full_log": "Oct 26 19:24:40 siem-lab-wazuh sudo[68624]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:24:40",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:24:43.089+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 31,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042683.1458691",
      "full_log": "Oct 26 19:24:41 siem-lab-wazuh sshd[68567]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:24:41",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:26:46.183+0000",
      "rule": {
        "level": 3,
        "description": "Wazuh agent stopped.",
        "id": "506",
        "mitre": {
          "id": [
            "T1562.001"
          ],
          "tactic": [
            "Defense Evasion"
          ],
          "technique": [
            "Disable or Modify Tools"
          ]
        },
        "firedtimes": 1,
        "mail": false,
        "groups": [
          "ossec"
        ],
        "pci_dss": [
          "10.6.1",
          "10.2.6"
        ],
        "gpg13": [
          "10.1"
        ],
        "gdpr": [
          "IV_35.7.d"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.6",
          "AU.14",
          "AU.5"
        ],
        "tsc": [
          "CC7.2",
          "CC7.3",
          "CC6.8"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042806.1459075",
      "full_log": "ossec: Agent stopped: 'siem-lab-honeypot->any'.",
      "decoder": {
        "parent": "ossec",
        "name": "ossec"
      },
      "data": {
        "extra_data": "siem-lab-honeypot->any"
      },
      "location": "wazuh-remoted"
    },
    {
      "timestamp": "2026-10-26T19:26:47.872+0000",
      "rule": {
        "level": 3,
        "description": "Wazuh agent started.",
        "id": "503",
        "firedtimes": 1,
        "mail": false,
        "groups": [
          "ossec"
        ],
        "pci_dss": [
          "10.6.1",
          "10.2.6"
        ],
        "gpg13": [
          "10.1"
        ],
        "gdpr": [
          "IV_35.7.d"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.6",
          "AU.14",
          "AU.5"
        ],
        "tsc": [
          "CC7.2",
          "CC7.3",
          "CC6.8"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042807.1459422",
      "full_log": "ossec: Agent started: 'siem-lab-honeypot->any'.",
      "decoder": {
        "parent": "ossec",
        "name": "ossec"
      },
      "data": {
        "extra_data": "siem-lab-honeypot->any"
      },
      "location": "wazuh-agent"
    },
    {
      "timestamp": "2026-10-26T19:26:50.195+0000",
      "rule": {
        "level": 7,
        "description": "Host-based anomaly detection event (rootcheck).",
        "id": "510",
        "firedtimes": 3,
        "mail": false,
        "groups": [
          "ossec",
          "rootcheck"
        ],
        "pci_dss": [
          "10.6.1"
        ],
        "gdpr": [
          "IV_35.7.d"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042810.1459767",
      "full_log": "Trojaned version of file '/bin/diff' detected. Signature used: 'bash|^/bin/sh|file\\.h|proc\\.h|/dev/[^n]|^/bin/.*sh' (Generic).",
      "decoder": {
        "name": "rootcheck"
      },
      "data": {
        "title": "Trojaned version of file detected.",
        "file": "/bin/diff"
      },
      "location": "rootcheck"
    },
    {
      "timestamp": "2026-10-26T19:26:50.235+0000",
      "rule": {
        "level": 7,
        "description": "Host-based anomaly detection event (rootcheck).",
        "id": "510",
        "firedtimes": 4,
        "mail": false,
        "groups": [
          "ossec",
          "rootcheck"
        ],
        "pci_dss": [
          "10.6.1"
        ],
        "gdpr": [
          "IV_35.7.d"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042810.1460160",
      "full_log": "Trojaned version of file '/usr/bin/diff' detected. Signature used: 'bash|^/bin/sh|file\\.h|proc\\.h|/dev/[^n]|^/bin/.*sh' (Generic).",
      "decoder": {
        "name": "rootcheck"
      },
      "data": {
        "title": "Trojaned version of file detected.",
        "file": "/usr/bin/diff"
      },
      "location": "rootcheck"
    },
    {
      "timestamp": "2026-10-26T19:26:53.324+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 32,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042813.1460561",
      "full_log": "Oct 26 19:26:52 siem-lab-honeypot sudo: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:26:52",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:26:55.332+0000",
      "rule": {
        "level": 4,
        "description": "First time user executed sudo.",
        "id": "5403",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 2,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042815.1460955",
      "full_log": "Oct 26 19:26:55 siem-lab-honeypot sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl is-active wazuh-agent",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:26:55",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/systemctl is-active wazuh-agent"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:26:55.349+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 30,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042815.1461331",
      "full_log": "Oct 26 19:26:55 siem-lab-honeypot sudo: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:26:55",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:26:55.349+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 33,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042815.1461786",
      "full_log": "Oct 26 19:26:55 siem-lab-honeypot sudo: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:26:55",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:26:55.349+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 34,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042815.1462180",
      "full_log": "Oct 26 19:26:55 siem-lab-honeypot sshd[9186]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:26:55",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:27:07.349+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 31,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042827.1462584",
      "full_log": "Oct 26 19:27:05 siem-lab-honeypot sshd[9838]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:27:05",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:27:07.349+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 16,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042827.1463049",
      "full_log": "Oct 26 19:27:05 siem-lab-honeypot sshd[9838]: Accepted publickey for ubuntu from 58.84.61.15 port 25552 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:27:05",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "25552",
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:27:07.353+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 32,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042827.1463580",
      "full_log": "Oct 26 19:27:05 siem-lab-honeypot systemd: pam_unix(systemd-user:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "systemd",
        "timestamp": "Oct 26 19:27:05",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:27:07.355+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 14,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042827.1464050",
      "full_log": "Oct 26 19:27:06 siem-lab-honeypot sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl is-active wazuh-agent",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:27:06",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/systemctl is-active wazuh-agent"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:27:07.357+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 33,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042827.1464601",
      "full_log": "Oct 26 19:27:06 siem-lab-honeypot sudo: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:27:06",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:27:07.359+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 35,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042827.1465056",
      "full_log": "Oct 26 19:27:06 siem-lab-honeypot sudo: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:27:06",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:27:07.365+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 36,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042827.1465450",
      "full_log": "Oct 26 19:27:06 siem-lab-honeypot sshd[9838]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:27:06",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:27:19.265+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 17,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042839.1465854",
      "full_log": "Oct 26 19:27:19 siem-lab-wazuh sshd[68642]: Accepted publickey for ubuntu from 58.84.61.15 port 6572 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:27:19",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "6572",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:27:19.266+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 34,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042839.1466363",
      "full_log": "Oct 26 19:27:19 siem-lab-wazuh sshd[68642]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:27:19",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:27:21.266+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 15,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042841.1466808",
      "full_log": "Oct 26 19:27:20 siem-lab-wazuh sudo[68700]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/grep siem-lab-honeypot /var/ossec/logs/alerts/alerts.json",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:27:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/grep siem-lab-honeypot /var/ossec/logs/alerts/alerts.json"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:27:21.267+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 35,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042841.1467397",
      "full_log": "Oct 26 19:27:20 siem-lab-wazuh sudo[68700]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:27:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:27:21.267+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 37,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042841.1467838",
      "full_log": "Oct 26 19:27:20 siem-lab-wazuh sudo[68700]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:27:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:27:21.267+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 38,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042841.1468218",
      "full_log": "Oct 26 19:27:20 siem-lab-wazuh sshd[68642]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:27:20",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:27:35.378+0000",
      "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "id": "5710",
        "mitre": {
          "id": [
            "T1110.001",
            "T1021.004"
          ],
          "tactic": [
            "Credential Access",
            "Lateral Movement"
          ],
          "technique": [
            "Password Guessing",
            "SSH"
          ]
        },
        "firedtimes": 1,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_failed",
          "invalid_login"
        ],
        "gdpr": [
          "IV_35.7.d",
          "IV_32.2"
        ],
        "gpg13": [
          "7.1"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AU.6"
        ],
        "pci_dss": [
          "10.2.4",
          "10.2.5",
          "10.6.1"
        ],
        "tsc": [
          "CC6.1",
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042855.1468602",
      "full_log": "Oct 26 19:27:33 siem-lab-honeypot sshd[10271]: Invalid user vr from 209.99.190.186 port 39910",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:27:33",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "209.99.190.186",
        "srcport": "39910",
        "srcuser": "vr"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:29:25.494+0000",
      "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "id": "5710",
        "mitre": {
          "id": [
            "T1110.001",
            "T1021.004"
          ],
          "tactic": [
            "Credential Access",
            "Lateral Movement"
          ],
          "technique": [
            "Password Guessing",
            "SSH"
          ]
        },
        "firedtimes": 2,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_failed",
          "invalid_login"
        ],
        "gdpr": [
          "IV_35.7.d",
          "IV_32.2"
        ],
        "gpg13": [
          "7.1"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AU.6"
        ],
        "pci_dss": [
          "10.2.4",
          "10.2.5",
          "10.6.1"
        ],
        "tsc": [
          "CC6.1",
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793042965.1469146",
      "full_log": "Oct 26 19:29:23 siem-lab-honeypot sshd[10273]: Invalid user vr from 209.99.190.186 port 32984",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:29:23",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "209.99.190.186",
        "srcport": "32984",
        "srcuser": "vr"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:31:07.603+0000",
      "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "id": "5710",
        "mitre": {
          "id": [
            "T1110.001",
            "T1021.004"
          ],
          "tactic": [
            "Credential Access",
            "Lateral Movement"
          ],
          "technique": [
            "Password Guessing",
            "SSH"
          ]
        },
        "firedtimes": 3,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_failed",
          "invalid_login"
        ],
        "gdpr": [
          "IV_35.7.d",
          "IV_32.2"
        ],
        "gpg13": [
          "7.1"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AU.6"
        ],
        "pci_dss": [
          "10.2.4",
          "10.2.5",
          "10.6.1"
        ],
        "tsc": [
          "CC6.1",
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043067.1469690",
      "full_log": "Oct 26 19:31:07 siem-lab-honeypot sshd[10279]: Invalid user vr from 209.99.190.186 port 39786",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:31:07",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "209.99.190.186",
        "srcport": "39786",
        "srcuser": "vr"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:32:55.727+0000",
      "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "id": "5710",
        "mitre": {
          "id": [
            "T1110.001",
            "T1021.004"
          ],
          "tactic": [
            "Credential Access",
            "Lateral Movement"
          ],
          "technique": [
            "Password Guessing",
            "SSH"
          ]
        },
        "firedtimes": 4,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_failed",
          "invalid_login"
        ],
        "gdpr": [
          "IV_35.7.d",
          "IV_32.2"
        ],
        "gpg13": [
          "7.1"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AU.6"
        ],
        "pci_dss": [
          "10.2.4",
          "10.2.5",
          "10.6.1"
        ],
        "tsc": [
          "CC6.1",
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043175.1470234",
      "full_log": "Oct 26 19:32:54 siem-lab-honeypot sshd[10291]: Invalid user vr from 209.99.190.186 port 35488",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:32:54",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "209.99.190.186",
        "srcport": "35488",
        "srcuser": "vr"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:34:41.842+0000",
      "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "id": "5710",
        "mitre": {
          "id": [
            "T1110.001",
            "T1021.004"
          ],
          "tactic": [
            "Credential Access",
            "Lateral Movement"
          ],
          "technique": [
            "Password Guessing",
            "SSH"
          ]
        },
        "firedtimes": 5,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_failed",
          "invalid_login"
        ],
        "gdpr": [
          "IV_35.7.d",
          "IV_32.2"
        ],
        "gpg13": [
          "7.1"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AU.6"
        ],
        "pci_dss": [
          "10.2.4",
          "10.2.5",
          "10.6.1"
        ],
        "tsc": [
          "CC6.1",
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043281.1470778",
      "full_log": "Oct 26 19:34:40 siem-lab-honeypot sshd[10303]: Invalid user vr from 209.99.190.186 port 45846",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:34:40",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "209.99.190.186",
        "srcport": "45846",
        "srcuser": "vr"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:36:23.948+0000",
      "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "id": "5710",
        "mitre": {
          "id": [
            "T1110.001",
            "T1021.004"
          ],
          "tactic": [
            "Credential Access",
            "Lateral Movement"
          ],
          "technique": [
            "Password Guessing",
            "SSH"
          ]
        },
        "firedtimes": 6,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_failed",
          "invalid_login"
        ],
        "gdpr": [
          "IV_35.7.d",
          "IV_32.2"
        ],
        "gpg13": [
          "7.1"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AU.6"
        ],
        "pci_dss": [
          "10.2.4",
          "10.2.5",
          "10.6.1"
        ],
        "tsc": [
          "CC6.1",
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043383.1471322",
      "full_log": "Oct 26 19:36:22 siem-lab-honeypot sshd[10306]: Invalid user vor from 209.99.190.186 port 38792",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:36:22",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "209.99.190.186",
        "srcport": "38792",
        "srcuser": "vor"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:38:12.060+0000",
      "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "id": "5710",
        "mitre": {
          "id": [
            "T1110.001",
            "T1021.004"
          ],
          "tactic": [
            "Credential Access",
            "Lateral Movement"
          ],
          "technique": [
            "Password Guessing",
            "SSH"
          ]
        },
        "firedtimes": 7,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_failed",
          "invalid_login"
        ],
        "gdpr": [
          "IV_35.7.d",
          "IV_32.2"
        ],
        "gpg13": [
          "7.1"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AU.6"
        ],
        "pci_dss": [
          "10.2.4",
          "10.2.5",
          "10.6.1"
        ],
        "tsc": [
          "CC6.1",
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043492.1471867",
      "full_log": "Oct 26 19:38:10 siem-lab-honeypot sshd[10310]: Invalid user var from 209.99.190.186 port 40986",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:38:10",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "209.99.190.186",
        "srcport": "40986",
        "srcuser": "var"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:40:16.195+0000",
      "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "id": "5710",
        "mitre": {
          "id": [
            "T1110.001",
            "T1021.004"
          ],
          "tactic": [
            "Credential Access",
            "Lateral Movement"
          ],
          "technique": [
            "Password Guessing",
            "SSH"
          ]
        },
        "firedtimes": 8,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_failed",
          "invalid_login"
        ],
        "gdpr": [
          "IV_35.7.d",
          "IV_32.2"
        ],
        "gpg13": [
          "7.1"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AU.6"
        ],
        "pci_dss": [
          "10.2.4",
          "10.2.5",
          "10.6.1"
        ],
        "tsc": [
          "CC6.1",
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043616.1472412",
      "full_log": "Oct 26 19:40:14 siem-lab-honeypot sshd[10322]: Invalid user www from 209.99.190.186 port 60454",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:40:14",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "209.99.190.186",
        "srcport": "60454",
        "srcuser": "www"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:41:34.281+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 36,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043694.1472957",
      "full_log": "Oct 26 19:41:34 siem-lab-honeypot sshd[10327]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:41:34",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:41:34.280+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 18,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043694.1473423",
      "full_log": "Oct 26 19:41:34 siem-lab-honeypot sshd[10327]: Accepted publickey for ubuntu from 58.84.61.15 port 10284 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:41:34",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "10284",
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:41:34.285+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 37,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043694.1473955",
      "full_log": "Oct 26 19:41:34 siem-lab-honeypot systemd: pam_unix(systemd-user:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "systemd",
        "timestamp": "Oct 26 19:41:34",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:41:36.282+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 16,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043696.1474425",
      "full_log": "Oct 26 19:41:36 siem-lab-honeypot sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/tail -n 10 /var/log/auth.log",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:41:36",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/tail -n 10 /var/log/auth.log"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:41:36.282+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 38,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043696.1474970",
      "full_log": "Oct 26 19:41:36 siem-lab-honeypot sudo: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:41:36",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:41:36.284+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 39,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043696.1475425",
      "full_log": "Oct 26 19:41:36 siem-lab-honeypot sudo: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:41:36",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:41:38.287+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 40,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043698.1475819",
      "full_log": "Oct 26 19:41:36 siem-lab-honeypot sshd[10327]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:41:36",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:41:52.139+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 19,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043712.1476224",
      "full_log": "Oct 26 19:41:51 siem-lab-wazuh sshd[68747]: Accepted publickey for ubuntu from 58.84.61.15 port 14078 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:41:51",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "14078",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:41:52.139+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 39,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043712.1476735",
      "full_log": "Oct 26 19:41:51 siem-lab-wazuh sshd[68747]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:41:51",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:41:54.141+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 40,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043714.1477180",
      "full_log": "Oct 26 19:41:52 siem-lab-wazuh sudo[68805]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:41:52",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:41:54.141+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 17,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043714.1477621",
      "full_log": "Oct 26 19:41:52 siem-lab-wazuh sudo[68805]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/grep 209.99.190.186 /var/ossec/logs/alerts/alerts.json",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:41:52",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/grep 209.99.190.186 /var/ossec/logs/alerts/alerts.json"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:41:54.141+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 41,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043714.1478204",
      "full_log": "Oct 26 19:41:52 siem-lab-wazuh sudo[68805]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:41:52",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:41:54.142+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 42,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043714.1478584",
      "full_log": "Oct 26 19:41:53 siem-lab-wazuh sshd[68747]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:41:53",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:42:10.158+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 41,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043730.1478968",
      "full_log": "Oct 26 19:42:09 siem-lab-wazuh sshd[68811]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:42:09",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:42:10.158+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 20,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043730.1479413",
      "full_log": "Oct 26 19:42:09 siem-lab-wazuh sshd[68811]: Accepted publickey for ubuntu from 58.84.61.15 port 16436 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:42:09",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "16436",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:42:10.319+0000",
      "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "id": "5710",
        "mitre": {
          "id": [
            "T1110.001",
            "T1021.004"
          ],
          "tactic": [
            "Credential Access",
            "Lateral Movement"
          ],
          "technique": [
            "Password Guessing",
            "SSH"
          ]
        },
        "firedtimes": 9,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_failed",
          "invalid_login"
        ],
        "gdpr": [
          "IV_35.7.d",
          "IV_32.2"
        ],
        "gpg13": [
          "7.1"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AU.6"
        ],
        "pci_dss": [
          "10.2.4",
          "10.2.5",
          "10.6.1"
        ],
        "tsc": [
          "CC6.1",
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043730.1479924",
      "full_log": "Oct 26 19:42:10 siem-lab-honeypot sshd[10398]: Invalid user tmp from 209.99.190.186 port 43482",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:42:10",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "209.99.190.186",
        "srcport": "43482",
        "srcuser": "tmp"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:42:12.160+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 18,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043732.1480469",
      "full_log": "Oct 26 19:42:10 siem-lab-wazuh sudo[68859]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/grep -E id:1000[0-9]{2} /var/ossec/logs/alerts/alerts.json",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:42:10",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/grep -E id:1000[0-9]{2} /var/ossec/logs/alerts/alerts.json"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:42:12.160+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 42,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043732.1481060",
      "full_log": "Oct 26 19:42:10 siem-lab-wazuh sudo[68859]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:42:10",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:42:12.161+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 43,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043732.1481501",
      "full_log": "Oct 26 19:42:10 siem-lab-wazuh sudo[68859]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:42:10",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:42:12.161+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 44,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043732.1481881",
      "full_log": "Oct 26 19:42:10 siem-lab-wazuh sshd[68811]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:42:10",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:42:24.172+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 43,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043744.1482265",
      "full_log": "Oct 26 19:42:23 siem-lab-wazuh sshd[68863]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:42:23",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:42:24.172+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 21,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043744.1482710",
      "full_log": "Oct 26 19:42:23 siem-lab-wazuh sshd[68863]: Accepted publickey for ubuntu from 58.84.61.15 port 26361 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:42:23",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "26361",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:42:26.174+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 44,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043746.1483221",
      "full_log": "Oct 26 19:42:24 siem-lab-wazuh sudo[68915]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:42:24",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:42:26.174+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 19,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043746.1483662",
      "full_log": "Oct 26 19:42:24 siem-lab-wazuh sudo[68915]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/grep 1000 /var/ossec/logs/alerts/alerts.json",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:42:24",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/grep 1000 /var/ossec/logs/alerts/alerts.json"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:42:26.175+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 45,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043746.1484225",
      "full_log": "Oct 26 19:42:24 siem-lab-wazuh sudo[68915]: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:42:24",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:42:28.177+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 46,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043748.1484605",
      "full_log": "Oct 26 19:42:26 siem-lab-wazuh sshd[68863]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:42:26",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:44:02.418+0000",
      "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "id": "5710",
        "mitre": {
          "id": [
            "T1110.001",
            "T1021.004"
          ],
          "tactic": [
            "Credential Access",
            "Lateral Movement"
          ],
          "technique": [
            "Password Guessing",
            "SSH"
          ]
        },
        "firedtimes": 10,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_failed",
          "invalid_login"
        ],
        "gdpr": [
          "IV_35.7.d",
          "IV_32.2"
        ],
        "gpg13": [
          "7.1"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AU.6"
        ],
        "pci_dss": [
          "10.2.4",
          "10.2.5",
          "10.6.1"
        ],
        "tsc": [
          "CC6.1",
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043842.1484989",
      "full_log": "Oct 26 19:44:01 siem-lab-honeypot sshd[10402]: Invalid user sysadmin from 209.99.190.186 port 48448",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:01",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "209.99.190.186",
        "srcport": "48448",
        "srcuser": "sysadmin"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:38.458+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 22,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043878.1485539",
      "full_log": "Oct 26 19:44:37 siem-lab-honeypot sshd[10404]: Accepted publickey for ubuntu from 58.84.61.15 port 6326 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:37",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "6326",
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:38.459+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 45,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043878.1486069",
      "full_log": "Oct 26 19:44:37 siem-lab-honeypot sshd[10404]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:37",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:38.478+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 46,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043878.1486535",
      "full_log": "Oct 26 19:44:37 siem-lab-honeypot systemd: pam_unix(systemd-user:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "systemd",
        "timestamp": "Oct 26 19:44:37",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:42.467+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 47,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043882.1487005",
      "full_log": "Oct 26 19:44:42 siem-lab-honeypot sshd[10404]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:42",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:46.468+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 47,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043886.1487410",
      "full_log": "Oct 26 19:44:45 siem-lab-honeypot sshd[10475]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:45",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:46.468+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 23,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043886.1487876",
      "full_log": "Oct 26 19:44:45 siem-lab-honeypot sshd[10475]: Accepted publickey for ubuntu from 58.84.61.15 port 29415 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:45",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "29415",
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:46.472+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 20,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043886.1488408",
      "full_log": "Oct 26 19:44:46 siem-lab-honeypot sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cp /var/log/audit/audit.log /tmp/audit.log",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:44:46",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/cp /var/log/audit/audit.log /tmp/audit.log"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:46.474+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 48,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043886.1488981",
      "full_log": "Oct 26 19:44:46 siem-lab-honeypot sudo: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:44:46",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:46.476+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 48,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043886.1489436",
      "full_log": "Oct 26 19:44:46 siem-lab-honeypot sudo: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:44:46",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:46.478+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 21,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043886.1489830",
      "full_log": "Oct 26 19:44:46 siem-lab-honeypot sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/chmod 644 /tmp/audit.log",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:44:46",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/chmod 644 /tmp/audit.log"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:46.480+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 49,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043886.1490367",
      "full_log": "Oct 26 19:44:46 siem-lab-honeypot sudo: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:44:46",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:46.482+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 49,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043886.1490822",
      "full_log": "Oct 26 19:44:46 siem-lab-honeypot sudo: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:44:46",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:48.502+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 50,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043888.1491216",
      "full_log": "Oct 26 19:44:46 siem-lab-honeypot sshd[10475]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:46",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:50.474+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 24,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043890.1491621",
      "full_log": "Oct 26 19:44:49 siem-lab-honeypot sshd[10526]: Accepted publickey for ubuntu from 58.84.61.15 port 6154 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:49",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "6154",
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:50.474+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 50,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043890.1492151",
      "full_log": "Oct 26 19:44:49 siem-lab-honeypot sshd[10526]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:49",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:44:56.503+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 51,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043896.1492617",
      "full_log": "Oct 26 19:44:56 siem-lab-honeypot sshd[10526]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:56",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:45:00.495+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 51,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043900.1493022",
      "full_log": "Oct 26 19:44:58 siem-lab-honeypot sshd[10584]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:58",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:45:00.495+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 25,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043900.1493488",
      "full_log": "Oct 26 19:44:58 siem-lab-honeypot sshd[10584]: Accepted publickey for ubuntu from 58.84.61.15 port 7095 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:58",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "7095",
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:45:00.500+0000",
      "rule": {
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "id": "5402",
        "mitre": {
          "id": [
            "T1548.003"
          ],
          "tactic": [
            "Privilege Escalation",
            "Defense Evasion"
          ],
          "technique": [
            "Sudo and Sudo Caching"
          ]
        },
        "firedtimes": 22,
        "mail": false,
        "groups": [
          "syslog",
          "sudo"
        ],
        "pci_dss": [
          "10.2.5",
          "10.2.2"
        ],
        "gpg13": [
          "7.6",
          "7.8",
          "7.13"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7",
          "AC.6"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043900.1494018",
      "full_log": "Oct 26 19:44:59 siem-lab-honeypot sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/rm -f /tmp/audit.log",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:44:59",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sudo",
        "name": "sudo",
        "ftscomment": "First time user executed the sudo command"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "pwd": "/home/ubuntu",
        "command": "/usr/bin/rm -f /tmp/audit.log"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:45:00.502+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 52,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043900.1494547",
      "full_log": "Oct 26 19:44:59 siem-lab-honeypot sudo: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:44:59",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root(uid=0)",
        "uid": "1000"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:45:00.504+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 52,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043900.1495002",
      "full_log": "Oct 26 19:44:59 siem-lab-honeypot sudo: pam_unix(sudo:session): session closed for user root",
      "predecoder": {
        "program_name": "sudo",
        "timestamp": "Oct 26 19:44:59",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "root"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:45:00.510+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 53,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043900.1495396",
      "full_log": "Oct 26 19:44:59 siem-lab-honeypot sshd[10584]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:44:59",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:45:02.532+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 26,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043902.1495801",
      "full_log": "Oct 26 19:45:02 siem-lab-honeypot sshd[10633]: Accepted publickey for ubuntu from 58.84.61.15 port 27182 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:45:02",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "27182",
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:45:02.534+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 53,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043902.1496333",
      "full_log": "Oct 26 19:45:02 siem-lab-honeypot sshd[10633]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:45:02",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:45:04.505+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session closed.",
        "id": "5502",
        "firedtimes": 54,
        "mail": false,
        "groups": [
          "pam",
          "syslog"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "001",
        "name": "siem-lab-honeypot",
        "ip": "10.0.1.3"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043904.1496799",
      "full_log": "Oct 26 19:45:03 siem-lab-honeypot sshd[10633]: pam_unix(sshd:session): session closed for user ubuntu",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:45:03",
        "hostname": "siem-lab-honeypot"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu"
      },
      "location": "/var/log/auth.log"
    },
    {
      "timestamp": "2026-10-26T19:45:06.338+0000",
      "rule": {
        "level": 3,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "mitre": {
          "id": [
            "T1078"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access"
          ],
          "technique": [
            "Valid Accounts"
          ]
        },
        "firedtimes": 54,
        "mail": false,
        "groups": [
          "pam",
          "syslog",
          "authentication_success"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "gpg13": [
          "7.8",
          "7.9"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043906.1497204",
      "full_log": "Oct 26 19:45:06 siem-lab-wazuh sshd[68929]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:45:06",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "pam",
        "name": "pam"
      },
      "data": {
        "dstuser": "ubuntu(uid=1000)",
        "uid": "0"
      },
      "location": "journald"
    },
    {
      "timestamp": "2026-10-26T19:45:06.338+0000",
      "rule": {
        "level": 3,
        "description": "sshd: authentication success.",
        "id": "5715",
        "mitre": {
          "id": [
            "T1078",
            "T1021"
          ],
          "tactic": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
            "Lateral Movement"
          ],
          "technique": [
            "Valid Accounts",
            "Remote Services"
          ]
        },
        "firedtimes": 27,
        "mail": false,
        "groups": [
          "syslog",
          "sshd",
          "authentication_success"
        ],
        "gdpr": [
          "IV_32.2"
        ],
        "gpg13": [
          "7.1",
          "7.2"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "pci_dss": [
          "10.2.5"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ]
      },
      "agent": {
        "id": "000",
        "name": "siem-lab-wazuh"
      },
      "manager": {
        "name": "siem-lab-wazuh"
      },
      "id": "1793043906.1497649",
      "full_log": "Oct 26 19:45:06 siem-lab-wazuh sshd[68929]: Accepted publickey for ubuntu from 58.84.61.15 port 20500 ssh2: RSA SHA256:FPjcmNzJAzrXiT62NoR/eYlI6V+HO3WleNqVE0rUvLo",
      "predecoder": {
        "program_name": "sshd",
        "timestamp": "Oct 26 19:45:06",
        "hostname": "siem-lab-wazuh"
      },
      "decoder": {
        "parent": "sshd",
        "name": "sshd"
      },
      "data": {
        "srcip": "58.84.61.15",
        "srcport": "20500",
        "dstuser": "ubuntu"
      },
      "location": "journald"
    }
  ]
};
