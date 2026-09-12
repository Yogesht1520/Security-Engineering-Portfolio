# SIEM Lab Restart & Recovery Guide

Because this lab was built using Terraform (Infrastructure as Code), bringing it all back online from scratch is surprisingly fast. However, because the software installation (Wazuh) was done manually as part of the learning process, there are a few steps required to fully restore the environment.

Here is the exact playbook to spin the lab back up in the future:

## 1. Rebuild the Infrastructure
Open your terminal and run:
```bash
cd infra/terraform
terraform apply
```
*This instantly provisions your VPC, subnets, firewalls, and both VMs using your existing SSH keys.*

## 2. Reinstall the SIEM (Wazuh Manager)
SSH into the new SIEM VM using the IP output by Terraform, and run the quickstart script again:
```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
*(Save the new admin password it prints at the end!)*

## 3. Reinstall the Honeypot Agent
1. Update `infra/setup_honeypot.sh` with the **new** SIEM Private IP.
2. SSH into the new Honeypot VM and run the script:
```bash
chmod +x setup_honeypot.sh
sudo ./setup_honeypot.sh
```

## 4. Restore Your Custom Rules
Copy your custom XML rules from your `wazuh/custom_rules/` folder back onto the SIEM VM:
```bash
sudo cp *.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/*.xml
sudo systemctl restart wazuh-manager
```

## 5. Rebuild the Dashboards
Since you built the visualizations manually in the UI, you would just follow your `24HR_OBSERVATION_REPORT.md` and the screenshots you took to quickly recreate the dashboard panels in OpenSearch.

***

> **Pro-Tip for the future:** If you ever want to take this project to the next level, you could use a tool called **Ansible** to fully automate steps 2, 3, 4, and 5! (That's what actual DevOps and Security Automation teams do so they never have to configure a server manually twice).
