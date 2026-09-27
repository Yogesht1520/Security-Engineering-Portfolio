# Evidence Screenshots Index

This directory stores the visual evidence for the **Hybrid Enterprise Identity & Conditional Access Lab**.

| File | Description | Verification Purpose |
|---|---|---|
| [`00-powershell-seed-users.png`](./00-powershell-seed-users.png) | PowerShell execution of `seed_users.ps1` provisioning groups and users | Proves IaC and directory automation via Microsoft Graph SDK |
| [`01-conditional-access-policies.png`](./01-conditional-access-policies.png) | Entra ID Conditional Access policies table showing 5 custom policies | Proves complete Zero Trust policy catalogue architecture |
| [`02-whatif-simulation-block.png`](./02-whatif-simulation-block.png) | "What If" simulation result showing CAP-001 & CAP-004 evaluating to Block | Proves non-disruptive policy simulation & condition evaluation |
| [`03-signin-logs-report-only.png`](./03-signin-logs-report-only.png) | Entra Sign-in log Report-only tab showing CAP-005 Success | Proves safe staging and telemetry auditing in Report-only mode |
| [`04-mfa-challenge-prompt.png`](./04-mfa-challenge-prompt.png) | Live sign-in screen intercepting `adm-alex` with Authenticator setup | Visual end-user proof of enforced MFA step-up challenge |
| [`05-signin-log-mfa-enforced.png`](./05-signin-log-mfa-enforced.png) | Entra Sign-in log Conditional Access tab showing CAP-002 Failure | Telemetry proof that token was denied due to missing MFA factor |
