# End-to-End DevSecOps Workflow: Catching a Vulnerability

This document tells the story of how our DevSecOps pipeline functions in reality. We walk through a developer introducing vulnerable code, the pipeline catching and blocking it, and the subsequent remediation that allows the code to ship.

## Stage 1: The Vulnerable Commit

A developer is building a new search feature and pushes a commit to their feature branch. This commit intentionally introduces three major security flaws:

1. **A hardcoded AWS secret** in `app/config_example.py`
2. **A vulnerable dependency** (`Flask 2.2.2`, which suffers from CVE-2023-30861) in `app/requirements.txt`
3. **An insecure SQL concatenation pattern** (SQL Injection vector) in `app/app.py`

They open a Pull Request against the `main` branch.

## Stage 2: The Security Pipeline Triggers

The instant the PR is opened, GitHub Actions intercepts the event and spins up five parallel jobs.

Our pipeline employs **Defense in Depth**:
- `secret-scan` (TruffleHog)
- `dependency-scan` (Trivy SCA)
- `sast-scan` (Semgrep)
- `iac-scan` (Checkov)
- `container-scan` (Trivy Image)

Because the jobs run in parallel, one failure does not mask the others. The developer gets a complete picture of their PR's security posture in under 3 minutes.

## Stage 3: The Security Gate Blocks the Merge

The pipeline finishes running. The `security-gate` job aggregates the results and produces the following Security Dashboard in the GitHub Actions Job Summary:

```text
Security Pipeline Report
═══════════════════════════════════
| Scanner | Status |
|---------|--------|
| Secrets (TruffleHog) | failure |
| SCA (Trivy) | failure |
| SAST (Semgrep) | failure |
| IaC (Checkov) | failure |
| Container (Trivy) | failure |

### ❌ Security Gate Failed
Action Required: High or Critical vulnerabilities were found. This PR is blocked.
```

Because of our Branch Protection Rules, GitHub disables the "Merge Pull Request" button. The deployment job (`build-and-deploy`) is entirely skipped. No vulnerable code is built; no vulnerable artifact reaches the container registry.

## Stage 4: Inline PR Annotations (SARIF)

The developer doesn't have to dig through raw terminal logs to figure out what went wrong. Because our scanners output in **SARIF** format, the findings are uploaded directly to the GitHub Code Scanning tab and annotated inline on the PR diff.

When the developer looks at the `app.py` file diff, they see an inline comment from Semgrep on line 32:
> ⚠️ **python.lang.security.audit.formatted-sql-query**
> Detected string concatenation with a non-literal variable in a SQL query. This could lead to SQL injection. Use parameterized queries instead.

When they look at `requirements.txt`, they see Trivy's annotation:
> ⚠️ **CVE-2023-30861 (HIGH)**
> Flask 2.2.2 is vulnerable to Cookie header not properly cleared on cross-domain redirects. Upgrade to 2.3.2.

## Stage 5: Remediation and Success

The developer fixes the code:
1. Replaces the hardcoded secret with an environment variable lookup (`os.environ.get('AWS_ACCESS_KEY_ID')`).
2. Upgrades Flask to `2.3.2` in `requirements.txt`.
3. Rewrites the SQL query in `app.py` to use parameterized inputs (`c.execute("SELECT ... WHERE username = ?", (query,))`).

They push the new commit. The pipeline triggers again.

This time, the dashboard lights up green:

```text
Security Pipeline Report
═══════════════════════════════════
| Scanner | Status |
|---------|--------|
| Secrets (TruffleHog) | success |
| SCA (Trivy) | success |
| SAST (Semgrep) | success |
| IaC (Checkov) | success |
| Container (Trivy) | success |

### ✅ Security Gate Passed
```

Because the gate passed, the `build-and-deploy` job finally executes:
1. It builds the Docker image.
2. It generates a CycloneDX **SBOM** (Software Bill of Materials) for supply-chain integrity.
3. It pushes the clean, verified image to GitHub Container Registry (`ghcr.io`).

The "Merge" button turns green. The secure code ships.
