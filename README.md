# CloudGuard 🛡️

**CloudGuard** is a read-only AWS misconfiguration scanner written in Python 3.11. Developed as a cloud computing project, it evaluates target AWS accounts against selected CIS AWS Foundations Benchmark controls, assigns severity-based risk scores, and generates both an interactive Streamlit dashboard and an actionable HTML remediation report.

## Features
- **Strictly Read-Only:** Exclusively invokes AWS `describe_*`, `get_*`, and `list_*` APIs.
- **Resilient Scanning:** Gracefully handles `AccessDenied` and unavailable services without crashing.
- **CIS Aligned:** Audits S3, IAM, CloudTrail, EC2/VPC, EBS, and RDS against recognized CIS recommendations.
- **Posture Scoring:** Severity-weighted risk calculations per resource and per account.
- **Reporting & Visualization:** Jinja2-powered HTML report generation and Streamlit dashboard.

## Implemented Security Checks

| Check ID | Module | Title | Severity | CIS Control Focus | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **S3-01** | S3 | S3 bucket is publicly accessible | CRITICAL | Block Public Access, public ACLs, and wildcard policies | ✅ Implemented |
| **S3-02** | S3 | S3 bucket default encryption disabled | MEDIUM | Default server-side encryption (SSE-S3 / KMS) | ✅ Implemented |
| **S3-03** | S3 | S3 bucket versioning not enabled | LOW | S3 object versioning and recovery | ✅ Implemented |
| **IAM-01** | IAM | IAM user has console access without MFA | HIGH | Multi-factor authentication on console users | ✅ Implemented |
| **IAM-02** | IAM | IAM policy grants full administrative privileges (`*:*`) | HIGH | Customer-managed and inline wildcard admin policies | ✅ Implemented |
| **IAM-03** | IAM | IAM access key is older than 90 days or unused | MEDIUM | 90-day access key rotation and inactivity | ✅ Implemented |
| **IAM-04** | IAM | Root account has active access keys | CRITICAL | Elimination of root account access keys | ✅ Implemented |
| **NET-01** | Network | SSH (22) or RDP (3389) open to the world | HIGH | Ingress restriction on remote admin ports | ✅ Implemented |
| **NET-02** | Network | All traffic open to the world (`-1`) | CRITICAL | Ingress restriction on unrestricted traffic | ✅ Implemented |
| **DATA-01** | Data | EBS volume is not encrypted | MEDIUM | EBS volume encryption at rest | ✅ Implemented |
| **DATA-02** | Data | RDS instance unencrypted or publicly accessible | HIGH | RDS storage encryption and private endpoint isolation | ✅ Implemented |
| **LOG-01** | Logging | No multi-region CloudTrail is actively logging | HIGH | Multi-region CloudTrail auditing and active logging | ✅ Implemented |

## Project Structure
```text
cloudguard/
├── cloudguard/             # Core scanner package
│   ├── collectors/         # Read-only AWS resource configuration collectors
│   ├── checks/             # Modular, testable CIS security checks
│   │   ├── base.py         # BaseCheck & error-wrapping helper
│   │   ├── registry.py     # Check auto-discovery & registry
│   │   ├── s3.py           # S3-01, S3-02, S3-03
│   │   ├── iam.py          # IAM-01, IAM-02, IAM-03, IAM-04
│   │   ├── network.py      # NET-01, NET-02
│   │   ├── data.py         # DATA-01, DATA-02
│   │   └── logging_checks.py # LOG-01
│   ├── config.py           # Environment and profile configuration
│   ├── session.py          # Boto3 session & credential resolution
│   ├── models.py           # Finding dataclass & Severity enum
│   ├── scoring.py          # Severity-weighted risk scoring engine
│   ├── scanner.py          # Collector & check orchestration
│   ├── report.py           # Jinja2 HTML report generator
│   └── cli.py              # CLI entry point
├── dashboard/              # Streamlit dashboard application
│   └── app.py
├── templates/              # Jinja2 report templates
│   └── report.html.j2
├── tests/                  # Pytest test suite with Moto mocks
├── testbed/                # Vulnerable testbed IaC / fixtures
├── evaluation/             # Detection benchmarks & experimental metrics
├── docs/                   # Architecture & documentation
├── requirements.txt        # Project dependencies
├── .gitignore              # Git exclusions for secrets, state, and caches
└── README.md
```

## Quickstart

### 1. Set Up Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Tests
```bash
pytest
```

### 3. Run the Scanner via CLI
```bash
python -m cloudguard.cli --profile my-readonly-profile --regions us-east-1
```

### 4. Launch the Dashboard
```bash
streamlit run dashboard/app.py
```
