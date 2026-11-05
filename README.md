# CloudGuard 🛡️

**CloudGuard** is a read-only AWS misconfiguration scanner written in Python 3.11. Developed as a cloud computing project, it evaluates target AWS accounts against selected CIS AWS Foundations Benchmark controls, assigns severity-based risk scores, and generates both an interactive Streamlit dashboard and an actionable HTML remediation report.

## Features
- **Strictly Read-Only:** Exclusively invokes AWS `describe_*`, `get_*`, and `list_*` APIs.
- **Resilient Scanning:** Gracefully handles `AccessDenied` and unavailable services without crashing.
- **CIS Aligned:** Audits S3, IAM, CloudTrail, VPC, and more against recognized CIS control recommendations.
- **Posture Scoring:** Severity-weighted risk calculations per resource and per account.
- **Reporting & Visualization:** Jinja2-powered HTML report generation and Streamlit dashboard.

## Project Structure
```text
cloudguard/
├── cloudguard/             # Core scanner package
│   ├── collectors/         # Read-only AWS resource configuration collectors
│   ├── checks/             # Modular, testable CIS security checks
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

# Cloud_Guard
