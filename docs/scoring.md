# CloudGuard Risk Scoring Model

## 1. Finding-Level Risk Scoring

CloudGuard adopts a transparent two-dimensional risk scoring model based on **Impact** and **Exposure**:

$$\text{Risk Score} = \text{Impact} \times \text{Exposure}$$

Both factors are rated on a normalized integer scale from **1 to 5**, producing a composite risk score ranging from **1 to 25**.

### 1.1 Impact Scale (1 to 5)
Impact represents the technical and business damage should the misconfiguration be exploited. It derives directly from the check's baseline severity:

| Severity | Default Impact | Description |
| :--- | :---: | :--- |
| **CRITICAL** | 5 | Total account compromise, direct root access, or unrestricted public administrative access. |
| **HIGH** | 4 | Significant privilege escalation, remote administration exposure, or unrestricted network entry. |
| **MEDIUM** | 3 | Data protection gaps at rest, stale access credentials, or missing encryption configurations. |
| **LOW** | 2 | Governance hygiene issues, disabled versioning, or lack of object lifecycle recovery safeguards. |

### 1.2 Exposure Scale (1 to 5)
Exposure reflects the contextual accessibility and reachability of the affected resource:

| Exposure | Level | Contextual Indicators |
| :---: | :--- | :--- |
| **5** | Public Internet | Directly routable from `0.0.0.0/0` or `::/0`, S3 bucket open to `AllUsers`/`AuthenticatedUsers`, root keys present, or public RDS. |
| **4** | Broad Attack Surface | Unrestricted administrative IAM permissions (`*:*`), console users without MFA, or missing multi-region audit trails. |
| **3** | Baseline / Internal | Unencrypted EBS volumes or unencrypted private RDS databases at rest. |
| **2** | Low / Defense-in-Depth | Internal unversioned S3 buckets or inactive credentials nearing rotation limits. |
| **1** | Isolated | Minimal reachability and fully isolated private network perimeter. |

### 1.3 Effective Severity Mapping
The product of impact and exposure maps to four severity classification bands:

$$\text{Severity} = \begin{cases}
\textbf{CRITICAL}, & 20 \le \text{Risk Score} \le 25 \\
\textbf{HIGH}, & 12 \le \text{Risk Score} \le 19 \\
\textbf{MEDIUM}, & 6 \le \text{Risk Score} \le 11 \\
\textbf{LOW}, & 1 \le \text{Risk Score} \le 5
\end{cases}$$

---

## 2. Account Security Posture Score (0 to 100)

The account-level posture score provides a single normalized health index for the evaluated AWS environment:

$$\text{Posture Score} = \max\left(0.0, 100.0 - \sum_{f \in \text{Failures}} f.\text{risk\_score}\right)$$

### Rules:
1. **Clean Account Baseline:** An account with **zero failed findings** achieves a score of **100.0**.
2. **Deductions:** Each finding with status `FAIL` deducts its computed risk score (1 to 25) from the total.
3. **Skipped Checks:** Findings marked as `SKIPPED` (e.g. caused by `AccessDenied` or unconfigured services) deduct **0 points** and do not artificially lower the security posture.
4. **Lower Bound:** The posture score is bounded below at **0.0** and rounded to one decimal place.

### Summary Metrics Structure
The scanner produces an account-level summary dictionary containing:
- `total_findings`: Aggregate count of evaluated checks.
- `failed_findings`: Number of findings with `status == FAIL`.
- `skipped_findings`: Number of checks skipped due to missing permissions.
- `severity_counts`: Distribution of failed findings across `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `SKIPPED`.
- `posture_score`: Composite posture score (0.0 to 100.0).
- `total_risk_score`: Cumulative risk score across all failed findings.

