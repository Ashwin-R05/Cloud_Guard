# CloudGuard Evaluation

This directory contains scripts and artifacts for measuring CloudGuard's detection accuracy, false positive rate, and remediation verification against controlled AWS test environments.

## Metrics Defined

- **Planted Issues ($P$):** Misconfigurations intentionally created in the testbed and tracked in `testbed/manifest.json`.
- **True Positives ($TP$):** Planted issues successfully detected by CloudGuard (`status == "FAIL"`).
- **False Negatives / Missed ($FN$):** Planted issues that CloudGuard failed to identify ($FN = P - TP$).
- **Detection Rate / Recall:** $\text{Recall} = \frac{TP}{P} \times 100\%$ (Target: 100%).
- **Control False Positives ($FP$):** Findings flagged against known-compliant control resources (e.g., properly encrypted and access-blocked S3 buckets). (Target: 0).
- **Remediation Success Rate:** Percentage of previously detected issues verified resolved in post-remediation scans: $\frac{\text{Remediated}}{TP} \times 100\%$.

## Evaluation Workflow

1. **Deploy Vulnerable Testbed:**
   ```bash
   python testbed/create_vulnerable.py --region us-east-1
   ```
   *(Saves resource metadata to `testbed/manifest.json`)*

2. **Run Baseline Scan (Before Remediation):**
   ```bash
   python -m cloudguard.cli --regions us-east-1 --output-dir evaluation/scans --format json
   ```

3. **Evaluate Baseline Scan:**
   ```bash
   python evaluation/evaluate.py --manifest testbed/manifest.json --before evaluation/scans/scan_pre.json
   ```

4. **Remediate Misconfigurations & Re-Scan:**
   Remediate the issues and run a post-remediation scan:
   ```bash
   python -m cloudguard.cli --regions us-east-1 --output-dir evaluation/scans --format json
   ```

5. **Compare Before & After Remediation:**
   ```bash
   python evaluation/evaluate.py \
       --manifest testbed/manifest.json \
       --before evaluation/scans/scan_pre.json \
       --after evaluation/scans/scan_post.json \
       --output evaluation/results.md
   ```


