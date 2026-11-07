# CloudGuard Documentation

This directory contains technical documentation for the CloudGuard security assessment framework. Each document is self-contained and cross-referenced.

---

## Index

| Document | Contents |
| :--- | :--- |
| [architecture.md](architecture.md) | System architecture, Mermaid flowcharts and sequence diagrams, component specifications, module dependency map |
| [iam-setup.md](iam-setup.md) | IAM prerequisites, AWS managed policies (`SecurityAudit`, `ViewOnlyAccess`), minimal custom IAM policy JSON, authentication configuration options (named profiles, environment variables, cross-account role assumption), and identity verification instructions |
| [scoring.md](scoring.md) | Two-dimensional risk scoring model ($\text{Impact} \times \text{Exposure}$), severity band mapping, account security posture score formula, and summary metrics structure |
| [schema.md](schema.md) | JSON report schema specification (JSON Schema 2020-12), root object properties, finding object properties, and credential safety guarantee |

## Related Documentation

| Location | Contents |
| :--- | :--- |
| [../evaluation/README.md](../evaluation/README.md) | Evaluation methodology, detection recall and false positive metrics, evaluation workflow |
| [../testbed/README.md](../testbed/README.md) | Testbed provisioning safety controls, creation and teardown instructions |
| [../README.md](../README.md) | Project overview, installation, CLI and dashboard usage, checks table, limitations, and future scope |
