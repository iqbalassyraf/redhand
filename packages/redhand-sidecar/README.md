# RedHand In-VPC Sidecar (`redhand-sidecar`)

The RedHand In-VPC Sidecar runs co-located with AI agent containers in customer VPC Kubernetes pods (EKS, GKE, AKS, or OpenShift).

## Architecture & Data Residency
1. **Local Evaluation:** Runs Tier 0 AST and Tier 1 ONNX DeBERTa prompt injection classifiers locally on `localhost:8080` (<50ms).
2. **Local DLP Scrubber:** Redacts API keys, bearer tokens, and PII before any packet leaves the pod boundary.
3. **Multi-Cloud STS Broker:** Downscopes cloud credentials via GCP Credential Access Boundaries or AWS STS Session Policies in-VPC.
4. **Metadata-Only Egress:** Only scrubbed, standardized OCSF v1.1.0 security findings are forwarded to customer SIEM / RedHand Cloud over TLS.

