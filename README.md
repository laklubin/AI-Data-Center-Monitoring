# AI Data Center SIEM Use Cases

A SIEM detection library for **AI GPU data centers**: identity and the network edge, GPU fabric, bare metal,
Kubernetes and schedulers, MLOps, LLM applications, RAG, data and the facility itself.

**Live site:** https://laklubin.github.io/AI-Data-Center-Monitoring/

Each use case contains:

| Field | What it gives you |
|---|---|
| **Use case name** | The behaviour to detect |
| **Log source** | Which product / log stream to collect (e.g. Kubernetes audit, DCGM exporter, Entra ID sign-in logs, Lustre changelogs) |
| **Sample log** | A realistic event in the source's native format, for building parsers and testing rules |
| **Detection logic** | Vendor-neutral rule logic with starting thresholds |
| **Severity** | Critical / High / Medium / Low |
| **Mappings** | MITRE ATT&CK (Enterprise & ICS), MITRE ATLAS, OWASP Top 10 for LLM Apps 2025, OWASP API Top 10 2023 |

## Coverage

Domains are grouped by layer. Domains marked *(added)* go beyond the original 14-domain scope and cover areas
specific to GPU data centers: storage, facilities, endpoint runtime, cloud control plane, multi-tenancy, AI gateways
and backup.

<!-- COVERAGE:START -->
| Layer | Domain | Scope | Use cases | Critical | High | Medium | Low |
|---|---|---|---:|---:|---:|---:|---:|
| Identity & Perimeter | Identity & Access | Active Directory, Entra ID, LDAP, SSO, MFA, PAM, service accounts, workload identities, API keys | 15 | 3 | 10 | 2 | 0 |
| Identity & Perimeter | Network Security | Next-generation firewalls, IDS/IPS, NDR, DNS, VPN, ZTNA, network flow monitoring | 10 | 1 | 6 | 3 | 0 |
| Identity & Perimeter | Application Security | WAF, API gateway, reverse proxy, load balancers, bot protection, DDoS protection | 8 | 1 | 6 | 1 | 0 |
| GPU & Physical Infrastructure | GPU Infrastructure | NVIDIA GPUs, NVIDIA DCGM, GPU Operator, GPU drivers, MIG, GPU allocation and scheduling | 12 | 1 | 6 | 3 | 2 |
| GPU & Physical Infrastructure | GPU Networking | Ethernet, InfiniBand, RDMA / RoCE, NVLink, NVSwitch, BlueField DPUs, fabric management | 10 | 1 | 8 | 1 | 0 |
| GPU & Physical Infrastructure | Compute / Hardware | Bare-metal servers, virtual machines, hypervisors, Linux, BMC, Redfish / IPMI, secure boot | 10 | 0 | 9 | 1 | 0 |
| GPU & Physical Infrastructure | Storage & HPC Filesystems *(added)* | Lustre, IBM Storage Scale (GPFS), WEKA, VAST, NFS, GPUDirect Storage, dataset ingest | 7 | 1 | 3 | 3 | 0 |
| GPU & Physical Infrastructure | Facilities & Physical Security *(added)* | DCIM, BMS, PDUs / UPS, liquid cooling (CDU), leak detection, physical access control (PACS), CCTV, GPU asset custody | 10 | 3 | 6 | 1 | 0 |
| Platform & Pipeline | Container Platform | Kubernetes, OpenShift, Docker, containerd, admission controllers, service mesh | 14 | 2 | 10 | 2 | 0 |
| Platform & Pipeline | Workload Scheduling | Kubernetes scheduler, Slurm, Ray / KubeRay, distributed training orchestrators | 9 | 2 | 3 | 3 | 1 |
| Platform & Pipeline | DevSecOps | GitHub, GitLab, Azure DevOps, Jenkins, CI/CD, artifact repositories, secrets management | 10 | 0 | 9 | 1 | 0 |
| Platform & Pipeline | Endpoint & Runtime Security *(added)* | EDR / XDR on Linux GPU nodes, Falco, Tetragon, auditd, osquery, file integrity monitoring | 8 | 4 | 4 | 0 | 0 |
| Platform & Pipeline | Cloud & Hybrid Control Plane *(added)* | AWS CloudTrail, Azure Activity Log, GCP Audit Logs, GuardDuty / Defender for Cloud, IaC state, cloud GPU capacity | 9 | 3 | 5 | 1 | 0 |
| Platform & Pipeline | Multi-Tenancy & GPU Abuse *(added)* | GPU-as-a-service tenants, tenant isolation (VRF / VNI / partitions), node sanitization, quotas, billing fraud, abuse desk | 7 | 1 | 5 | 1 | 0 |
| AI Stack | AI/ML Platform | NVIDIA NIM, Triton Inference Server, vLLM, SGLang, MLflow, Kubeflow, Jupyter, model registries | 10 | 3 | 5 | 2 | 0 |
| AI Stack | AI Applications | Customer-hosted LLMs, RAG applications, inference APIs, AI agents and microservices, MCP tools | 12 | 2 | 8 | 2 | 0 |
| AI Stack | RAG & Vector Databases | Milvus, Weaviate, Pinecone, pgvector, document retrieval and embedding services | 8 | 0 | 6 | 2 | 0 |
| AI Stack | AI Gateway & Guardrails *(added)* | LLM gateways (LiteLLM, Kong AI Gateway), guardrail engines (NeMo Guardrails, Llama Guard), prompt firewalls, model routing, token budgets | 8 | 0 | 4 | 4 | 0 |
| Data & Operations | Data Protection | DLP, object storage, databases, encryption, KMS / HSM, secrets vaults | 8 | 3 | 5 | 0 | 0 |
| Data & Operations | Observability | OpenTelemetry, Prometheus, Grafana, Loki, Jaeger, platform logs and traces | 8 | 0 | 6 | 1 | 1 |
| Data & Operations | Backup & Resilience *(added)* | Backup platforms, storage snapshots, object lock / WORM, checkpoint retention, disaster recovery | 7 | 4 | 3 | 0 | 0 |
| | **Total** | | **200** | **35** | **127** | **34** | **4** |
<!-- COVERAGE:END -->

## Using the site

- Filter by domain, severity or framework, or search across names, log sources, sample logs, event IDs and technique IDs.
- Open a use case to see its detection logic and sample log. **pretty** formats JSON samples for reading, **copy log**
  copies the raw sample for parser testing, and **copy link** gives a permalink (`…/#GPU-001`).
- **CSV ↓ / JSON ↓** export the current filtered view, for example to seed a detection backlog.

## Repository layout

```
index.html              the website (single page, no build step, no framework)
usecases.json           generated data the site loads (do not edit by hand)
usecases/NN-*.yml       source of truth: one YAML file per domain
usecases/frameworks.yml names for every ATT&CK / ATLAS / OWASP ID used
scripts/build.py        validates the YAML and regenerates usecases.json + the table above
```

## Adding or editing a use case

Edit the domain's YAML file. Sample logs are YAML block scalars, so paste them verbatim without escaping:

```yaml
  - id: GPU-013                      # <CODE>-NNN, unique
    name: Short description of the behaviour
    severity: High                   # Critical | High | Medium | Low
    description: >-
      Why it matters in an AI / GPU data center.
    log_sources:
      - NVIDIA DCGM Exporter metrics
    detection: >-
      Concrete, vendor-neutral rule logic with thresholds.
    mappings: [T1496.001, AML.T0029, "LLM10:2025"]   # names come from usecases/frameworks.yml
    sample_log: |
      paste the raw event here
```

Then rebuild and preview locally (requires Python 3 and PyYAML):

```bash
pip install pyyaml
```

```bash
python3 scripts/build.py
```

```bash
python3 -m http.server 8000
```

Open http://localhost:8000. The site fetches `usecases.json`, so it has to be served over HTTP; opening
`index.html` from disk will not load the data.

`python3 scripts/build.py --check` validates without writing, and exits non-zero if `usecases.json` or this
README is out of date. The build rejects duplicate IDs, unknown severities, unmapped framework IDs and
JSON-looking sample logs that do not parse.

## Publishing

The site is static. `.github/workflows/pages.yml` publishes it to GitHub Pages on every push to `main`, and you can
re-run it by hand from the Actions tab. One-time setup: **Settings → Pages → Build and deployment → Source →
GitHub Actions**. (`.nojekyll` also keeps the site working if you switch to *Deploy from a branch → `main` / `(root)`*.)

## Notes

- Sample logs are synthetic. Hostnames, users, keys and IPs (RFC 1918 / RFC 5737 / documentation ranges) are made up.
  Formats follow each product's documented logging where possible, trimmed to the fields a detection needs, but
  fields vary by version and collector, so check them against your own parsers.
- Thresholds are starting points. Baseline your environment before turning a use case into a paging alert.
- ATLAS technique IDs and names follow ATLAS content version 2026.10. Some older IDs used elsewhere, such as
  `AML.T0024.002`, `AML.T0056` and `AML.T0057`, are not in that release.
