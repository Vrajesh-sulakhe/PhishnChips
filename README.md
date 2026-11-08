# 🐟🍟 Phish&Chips

> **Tagline:** Fresh phish, fried in a sandbox.  
> **Event:** Vultr Agent Rush Hackathon on lablab.ai  
> **Track:** **01 · Blast Radius Zero**  
> **Live Secure Production URL:** [https://139.84.159.12.sslip.io](https://139.84.159.12.sslip.io) (Auto-TLS via Let's Encrypt / Caddy)  
> **Direct Control Plane:** [http://139.84.159.12:8000](http://139.84.159.12:8000)  
> **Health Check & Telemetry:** [https://139.84.159.12.sslip.io/api/health](https://139.84.159.12.sslip.io/api/health)  
> **Prometheus Metrics:** [https://139.84.159.12.sslip.io/metrics](https://139.84.159.12.sslip.io/metrics)  
> **Public Repository:** [https://github.com/Vrajesh-sulakhe/PhishnChips](https://github.com/Vrajesh-sulakhe/PhishnChips)

---

## ⚡ Vultr Hackathon Showcase & Judge Scorecard

This section provides an immediate, verifiable mapping of **Phish&Chips** against the **Vultr Agent Rush Hackathon** guidelines, architecture requirements, and judging criteria for **Track 01: Blast Radius Zero**.

### 1. How Vultr Powers Phish&Chips

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        VULTR INFRASTRUCTURE & SERVICE MAPPING                          │
├──────────────────────────────┬─────────────────────────────────────────────────────────┤
│ Vultr Service                │ Role in Phish&Chips Solution                            │
├──────────────────────────────┼─────────────────────────────────────────────────────────┤
│ Vultr Cloud Compute (BLR)    │ Central hardened host in Bangalore (4 vCPUs / 8 GB RAM  │
│ 139.84.159.12.vultrusercontent│ / 160 GB NVMe SSD, Ubuntu 24.04 LTS). Orchestrates the  │
│                              │ FastAPI control plane, Docker cgroups v2, and Caddy.    │
├──────────────────────────────┼─────────────────────────────────────────────────────────┤
│ Vultr Serverless Inference   │ High-throughput AI threat reasoning engine via          │
│ api.vultrinference.com/v1    │ GLM-5.3 (and Qwen 2.5/3.8 multi-model fallback). Evalu- │
│                              │ ates forensic DOM telemetry, visual screenshots, and    │
│                              │ REA disassembly into strict Pydantic verdicts.          │
├──────────────────────────────┼─────────────────────────────────────────────────────────┤
│ Vultr Isolated Virtual Net   │ Dedicated `phishnet` bridge (172.30.0.0/16) with kernel-│
│ (phishnet Bridge + iptables) │ level iptables rules dropping all traffic to the host   │
│                              │ gateway, RFC1918 subnets, and cloud metadata (169.254). │
└──────────────────────────────┴─────────────────────────────────────────────────────────┘
```

### 2. Backend & Deployment Architecture

Phish&Chips operates on a **Host/Agent/Caged Sandbox** model where the host never executes untrusted code, and the untrusted code can never escape the cage:

1. **Edge Ingress & TLS Termination:** Caddy reverse proxy terminates TLS 1.3 on `139.84.159.12.sslip.io` with automated Let's Encrypt certificates and routes traffic to FastAPI on port 8000.
2. **Central Control Plane (`backend/`):** FastAPI orchestrator validates target URLs, enforces SSRF defenses against local/private IPs, manages SQLite 3 (WAL mode) telemetry, and broadcasts real-time Server-Sent Events (`/api/scan/{job_id}/stream`).
3. **Caged Sandbox Execution (`sandbox/`):** An ephemeral Docker container (`phishchips-sandbox`) is spawned on the `phishnet` bridge. A non-root user (`runner`, UID 10001) drives headless Playwright Chromium under strict cgroup limits (`--cpus=1`, `--memory=1g`, `--pids-limit=256`), with `--read-only` rootfs and `--cap-drop=ALL`.
4. **Static Reverse Engineering Engine (`backend/re_engine.py`):** On every scan, the REA engine extracts and disassembles all inline scripts, external JS routines, intercepted binary drops (`.exe`/`.bin`), and WebAssembly bytecode (`.wasm`). It computes entropy, extracts IOC strings, maps capabilities to MITRE ATT&CK tactics, and renders disassembly cards directly in the UI.
5. **Tier-2 AI Synthesis (`backend/analyzer.py`):** Structured telemetry and screenshots are dispatched to Vultr Serverless Inference (`api.vultrinference.com/v1`) using model `glm-5.3`. The model validates against strict Pydantic schemas (`backend/schemas.py`) and outputs actionable indicators, confidence scores, and brand impersonation vectors.
6. **Destruction & Janitor:** The ephemeral container is destroyed via `--rm` and finally blocks. A background janitor purges stale artifacts, leaving a final verified log: `🍟 Phish fried. Sandbox destroyed.`

### 3. Agent Use Case & Real Task Execution

- **The Problem:** Modern phishing attacks (fake KYC notifications, UPI refund portals, banking clones, malicious invoice drops) evade traditional static blocklists by using ephemeral subdomains, client-side JavaScript obfuscation, and dynamic browser sniffing.
- **The Agentic Workflow:** Phish&Chips acts as an autonomous threat intelligence agent:
  - **Task 1: Safe Autonomous Detonation:** Intercepts untrusted URLs, opens them inside a quarantined browser, and records every redirect hop, network request, visual render, and console error.
  - **Task 2: Active Credential Harvesting Discovery:** Dissects DOM inputs. If credential/OTP fields are detected, it pauses and prompts the operator (**Pattern B: Human Authorization Decoy Pass**) to inject synthetic canary data and trace the attacker's exfiltration C2 server.
  - **Task 3: Automated Payload Quenching:** Detects drive-by downloads or payload injection, captures the dropped artifact into an isolated temporary volume, runs static analysis and entropy checks without executing binary code, and reports the SHA-256 hash.
  - **Task 4: 1-Click Takedown & Incident Escalation:** Auto-generates a signed legal takedown package (`.tar.gz` evidence locker) for hosting providers and registrar abuse desks, complete with screenshots, HAR recordings, and direct links to India's National Cybercrime Portal (`1930`).

### 4. Challenge 1: The Mandatory Containment Moment

In Track 01 (**Blast Radius Zero**), containment is not an afterthought—it is the core deliverable. Phish&Chips exhibits **two explicit, verifiable containment moments**:

#### Containment Moment 1: Kernel-Enforced Network Isolation
From inside the active container on the `phishnet` bridge (`172.30.0.0/16`), iptables strictly blocks any attempt to reach the host gateway, host public IP, internal RFC1918 networks, or cloud metadata endpoints (`169.254.169.254`).
```bash
# Verify containment on live production host:
curl -s https://139.84.159.12.sslip.io/api/health | jq .iptables_phishnet
# Returns: "Enforced (Host & RFC1918 Dropped)"
```
Verification script execution (`scripts/verify_containment.sh`):
```text
  Testing Public Internet (Cloudflare 1.1.1.1) ...  [PASS] REACHABLE (HTTP 301)
  Testing Host Bridge Gateway (172.30.0.1:8000) ... [PASS] BLOCKED (Code: 28)
  Testing Host Public IP (139.84.159.12:8000) ...   [PASS] BLOCKED (Code: 28)
  Testing Cloud Metadata (169.254.169.254) ...      [PASS] BLOCKED (Code: 28)
  Testing Private Subnet 10.0.0.1 ...               [PASS] BLOCKED (Code: 28)
  Testing Private Subnet 192.168.1.1 ...            [PASS] BLOCKED (Code: 28)
  🎉 ALL CONTAINMENT CHECKS PASSED. Blast Radius Zero verified!
```

#### Containment Moment 2: Intercepted Drive-By Malware Quarantine
When a phishing site attempts to drop an executable payload (e.g. `SBI_Mandatory_Security_Patch.exe`) or inject WebAssembly (`.wasm`), Playwright's download handler intercepts the file stream, cancels execution, and saves it directly to an isolated `/out` quarantine volume. The REA Engine inspects the PE headers, calculates entropy ($> 7.5 = \text{packed/encrypted}$), extracts IOC strings, and flags MITRE `T1204.002: Malicious File`, all with **zero execution of binary bytes**.

### 5. Alignment with Hackathon Judging Criteria

| Criteria | Hackathon Evaluation Standard | Phish&Chips Implementation & Evidence |
|:---|:---|:---|
| **Application of Technology** | Effective integration of chosen models and cloud infrastructure | Hardened **Vultr Cloud Compute** VM hosting the FastAPI control plane + Caddy reverse proxy; **Vultr Serverless Inference** powering deep threat reasoning via **GLM-5.3**; Playwright headless browser in cgroups v2; Prometheus `/metrics` telemetry. |
| **Presentation** | Clarity and effectiveness of project presentation and UX | Production web UI at [139.84.159.12.sslip.io](https://139.84.159.12.sslip.io) featuring an **animated 4-node pipeline graph**, live streaming SSE containment terminal, visual screenshot carousel, REA disassembly view, and dark cyber aesthetic. |
| **Business Value** | Practical impact and fit in real-world business domains | Resolves the \$10B credential phishing crisis for enterprises, SOC teams, and everyday users. Eliminates analyst fatigue and false positives via Tranco Top-10K fast-path; provides instant legal `.tar.gz` evidence lockers and emergency `1930` cybercrime escalation. |
| **Originality** | Uniqueness, creativity, and demonstration of agentic behaviors | **Blast Radius Zero** architecture; **Pattern B Human Approval Decoy Pass** allowing controlled canary injection; built-in static reverse engineering (REA) for JavaScript, WASM, and PE binaries; trilingual Indian localization (English/Hindi/Kannada). |

---  

---

## 1. Executive Summary

**Phish&Chips** is an ephemeral detonation and threat analysis platform that allows anyone to inspect suspicious links (fake KYC updates, UPI refund scams, banking portals, malicious file delivery) **without ever opening the link on their own device or touching the host operating system**.

Every scan triggers a locked-down, unprivileged Docker container (`phishchips-sandbox`) launched on a hardened **Vultr Cloud Compute VM** (Bangalore, 4 vCPUs, 8192 MB RAM, 160 GB SSD). A sandboxed headless Chromium browser detonates the target URL, intercepts redirect chains, captures visual proof, blocks automatic file downloads, and records all DOM inputs. 

The collected telemetry and screenshots are evaluated using a vision-capable model on **Vultr Serverless Inference** combined with a brand impersonation and heuristic rules engine. Once analysis completes, the container is **immediately destroyed** and the user is presented with a **Verdict Card** (Safe / Suspicious / Scam), a screenshot timeline, and a verifiable **Containment Log** concluding with:

```text
🍟 Phish fried. Sandbox destroyed.
```

---

## 2. Architecture & Blast Radius Zero Perimeter

```mermaid
flowchart TD
    User["User Browser / Mobile Device"] -->|"HTTPS / TLS 1.3"| Caddy["Caddy Reverse Proxy\n(139.84.159.12.sslip.io)"]
    Caddy -->|"Reverse Proxy"| FastAPI["FastAPI Orchestrator (Vultr VM)\nPort 8000 (Central Control Plane)"]
    
    subgraph HostVM ["Vultr Cloud Compute Host (Bangalore)"]
        FastAPI -->|"Input Validation & SSRF Shield"| Validation["validation.py"]
        FastAPI -->|"SSE Event Broadcaster & Janitor"| Events["events.py"]
        FastAPI -->|"Docker Exec (Full Containment Flags)"| DockerDaemon["Docker Runtime (cgroups v2)"]
        
        subgraph IsolatedNet ["Network Perimeter: phishnet (172.30.0.0/16)"]
            subgraph Sandbox ["Ephemeral Container (phishchips-sandbox)"]
                Inspector["inspector.py (User: runner, UID 10001)\nPlaywright Headless Chromium"]
                TmpfsHome["/home/runner (tmpfs rw, 256MB)"]
                TmpfsTmp["/tmp (tmpfs rw, 256MB)"]
                ReadOnlyRoot["Root Filesystem (READ-ONLY)"]
                OutMount["/out (Per-job Mount, rw)"]
            end
            
            IPTablesHost["iptables: INPUT -s 172.30.0.0/16 -j DROP\n(Host & Gateway Blocked)"]
            IPTablesPrivate["iptables: DOCKER-USER -d 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 -j DROP\n(RFC1918 Private Ranges Blocked)"]
            IPTablesMeta["iptables: DOCKER-USER -d 169.254.0.0/16 -j DROP\n(Cloud Metadata Blocked)"]
        end
    end

    Sandbox -->|"Public Web Traffic ONLY"| TargetSite["Untrusted Target Link / Web Server"]
    Sandbox -.->|"Auto-downloads & Popups"| Blocked["Intercepted & Blocked by Playwright"]
    
    FastAPI -->|"OpenAI SDK /api.vultrinference.com/v1"| VultrInference["Vultr Serverless Inference\n(Vision / Chat Threat Engine)"]
    FastAPI -->|"Brand-vs-Domain Mismatch Heuristics"| Heuristics["heuristics.py"]
```

---

## 3. Real-Time Orchestration Pipeline & Interactive Control Plane

To clearly demonstrate that Vultr acts as the central orchestration and control plane:

1. **Animated Pipeline Node Graph:** Directly on the dashboard, a 4-stage animated node graph illustrates the execution flow:
   `[User Client]` $\rightarrow$ `[Vultr VM Host Control Plane]` $\rightarrow$ `[phishnet Caged Sandbox]` $\rightarrow$ `[Vultr Serverless Inference]`.
2. **Server-Sent Events (SSE) Streaming:** The endpoint `GET /api/scan/{job_id}/stream` streams structured execution stages (`SANDBOX_INIT`, `CAP_DROP`, `NAVIGATING`, `INTERCEPT`, `EVIDENCE_COLLECTED`, `AWAITING_APPROVAL`, `INFERENCE_DISPATCH`, `DONE`) in real time, animating the nodes and streaming the containment terminal line-by-line.
3. **Live Control Plane Telemetry:** The dynamic host status pill polls `/api/health` to report active sandbox concurrency slots (`0 / 3 Active`), iptables network perimeter status, and Vultr Inference connectivity.

---

## 4. The 4 Non-Negotiable Containment Guarantees

In accordance with Track 01 criteria (**Blast Radius Zero**), containment is the product:

| Guarantee | Technical Implementation & Boundary Proof |
|---|---|
| **1. Process Isolation** | Execution occurs strictly inside throwaway Docker containers under an unprivileged user (`runner`, UID 10001). Linux capabilities are completely stripped via `--cap-drop=ALL` and privilege escalation is prevented with `--security-opt=no-new-privileges`. Root filesystem is `--read-only`. |
| **2. Secret Hygiene** | Zero API keys, SSH keys, or cloud credentials ever enter the sandbox container. Only `TARGET_URL` and non-sensitive flags are passed via environment variables. The Docker socket is never mounted. |
| **3. Hard Resource Limits** | Hard Linux cgroup limits enforce `--cpus=1`, `--memory=1g`, `--memory-swap=1g`, and `--pids-limit=256`. The FastAPI orchestrator enforces a hard 45-second wall-clock kill switch (`docker kill` & `docker rm -f`). |
| **4. Lifecycle Discipline** | Every sandbox container is destroyed immediately after telemetry collection (`--rm` + automated cleanup in finally blocks). A background janitor purges any orphan containers and retains job artifacts strictly for the retention period. |

---

## 5. Pattern B: Sandboxed Browser Use with Human Approval

Phish&Chips implements the hackathon's required **Pattern B** workflow:

1. **Pass 1 (Passive Reconnaissance):** The sandbox opens the target link, observes redirects, captures visual screenshots (`shot1.png`, `shot2.png`), inspects the DOM, and checks for credential forms.
2. **Human Approval Gate:** If login, password, OTP, or payment card fields are detected, the orchestrator pauses and transitions job status to `awaiting_approval`. The UI presents the user with an interactive decision modal:
   > *"Credential harvester detected. Authorize unprivileged container to inject decoy canary credentials to observe post-submission routing? [Authorize Decoy Submit] / [Terminate & Finalize Verdict]"*
3. **Pass 2 (Simulated Canary Submission):**
   - **User authorizes:** A second ephemeral container launches with `SUBMIT_PASS=1`. The browser populates synthetic decoy values (`test_canary_user@example.com`, `FakePassword123!`, `123456`) and clicks submit to observe where the data exfiltrates. Post-submit screenshots and redirect URLs are captured.
   - **User terminates:** The orchestrator skips submission and proceeds directly to threat synthesis using Pass 1 evidence.

---

## 6. Indian Regional Localization & Emergency Incident Escalation

- **Regional Localization:** Integrated one-click language toggle (**English / हिन्दी / ಕನ್ನಡ**) to cater to native language speakers frequently targeted by fake KYC and parcel scams in India.
- **Incident Escalation Drawer:** When a `SCAM` or `SUSPICIOUS` verdict is confirmed:
  - Direct 1-tap link to the **National Cyber Crime Reporting Portal** (`cybercrime.gov.in`).
  - Direct dialer to the **National Financial Fraud Helpline** (`1930`).
  - Emergency bank profile freeze checklist.

---

## 7. Verifiable Containment Verification

An automated verification test script ([scripts/verify_containment.sh](file:///root/phish-n-chips/scripts/verify_containment.sh)) proves from inside an active container that isolation holds:

```bash
# Execute containment verification suite on the host VM
bash scripts/verify_containment.sh
```

**Verification Output:**
```text
==========================================================
    PHISH&CHIPS: CONTAINMENT PERIMETER VERIFICATION       
==========================================================
Starting ephemeral verification container in phishnet...
  Testing Public Internet (Cloudflare 1.1.1.1) ...  [PASS] REACHABLE (HTTP 301)
  Testing Public Internet (Example.com) ...         [PASS] REACHABLE (HTTP 200)
  Testing Host Bridge Gateway (172.30.0.1:8000) ... [PASS] BLOCKED (Code: 28)
  Testing Host Public IP (139.84.159.12:8000) ...   [PASS] BLOCKED (Code: 28)
  Testing Cloud Metadata (169.254.169.254) ...      [PASS] BLOCKED (Code: 28)
  Testing Private Subnet 10.0.0.1 ...               [PASS] BLOCKED (Code: 28)
  Testing Private Subnet 192.168.1.1 ...            [PASS] BLOCKED (Code: 28)
----------------------------------------------------------
🎉 ALL CONTAINMENT CHECKS PASSED. Blast Radius Zero verified!
```

---

## 8. Repository Layout

```text
phish-and-chips/
├── README.md                 # Product documentation, architecture, and containment proofs
├── PROJECT_BRIEF.md          # Official hackathon brief & rules
├── .env.example              # Environment variables template
├── .gitignore                # Secret & artifact exclusion rules
├── deploy.sh                 # 1-click deployment & rebuild script
├── backend/
│   ├── main.py               # FastAPI orchestrator, SSE streaming, REST routes
│   ├── scanner.py            # Docker lifecycle, cgroups limits, janitor & approval gate
│   ├── analyzer.py           # Vultr Serverless Inference integration + fallback logic
│   ├── heuristics.py         # Brand-vs-domain rules & credential harvesting detection
│   ├── events.py             # Structured timestamped containment event logging & SSE
│   ├── validation.py         # URL validation, SSRF blocking & sliding-window rate limiter
│   └── requirements.txt      # Python backend dependencies
├── sandbox/
│   ├── Dockerfile            # Python 3.12 + Playwright Chromium sandbox image
│   ├── inspector.py          # Non-root browser automation & telemetry extraction
│   └── bank_login.html       # Self-contained demo asset
├── frontend/
│   ├── index.html            # Monospace dark-mode dashboard with pipeline graph & terminal
│   ├── app.js                # SSE stream consumer, node graph animator & approval modal
│   └── styles.css            # Cyber monospace styling & animated SVG paths
├── scripts/
│   ├── setup_network.sh      # Idempotent phishnet bridge & iptables containment setup
│   └── verify_containment.sh # Automated isolation proof script
├── demo/
│   └── fake-pages/           # Harmless fake phishing pages for video demonstration
└── deploy/
    └── phishchips.service    # systemd unit configuration for production runtime
```

---

## 9. 1-Click Deployment to Vultr VM

The included `deploy.sh` script executes a 1-command sync, build, dependency installation, Caddy reload, and systemd service reload over SSH:

```bash
./deploy.sh
```

---

## 10. License

Built for the **Vultr Agent Rush Hackathon** (November 2026).  
*Fresh phish, fried in a sandbox.* 🐟🍟

---

## Detection Pipeline (two-tier) & False-Positive Controls

```
URL -> validate/SSRF -> queue -> Docker sandbox (Playwright, stealth, behavioural interception)
    -> Tier 1: reputation gate (Tranco top-10K, user-content hosts excluded) + physical-signal heuristics
         reputable apex, landed on itself, no anomaly  -> BENIGN (model never consulted)
    -> Tier 2: reasoning model w/ rich evidence + screenshot -> strict Pydantic schema -> reconcile
    -> verdict: benign | suspicious | malicious | indeterminate   (+ confidence, indicators, evidence_chain)
```

* **Only physical evidence can convict.** `malicious` needs a hard signal (credential form posting off-site, brand mimicry *with* credential capture, covert download, off-apex redirect from a trusted origin, injected login UI). Lexical hints (TLD, URL length/edit tokens, brand words, hop count) can reach `suspicious` at most.
* **The model cannot convict alone**, and cannot return free text: output must validate against `backend/schemas.py`.
* **Failures are never malicious.** Timeout (20s end-to-end budget), API error, rate limit, schema drift or analyzer crash produce `indeterminate` (Analysis Incomplete, Retry / Manual Review).
* **Observability:** `GET /metrics` (Prometheus) and `GET /api/health`; one JSON log line per scan; the exact model payload is saved to `evidence/<job>/inference_payload.json`.
* **Tests:** `cd backend && pip install -r requirements-dev.txt && pytest -q` (unit + 500/500 golden gate, FPR must be < 0.1%). Regenerate fixtures with `python tests/golden/build_golden.py`; live containerised run: `python tests/golden/run_golden.py --live urls.csv`.
* Rebuild the sandbox image after pulling (`docker build -t phishchips-sandbox sandbox/`) to pick up the hardened inspector.
