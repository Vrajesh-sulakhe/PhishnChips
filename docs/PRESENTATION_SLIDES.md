# 🐟🍟 Phish&Chips: Presentation Slide Deck
## Vultr Agent Rush Hackathon · Track 01: Blast Radius Zero
**Team:** `alphax`  
**Live Production URL:** [https://139.84.159.12.sslip.io](https://139.84.159.12.sslip.io)  
**Public Repository:** [https://github.com/Vrajesh-sulakhe/PhishnChips](https://github.com/Vrajesh-sulakhe/PhishnChips)

---

## Slide 1: Title & Vision
### Phish&Chips: Ephemeral Sandboxed Detonation & Threat Intelligence Agent
*Fresh phish, fried in a sandbox.*

- **The Challenge:** Track 01 · Blast Radius Zero
- **Core Principle:** Any untrusted link detonates in an isolated, throwaway browser that cannot harm the host, read credentials, or infect the analyst.
- **Powered By:** Vultr Cloud Compute (Bangalore) + Vultr Serverless Inference (`glm-5.3`)
- **Presented By:** Team `alphax`

> **Speaker Notes:**
> "Hello judges and fellow builders! Welcome to Phish&Chips: an autonomous, ephemeral detonation and threat analysis platform. In an era where phishing attacks bypass traditional static blocklists in minutes, Phish&Chips introduces Blast Radius Zero — an agentic sandbox running on Vultr Cloud Compute that safely visits untrusted links, reverses malicious scripts and binary drops, executes controlled canary submissions, and synthesizes deep threat verdicts using Vultr Serverless Inference."

---

## Slide 2: The Problem
### The $10B Phishing Crisis & The Analyst Dilemma
- **Ephemeral Infrastructure:** Phishing sites stay alive for an average of 4 to 8 hours, rendering traditional URL blocklists and reputation feeds obsolete.
- **Client-Side Evasion:** Attackers employ fingerprinting, JavaScript packing, dynamic DOM injection, and regional localization (fake KYC, UPI payment portals).
- **Drive-by Malware Delivery:** Attackers spoof login screens while silently dropping disguised executables (`.exe`) or WebAssembly hooks (`.wasm`).
- **Analyst Vulnerability:** Security teams and non-technical users risk host infection, credential compromise, or lateral movement whenever they inspect suspicious links.

> **Speaker Notes:**
> "Every day, millions of people receive deceptive SMS messages, UPI refund links, or urgent KYC verification alerts. Traditional blocklists are too slow because attackers spin up new domains constantly. But opening these links to inspect them is dangerous — they fingerprint your browser, download malicious executables, or steal sensitive tokens. How do we inspect untrusted links without putting ourselves or our infrastructure at risk?"

---

## Slide 3: The Solution
### Blast Radius Zero: Containment-First Agentic Architecture
- **Zero Host Risk:** Untrusted links are opened inside throwaway Docker containers with stripped Linux capabilities (`--cap-drop=ALL`) and read-only filesystems.
- **Strict Network Perimeter:** The dedicated `phishnet` bridge uses iptables to completely drop all traffic to host services, RFC1918 private subnets, and cloud metadata.
- **Autonomous Playwright Detonation:** Headless Chromium drives human-like interaction, records network requests, intercepts redirects, and captures visual proof.
- **Guaranteed Ephemerality:** Every sandbox container is destroyed immediately after inspection:
  $$\text{Container Lifetime} \le 45\text{s} \quad \longrightarrow \quad \text{Destroyed via } \texttt{--rm}$$

> **Speaker Notes:**
> "The answer is Blast Radius Zero. Phish&Chips treats every URL as hostile. When a link is submitted, our FastAPI control plane on a hardened Vultr Cloud Compute VM spins up an isolated, unprivileged Playwright container on a custom 'phishnet' bridge. The sandbox is completely walled off by kernel iptables rules: it cannot touch the host, internal private subnets, or cloud metadata. Once evidence is gathered, the container is destroyed instantly."

---

## Slide 4: System Architecture
### End-to-End Orchestration on Vultr Infrastructure

```
┌──────────────────┐       HTTPS / TLS 1.3        ┌────────────────────────────┐
│   User Browser   │ ───────────────────────────> │     Caddy Reverse Proxy    │
└──────────────────┘                              └─────────────┬──────────────┘
                                                                │
                                                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                    VULTR CLOUD COMPUTE VM (Bangalore)                        │
│                                                                              │
│   FastAPI Control Plane (Port 8000)                                          │
│   ├── Input Validation & SSRF Guard (Blocks local/private IPs)               │
│   ├── SSE Real-time Event Broadcaster (/api/scan/{job_id}/stream)            │
│   ├── SQLite 3 WAL Telemetry Storage & Concurrency Slot Governor             │
│   └── REA Static Reverse-Engineering Engine                                  │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │ Network Perimeter: phishnet (172.30.0.0/16)                          │   │
│   │ iptables: Host Bridge Gateway DROPPED · Metadata 169.254 DROPPED     │   │
│   │                                                                      │   │
│   │   Ephemeral Sandbox Container (phishchips-sandbox)                   │   │
│   │   ├── User: runner (UID 10001) | --cap-drop=ALL | --read-only        │   │
│   │   ├── Headless Chromium + Stealth Driver                             │   │
│   │   ├── Automatic Download Interceptor & File Quencher                 │   │
│   │   └── Resource Cgroups: 1 vCPU, 1 GB RAM, 256 PIDs                   │   │
│   └──────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │ JSON Evidence + Visual Screenshot
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│            VULTR SERVERLESS INFERENCE (api.vultrinference.com/v1)            │
│                 Model: GLM-5.3 Flagship Reasoning Engine                      │
│                 Strict Pydantic Schema Validation & MITRE Mapping             │
└──────────────────────────────────────────────────────────────────────────────┘
```

> **Speaker Notes:**
> "Here is our full architecture. At the perimeter, Caddy handles automated TLS on 139.84.159.12.sslip.io. The FastAPI control plane validates the input, executes SSRF checks, and spins up the caged sandbox container. The container detonate the site, intercepts network requests, and collects forensic artifacts. That evidence is then sent directly to Vultr Serverless Inference running GLM-5.3 for deep reasoning, producing structured Pydantic verdicts with MITRE ATT&CK tactics."

---

## Slide 5: The Containment Moment (Challenge 1)
### Double-Perimeter Blast Radius Zero Verification
1. **Perimeter 1: Kernel-Level Network Lockdown**
   - Active containers are forbidden from pinging or querying the host gateway (`172.30.0.1:8000`), host public IP (`139.84.159.12`), or cloud metadata (`169.254.169.254`).
   - Verified via automated test suite `scripts/verify_containment.sh` (100% PASS).
2. **Perimeter 2: Drive-By Malware Interception & REA Disassembly**
   - When phishing pages attempt drive-by downloads (e.g. `SBI_Mandatory_Security_Patch.exe`), Playwright quenches the download stream.
   - The file is stored in an isolated volume, hashed (SHA-256), and analyzed for entropy without running executable bytes.
   - WebAssembly binaries (`.wasm`) and client-side JavaScript are decompiled and inspected for exfiltration hooks.

> **Speaker Notes:**
> "For Challenge 1, we demonstrate our dual Containment Moment. First, our automated verification script proves that any network request from the sandbox to the host gateway, private subnets, or Vultr metadata is immediately dropped at the kernel level by iptables. Second, when a phishing site triggers an automated malware download — such as a fake SBI banking security patch — our browser interceptor traps the file instantly. The executable is quarantined, hashed, and disassembled by our REA engine without a single instruction ever executing on the host."

---

## Slide 6: Pattern B & Advanced Agentic Features
### Sandboxed Browser Interaction with Human-in-the-Loop Gate
- **Pass 1: Passive Reconnaissance**
  - Spawns sandbox, renders page, detects brand logos, and identifies login/password/OTP fields.
- **Human Approval Gate (Pattern B)**
  - If a credential harvester is detected, the agent pauses:
  - *"Credential harvester detected. Authorize unprivileged container to inject decoy canary credentials to observe post-submission routing?"*
- **Pass 2: Synthetic Decoy Submission**
  - Upon user authorization, the unprivileged browser populates fake canary credentials (`test_canary_user@example.com`, `FakePassword123!`) and submits the form to track exfiltration endpoints and C2 servers.
- **Reputation Fast-Path (Zero False Positives):**
  - Tranco Top-10K reputable domains (Wikipedia, Google, Gov portals) complete within 5 seconds with guaranteed `SAFE` verdicts, eliminating model hallucinations.

> **Speaker Notes:**
> "Phish&Chips implements the hackathon's required Pattern B workflow. In Pass 1, the agent navigates passively. When it spots a credential harvesting form, it stops and requests human authorization. If approved, Pass 2 fires: the agent submits synthetic decoy credentials to observe where the data exfiltrates, capturing post-submit redirection and server-side behavior. Furthermore, our Tranco Top-10K reputation fast-path ensures that benign sites like Wikipedia are classified in seconds with zero false positives."

---

## Slide 7: Real-World Impact & Regional Escalation
### From Threat Detection to Remediation in Seconds
- **1-Click Abuse Takedown:** Generates a cryptographically signed `.tar.gz` Evidence Locker containing full screenshots, HAR network recordings, DOM dumps, and registrar abuse contact details.
- **Indian Regional Localization:** Full multilingual support in **English, हिन्दी (Hindi), and ಕನ್ನಡ (Kannada)** for frontline victims of fake KYC and postal scams.
- **Emergency Incident Escalation:** Direct 1-tap dialer for the **National Cybercrime Helpline (`1930`)** and direct reporting to `cybercrime.gov.in`.
- **Production Observability:** Native Prometheus `/metrics` endpoint tracking scan throughput, engine latency, and sandbox lifecycle stats.

> **Speaker Notes:**
> "Detection is only half the battle. Phish&Chips provides immediate remediation: a 1-click Abuse Takedown pack that SOC analysts can send to domain registrars, and a localized emergency drawer for Indian users featuring the 1930 National Cybercrime Helpline. It's trilingual, fully observable via Prometheus metrics, and ready for production deployment."

---

## Slide 8: Summary & Conclusion
### Why Phish&Chips Wins the Vultr Agent Rush
- **Application of Technology:** 100% production-ready on Vultr Cloud Compute (Bangalore) with Vultr Serverless Inference (`glm-5.3`) and hardened Docker sandbox.
- **Presentation:** High-impact UI with live SSE containment logs, animated pipeline graph, and 3-minute video demonstration.
- **Business Value:** Shields organizations and citizens from multi-billion dollar fraud with zero host exposure.
- **Originality:** Blast Radius Zero + Pattern B Decoy Pass + Static REA Disassembly.

**Live URL:** [https://139.84.159.12.sslip.io](https://139.84.159.12.sslip.io)  
**Try it now:** Click any demo preset (`demo://fake-bank`, `https://wikipedia.org`) and watch the phish get fried!

> **Speaker Notes:**
> "Phish&Chips proves that autonomous AI agents can handle hazardous security tasks safely and effectively when built on solid cloud infrastructure. Thank you to Vultr and LabLab for this incredible challenge. Remember: fresh phish, fried in a sandbox. Thank you!"