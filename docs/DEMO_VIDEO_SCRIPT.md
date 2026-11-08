# 🎬 Phish&Chips: 3-Minute Demo Video Recording Script
## Vultr Agent Rush Hackathon · Track 01: Blast Radius Zero
**Target Length:** 3:00 minutes (180 seconds)  
**Live URL to Record:** [https://139.84.159.12.sslip.io](https://139.84.159.12.sslip.io)  
**Alternative Terminal/SSH Tab:** Logged in to the Vultr VM (`ssh root@139.84.159.12`) to show `verify_containment.sh`

---

## Pre-Recording Checklist
1. **Screen Resolution:** 1920x1080 (1080p).
2. **Browser Window 1:** Open [https://139.84.159.12.sslip.io](https://139.84.159.12.sslip.io) in Full Screen or clean window (Chrome or Arc).
3. **Browser Window 2:** Open [https://139.84.159.12.sslip.io/api/health](https://139.84.159.12.sslip.io/api/health) and [https://139.84.159.12.sslip.io/metrics](https://139.84.159.12.sslip.io/metrics) in separate tabs for quick 5-second proof.
4. **Terminal Tab (Optional but high impact):** A terminal window ready with `bash scripts/verify_containment.sh`.
5. **Microphone Check:** Clear audio with no background noise.

---

## Scene-by-Scene Timed Walkthrough

### Act 1: The Hook & Blast Radius Zero (0:00 – 0:30)
- **Time:** `0:00 – 0:30` (30 seconds)
- **Screen Action:**
  - Show the Phish&Chips homepage at `https://139.84.159.12.sslip.io`.
  - Point mouse cursor to the top header showing the active status pill: `🟢 0 / 3 Active · phishnet (172.30.0.0/16) · Vultr Cloud Compute (BLR)`.
  - Show the animated 4-stage pipeline graph: `User Client -> Vultr VM Host Control Plane -> phishnet Caged Sandbox -> Vultr Serverless Inference`.
- **Spoken Narration:**
  > "Welcome to Phish&Chips. We built this for Track 01: Blast Radius Zero of the Vultr Agent Rush Hackathon.
  >
  > Every day, users receive deceptive links — fake banking portals, urgent KYC verifications, and delivery scams. But clicking on them is hazardous: they steal credentials and drop malware.
  >
  > Phish&Chips solves this by orchestrating an unprivileged, throwaway browser inside a hardened Docker container on Vultr Cloud Compute in Bangalore. Every scan has Blast Radius Zero — isolated from the host, stripped of all privileges, and destroyed immediately after detonation."
- **Judge Cue:** Demonstrates Vultr infrastructure, problem statement, and Track 01 alignment.

---

### Act 2: Challenge 1 — The Containment Moment & Malware Interception (0:30 – 1:15)
- **Time:** `0:30 – 1:15` (45 seconds)
- **Screen Action:**
  - Click the **"Bank login"** quick-preset button (`demo://fake-bank`).
  - Click the red **"DETONATE URL"** button.
  - Watch the live Server-Sent Events (SSE) containment terminal stream line by line:
    - Node graph lights up dynamically: `CONTROL PLANE` (active) $\rightarrow$ `CAGED SANDBOX` (active).
    - Terminal prints:
      `[CAGED SANDBOX] User: runner (UID 10001) | --cap-drop=ALL | --read-only rootfs`
      `[NETWORK PERIMETER] Host gateway & RFC1918 traffic dropped via iptables`
      `[INTERCEPT] Blocked drive-by download: SBI_Mandatory_Security_Patch.exe`
  - *(Optional 5-second cut)*: Show the terminal running `bash scripts/verify_containment.sh` showing all gateway and private IP tests `[BLOCKED]`.
- **Spoken Narration:**
  > "Let's detonate a hostile banking credential harvester and malware dropper.
  >
  > Watch the live terminal: our FastAPI control plane deploys an ephemeral sandbox on an isolated bridge called 'phishnet'. Notice our first Containment Moment: Linux capabilities are stripped with `--cap-drop=ALL`, the filesystem is read-only, and iptables drops any attempt to touch the host gateway or cloud metadata.
  >
  > Now look at the interceptor: the phishing site immediately tried to trigger an automatic drive-by download of a fake executable called `SBI_Mandatory_Security_Patch.exe`. Playwright intercepted and quenched the stream instantly. The file was quarantined with zero code execution on the host. That is Blast Radius Zero in action."
- **Judge Cue:** **Fulfills Challenge 1 Mandatory Requirement: Containment Moment explicitly demonstrated!**

---

### Act 3: Pattern B — The Human Approval Decoy Pass (1:15 – 1:50)
- **Time:** `1:15 – 1:50` (35 seconds)
- **Screen Action:**
  - The scan pauses and a highlighted red authorization modal/banner appears:
    `⚠️ Credential harvester detected (Username & Password fields). Authorize unprivileged container to inject decoy canary credentials to observe post-submission routing?`
  - Click **"Authorize Decoy Submit"**.
  - The terminal logs:
    `[PATTERN B] Decoy pass authorized by operator.`
    `[CANARY] Populating synthetic credentials: test_canary_user@example.com`
    `[EXFILTRATION] POST captured -> https://scam-c2-collector.xyz/login.php`
- **Spoken Narration:**
  > "Here is our agentic workflow implementing Pattern B: Sandboxed Browser Use with Human Approval.
  >
  > In Pass 1, the agent observed username and password input fields. Rather than blindly submitting data, it paused and asked for operator approval.
  >
  > I'll click 'Authorize Decoy Submit'. The unprivileged sandbox injects synthetic canary credentials and clicks submit, revealing the attacker's true exfiltration endpoint without ever leaking real user data."
- **Judge Cue:** Demonstrates compliance with the hackathon's required Pattern B Human-in-the-Loop workflow.

---

### Act 4: REA Engine Disassembly & GLM-5.3 AI Reasoning (1:50 – 2:30)
- **Time:** `1:50 – 2:30` (40 seconds)
- **Screen Action:**
  - The scan completes and prints: `🍟 Phish fried. Sandbox destroyed.`
  - Scroll down to show:
    1. **Visual Screenshot Carousel:** Rendered login page with warning overlays.
    2. **REA Disassembly Card:** Shows `client_dom_scripts.js`, entropy `7.82` (packed), MITRE ATT&CK tactics (`T1056: Input Capture`, `T1071: Exfiltration Over C2`, `T1204: Malicious File`).
    3. **AI Verdict Card:** Verdict: `SCAM`, Confidence: `98%`, Threat Classification: `Credential Harvester & Malware Dropper`, powered by **Vultr Serverless Inference (`glm-5.3`)**.
- **Spoken Narration:**
  > "Notice the final log line: 'Phish fried. Sandbox destroyed.' The container is gone.
  >
  > On the result card, our Reverse Engineering Anything — or REA — engine extracted every inline script and disassembled the intercepted `.exe` and WebAssembly routines. It calculated entropy, extracted IOC strings, and mapped the attack to MITRE ATT&CK tactics.
  >
  > Finally, all forensic telemetry was dispatched to Vultr Serverless Inference using the flagship GLM-5.3 model, which synthesized the 98% confidence SCAM verdict with complete reasoning."
- **Judge Cue:** Demonstrates Vultr Serverless Inference integration, REA Engine, and threat intelligence depth.

---

### Act 5: Zero False Positives & Regional Remediation (2:30 – 3:00)
- **Time:** `2:30 – 3:00` (30 seconds)
- **Screen Action:**
  - Click **"Back to workspace"**. Click the **"Wikipedia"** preset (`https://wikipedia.org`) and hit Detonate.
  - Show how it completes in under 5 seconds with a `SAFE` verdict (Tranco Top-10K fast path, zero false positives).
  - Show the **"1-Click Abuse Takedown"** button and the **Incident Escalation Drawer** with the **1930 National Cybercrime Helpline** and the language toggle (**English / हिन्दी / ಕನ್ನಡ**).
- **Spoken Narration:**
  > "Crucially, Phish&Chips eliminates false positives. Detonating a trusted site like Wikipedia completes in under 5 seconds via our Tranco Top-10K reputation fast-path with zero model hallucination.
  >
  > For confirmed scams, we generate a 1-click legal takedown package and provide an emergency escalation drawer for Indian citizens featuring the 1930 Cybercrime Helpline and trilingual support.
  >
  > Phish&Chips is deployed, fully functional, and live right now. Thank you Vultr and LabLab!"
- **Judge Cue:** Demonstrates false-positive controls, business value, regional localization, and operational readiness.

---

## Summary of Video Timestamps
| Time | Segment | Core Highlight |
|---|---|---|
| `0:00 - 0:30` | Overview & Architecture | Vultr Cloud Compute host + Blast Radius Zero |
| `0:30 - 1:15` | **Challenge 1: Containment Moment** | Caged sandbox + Malware drop interception |
| `1:15 - 1:50` | Pattern B Workflow | Credential discovery & Human approval decoy pass |
| `1:50 - 2:30` | REA & Vultr Inference | Static disassembly + GLM-5.3 AI threat synthesis |
| `2:30 - 3:00` | Remediation & Wrap-up | Zero false positives, 1930 hotline, live URL |