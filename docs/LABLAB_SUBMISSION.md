# 📋 LabLab Submission Package: Phish&Chips
## Vultr Agent Rush Hackathon · Track 01: Blast Radius Zero
**Submission Portal:** [https://lablab.build/ai-hackathons/vultr-hackathon/alphax/submission](https://lablab.build/ai-hackathons/vultr-hackathon/alphax/submission)  
**Team Name:** `alphax`  
**Track:** 01 · Blast Radius Zero  

Use the exact copy-paste blocks below to populate your official LabLab project submission form.

---

### Field 1: Project Title
```text
Phish&Chips: Ephemeral Sandboxed Detonation & Threat Intelligence Agent
```

---

### Field 2: Short Description (Tagline)
*(Paste this into the Short Description / Tagline input field)*
```text
Fresh phish, fried in a sandbox. Ephemeral detonation and threat intelligence platform with Blast Radius Zero, powered by Vultr Cloud Compute and Vultr Serverless Inference.
```

---

### Field 3: Technology & Category Tags
Select or enter the following tags:
- `Cybersecurity`
- `Autonomous Agents`
- `Vultr Cloud Compute`
- `Vultr Serverless Inference`
- `Sandboxing`
- `FastAPI`
- `React`
- `Docker`
- `Threat Intelligence`
- `GLM-5.3`

---

### Field 4: App Hosting & Repository URLs
- **Public GitHub Repository:**
  ```text
  https://github.com/Vrajesh-sulakhe/PhishnChips
  ```
- **Demo Application Platform:**
  ```text
  Vultr Cloud Compute (Bangalore, Ubuntu 24.04 LTS, 4 vCPUs / 8 GB RAM / 160 GB SSD)
  ```
- **Application URL (Live Working Product):**
  ```text
  https://139.84.159.12.sslip.io
  ```

---

### Field 5: Long Description (Markdown)
*(Copy and paste the entire block below into the Long Description Markdown editor)*

```markdown
# 🐟🍟 Phish&Chips: Fresh Phish, Fried in a Sandbox

**Phish&Chips** is an ephemeral detonation and threat analysis platform that empowers anyone—from frontline SOC analysts to everyday citizens—to inspect suspicious links (fake KYC updates, UPI payment scams, banking impersonations, and malicious invoice drops) **without ever opening the link on their device or exposing host systems**.

Built specifically for the **Vultr Agent Rush Hackathon** under **Track 01: Blast Radius Zero**, Phish&Chips proves that autonomous AI agents can safely handle hazardous security tasks when backed by hardened cloud infrastructure and strict containment boundaries.

---

## ⚡ How Vultr Powers Phish&Chips

Phish&Chips relies on Vultr infrastructure across its entire operational lifecycle:

1. **Vultr Cloud Compute (Bangalore Region - 4 vCPUs / 8192 MB RAM / 160 GB NVMe SSD):**
   - Serves as the central hardened control plane hosting the FastAPI orchestration server, automated Caddy TLS reverse proxy, and local SQLite WAL database.
   - Enforces strict kernel-level cgroups v2 limits (`--cpus=1`, `--memory=1g`, `--pids-limit=256`) and an automated 45-second wall-clock kill switch.
2. **Vultr Serverless Inference (`api.vultrinference.com/v1`):**
   - High-performance AI reasoning powered by the flagship **GLM-5.3** model (with fallback multi-model support).
   - Evaluates collected forensic DOM telemetry, network request graphs, visual rendered screenshots, and binary disassembly into strict Pydantic schemas (`backend/schemas.py`).
3. **Vultr Isolated Virtual Network (`phishnet` Bridge + iptables):**
   - Custom bridge network (`172.30.0.0/16`) protected by iptables rules that drop all traffic attempting to reach the host bridge gateway (`172.30.0.1`), host public IP (`139.84.159.12`), RFC1918 private subnets (`10.0.0.0/8`, `192.168.0.0/16`), and cloud metadata (`169.254.169.254`).

---

## 🛡️ Challenge 1: The Containment Moment

In accordance with Track 01 criteria, containment is our core guarantee. Phish&Chips demonstrates two verifiable containment moments:

### 1. Kernel-Enforced Network Isolation
Active containers on the `phishnet` bridge are blocked from touching internal host or cloud services. Live verification via `scripts/verify_containment.sh` tests and confirms:
- Host Bridge Gateway (`172.30.0.1:8000`) $\rightarrow$ **[PASS] BLOCKED** (Connection dropped by iptables)
- Cloud Metadata (`169.254.169.254`) $\rightarrow$ **[PASS] BLOCKED**
- Private Subnets (`10.0.0.1`, `192.168.1.1`) $\rightarrow$ **[PASS] BLOCKED**
- Public Internet (`Cloudflare 1.1.1.1`) $\rightarrow$ **[PASS] REACHABLE**

### 2. Drive-By Malware Interception & Quenching
When a phishing site triggers an automated executable drop (e.g. `SBI_Mandatory_Security_Patch.exe`), Playwright quenches the download stream instantly. The file is saved to an isolated quarantine volume, hashed (SHA-256), and analyzed for entropy without running executable bytes.

---

## 🤖 The Agentic Workflow & Pattern B Implementation

Phish&Chips implements the hackathon's required **Pattern B: Sandboxed Browser Use with Human Approval**:

1. **Pass 1 (Passive Reconnaissance):** An unprivileged Playwright Chromium browser (`runner`, UID 10001, `--cap-drop=ALL`, `--read-only`) detonates the target URL, captures full-page visual screenshots, monitors HTTP redirects, and parses all DOM forms.
2. **Human Approval Gate:** If credential or OTP fields are discovered, the agent pauses and triggers an interactive authorization modal in the UI:
   > *"Credential harvester detected. Authorize unprivileged container to inject decoy canary credentials to observe post-submission routing?"*
3. **Pass 2 (Simulated Canary Submission):** Upon operator approval, the unprivileged browser injects synthetic decoy credentials (`test_canary_user@example.com`, `FakePassword123!`) to observe where the data exfiltrates, capturing post-submit redirection and server-side behavior.
4. **REA Static Disassembly:** Our integrated Reverse Engineering Anything engine analyzes all inline scripts, WebAssembly bytecode, and dropped binaries, calculating Shannon entropy and mapping behaviors to MITRE ATT&CK tactics (`T1056: Input Capture`, `T1071: Exfiltration Over C2`, `T1204: Malicious File`).
5. **Ephemerality Guarantee:** Once telemetry is captured, the container is destroyed:
   ```text
   🍟 Phish fried. Sandbox destroyed.
   ```

---

## 🎯 Zero False Positives & Real-World Impact

- **Zero False-Positive Reputation Fast-Path:** Tranco Top-10K reputable domains (Wikipedia, Google, Gov portals) complete within 5 seconds with guaranteed `SAFE` verdicts, eliminating AI hallucination and saving inference compute.
- **1-Click Abuse Takedown:** Auto-generates a signed `.tar.gz` Evidence Locker containing screenshots, HAR recordings, and registrar abuse contact details.
- **Indian Regional Localization:** Full multilingual support in **English, हिन्दी (Hindi), and ಕನ್ನಡ (Kannada)** protecting citizens frequently targeted by fake KYC and electricity bill scams.
- **Emergency Escalation:** Direct 1-tap dialer for India's **National Cybercrime Helpline (`1930`)** and direct reporting to `cybercrime.gov.in`.
- **Production Observability:** Native Prometheus `/metrics` and `/api/health` endpoints.

---

## 🔗 Try It Live
- **Production URL:** [https://139.84.159.12.sslip.io](https://139.84.159.12.sslip.io)
- **GitHub Repository:** [https://github.com/Vrajesh-sulakhe/PhishnChips](https://github.com/Vrajesh-sulakhe/PhishnChips)
- **Slide Presentation:** Included in repository under `docs/slides.html` and `docs/PRESENTATION_SLIDES.md`.
```

---

### Field 6: Cover Image Guidance & AI Generation Prompt

LabLab requires a high-resolution 16:9 cover image for the project listing. You can generate an image using Midjourney, DALL-E 3, or Nano Banana using the prompt below:

#### AI Generation Prompt:
> **Prompt:** `A cinematic, ultra-modern cybersecurity concept art of a glowing digital fried fish and chips inside a high-tech holographic containment chamber. The containment cage has glowing neon red and laser-blue boundary barriers with digital circuit patterns. Holographic terminals display binary code, threat waveforms, and MITRE ATT&CK labels. Deep obsidian dark background, volumetric cinematic lighting, photorealistic, 8k resolution, octane render, cyber defense aesthetic, 16:9 aspect ratio --ar 16:9 --v 6.0`

#### Quick Option:
You can also take a clean 16:9 screenshot of the live dashboard at `https://139.84.159.12.sslip.io` with the animated node graph glowing and the containment terminal open.

---

### Field 7: Video Presentation URL
Follow the 3-minute recording script in [`docs/DEMO_VIDEO_SCRIPT.md`](file:///Users/vrajeshsulakhe/Documents/GitHub/PhishnChips/docs/DEMO_VIDEO_SCRIPT.md).
- Record the video using Loom or OBS.
- Upload to YouTube (Unlisted or Public) or Loom.
- Paste the URL into the Video presentation input field on LabLab.

---

### Field 8: Slide Presentation URL
- In your browser, open the included HTML slide deck: [`docs/slides.html`](file:///Users/vrajeshsulakhe/Documents/GitHub/PhishnChips/docs/slides.html).
- Press `Cmd + P` (or `Ctrl + P`) and select **"Save as PDF"**.
- Upload the PDF to Google Drive or Pitch / SpeakerDeck, make it public, and paste the URL, OR link directly to:
  `https://github.com/Vrajesh-sulakhe/PhishnChips/blob/main/docs/PRESENTATION_SLIDES.md`