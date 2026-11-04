# Phish&Chips: Project Brief (read this fully before writing any code)

> Tagline: **Fresh phish, fried in a sandbox.**
> Repo: `phish-and-chips` (display name: **Phish&Chips**, with the "&")
> Event: **Vultr Agent Rush** on lablab.ai. Track: **01 · Blast Radius Zero**.
> Hard deadline: **Nov 9, 4:30 AM IST**. Treat **Nov 8 night** as the real deadline.

---

## 0. Instructions to the coding agent

1. Read this whole file first. It contains hackathon rules that are scored by judges.
2. **Containment is the product.** Never weaken a containment rule (section 6) to make something "just work". If a rule blocks you, stop and ask.
3. Keep the stack simple. Working end to end beats clever. Prefer plain, readable code.
4. Build in the milestones listed in section 14. After each milestone, run its acceptance check before continuing.
5. Never hardcode secrets. Never print secrets in logs. Never put secrets inside the sandbox container (section 11).
6. Commit small and often with clear messages.
7. Do not open real malicious links during development or testing. Use only harmless sites (example.com) and our own fake phishing test page (section 12).

---

## 1. One-paragraph summary

Phish&Chips lets a person paste a suspicious link (fake KYC, fake UPI refund, fake parcel notice, fake job offer) and get a verdict **without ever opening it on their own device**. A backend running on a Vultr VM creates a **brand-new, locked-down Docker container** for each scan. Inside it, a Playwright (Chromium) browser opens the link and records screenshots, page text, the redirect chain and form fields. The backend then sends that evidence to a **vision-capable model on Vultr Serverless Inference** which decides **Safe / Suspicious / Scam** and explains why. The container is **destroyed** after every scan and the user sees a verdict card, a screenshot timeline and a **containment log** that proves the sandbox was created, limited and destroyed.

Target users: everyday people (especially in India) who receive scam links on WhatsApp/SMS, plus family members who want to check a link before tapping.

---

## 2. Hackathon context and rules (from the event page)

**Challenge 01 · Blast Radius Zero.** Build a web-based agent that performs real work (writing and running code, or operating a real browser) while every action stays inside an isolated sandbox running on Vultr.

- Core idea: **containment-first**. The system should plan, dispatch and verify real executed work, not just describe it.
- Vultr is looking for an app that uses **Vultr as the central control layer**, dispatches real work into isolated execution environments, and returns **verifiable output**.
- We build against **Pattern B: sandboxed browser use**: user gives a goal, model plans, **Playwright runs in a container**, **screenshots return**, a **vision model verifies**, and there is **human approval before final actions**.

**Containment focus (what judges look for):**
- **Process isolation:** execution never touches the host or app runtime.
- **Secret hygiene:** no API keys or credentials inside the sandbox.
- **Resource limits:** apply time and memory caps to every run.
- **Lifecycle discipline:** reset or destroy the environment after each task.

**Technology requirements:**
- A **Vultr VM backend** is required, and the web app must be **deployed on Vultr**. Vultr should be the central system of control and orchestration, not just static hosting.
- **Vultr Serverless Inference is required** for the agent's LLM calls. It is OpenAI-compatible at `https://api.vultrinference.com/v1`.
- Docker is strongly recommended for sandboxing (OpenSandbox, gVisor, E2B, Microsandbox are listed as alternatives).
- Vultr API for throwaway instances is optional.
- **Vultr GPUs are NOT available for this event.** Do not plan any GPU work on Vultr.

**Submission expectations (all required):**
1. GitHub repository with setup and documentation
2. Vultr VM backend deployment
3. Public demo URL
4. Recorded demo video
5. Clear architecture and use-case explanation
6. **One containment moment shown in the video**

> Note: the Judging Criteria, Prizes and Event Schedule tabs have not been reviewed yet. If the owner shares them, align priorities accordingly.

---

## 3. User-facing behavior

### Main flow
1. User opens the site and pastes a link.
2. UI shows live progress: `Creating sandbox → Opening link → Taking screenshots → Analyzing → Destroying sandbox`.
3. UI shows a **screenshot timeline** (what the sandboxed browser actually saw).
4. UI shows a **verdict card**:
   - 🟢 **Safe**
   - 🟡 **Suspicious**
   - 🔴 **Scam**
   with "pretending to be", "asks for", and 3 plain-English reasons.
5. UI shows a **Containment Log** panel, for example:
   ```
   14:02:11  Container created (id a1b2c3)
   14:02:11  Limits applied: 1 CPU, 1 GB RAM, 256 PIDs, 45 s timeout
   14:02:11  Network: public internet only, host + private ranges blocked
   14:02:11  Secrets inside sandbox: none
   14:02:19  Link opened, 3 screenshots captured
   14:02:20  Blocked: automatic file download attempt
   14:02:24  Container destroyed
   🍟 Phish fried. Sandbox destroyed.
   ```

### Human approval step (Pattern B requirement)
If the inspected page contains a login/OTP/card form, the agent **pauses** and asks the user:
"This page asks for a login. Allow the sandbox to enter **fake dummy details** and submit, to see what happens? Yes / No."
- **No** → finish with the verdict so far.
- **Yes** → run a second sandbox pass that fills the form with obviously fake values (never real user data), submits, and captures what happens (redirect to real site? asks for OTP? posts to another domain?). Final verdict uses that extra evidence.
This is the "human approval before final actions" requirement. If time is short, implement the pause and approve/deny UI first and the second pass later.

---

## 4. Architecture

```
 Browser (user)
     │  HTTPS
     ▼
 FastAPI backend on Vultr VM  ──────────────►  Vultr Serverless Inference
 (the "manager": validates, queues,            (vision model, OpenAI-compatible)
  launches/kills containers, calls LLM,         key lives ONLY here
  keeps the containment log)
     │  docker run (limits, no secrets)
     ▼
 ┌──────────────────────────────┐
 │ Sandbox container (throwaway)│   public internet only
 │  Playwright + Chromium       │──────────────► suspicious website
 │  inspector.py                │
 │  writes /out/*.png,result.json│
 └──────────────────────────────┘
     │  container destroyed (--rm + forced kill on timeout)
     ▼
 Backend reads /out, deletes job folder after retention, returns result
```

Key principle: **the backend never opens the link itself.** Only the caged container does.

---

## 5. Tech stack (decided)

| Layer | Choice |
|---|---|
| Server | Vultr Cloud Compute VM, Shared CPU `vc2-4c-8gb`, **Bangalore**, Ubuntu 24.04 LTS |
| Sandbox | Docker (one container per scan) |
| Browser automation | Playwright (Python) with Chromium inside the container |
| Backend | Python 3.12, FastAPI, uvicorn |
| AI | Vultr Serverless Inference via the `openai` Python SDK, base URL `https://api.vultrinference.com/v1` |
| Frontend | Plain HTML/CSS/vanilla JS served by FastAPI (keep it simple and fast to build); responsive and mobile-friendly |
| Process management | systemd service for the backend |
| Reverse proxy | Nginx (optional, nice to have) |
| Optional bonus | scikit-learn URL risk model trained offline on a laptop and loaded as `model.pkl` |

**Model choice:** must be a **vision-capable** model available on Vultr Serverless Inference. The owner is verifying in the console's Prompt tab (candidate: `Nemotron-3-Nano-Omni-30B-A3B-Reasoning`). Read the model name from an env var `VULTR_MODEL`. **Do not hardcode it.** Provide a **text-only fallback** path (page text + signals, optionally OCR text) if the chosen model cannot accept images.

No GPU is used anywhere. No model training happens on the server.

---

## 6. Containment requirements (non-negotiable)

Every scan must run in a **fresh container** created by the backend with at least:

```bash
docker run --rm \
  --name sandbox-<job_id> \
  --network phishnet \
  --memory=1g --memory-swap=1g \
  --cpus=1 \
  --pids-limit=256 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,size=256m \
  --tmpfs /home/runner:rw,size=256m \
  --shm-size=512m \
  -v <job_dir>:/out:rw \
  -e TARGET_URL=<validated_url> \
  phishchips-sandbox
```

Rules:
1. **Non-root user** inside the image (`runner`).
2. **No secrets** in env vars, files or mounts. Only `TARGET_URL` (and non-secret flags) go in. Never mount the Docker socket. Never mount the project directory or home directory. Only the per-job `/out` folder is mounted.
3. **Timeouts:** the backend enforces a hard wall-clock limit (default 45 s). On timeout run `docker kill` then `docker rm -f`. Playwright also has its own navigation timeout (20 s).
4. **Destroy after every scan:** `--rm`, plus an explicit cleanup in a `finally` block. A background janitor removes any leftover `sandbox-*` containers older than 2 minutes and job folders older than a configurable retention period.
5. **Network isolation.** The browser needs the public internet to load the link, so the container cannot be fully offline. Instead:
   - Run sandboxes on a dedicated user-defined Docker network `phishnet` (for example subnet `172.30.0.0/16`).
   - Add iptables rules (in the `DOCKER-USER` chain for forwarded traffic, and in `INPUT` for traffic to the host itself) that **drop traffic from `phishnet` to**: RFC1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local / cloud metadata (`169.254.0.0/16`), the Docker bridge gateways, and the VM's own public IP.
   - Provide a script `scripts/setup_network.sh` that creates the network and rules idempotently, and `scripts/verify_containment.sh` that proves from inside a test container that the host, private ranges and metadata address are unreachable while the public internet works.
6. **Downloads blocked:** Playwright context uses `accept_downloads=False`. Any attempted download is **logged as an event** (it is great demo material).
7. **Concurrency cap:** at most 3 simultaneous sandboxes (semaphore) to protect the VM.
8. **Input validation:** accept only `http://` and `https://` URLs, max 2048 chars, reject URLs whose host is an IP in private/loopback/link-local ranges or `localhost` (defense in depth; the network rules are the real boundary).
9. **Rate limit** the scan endpoint per IP (simple in-memory limiter is fine).
10. The backend must keep a structured **event log per job** (timestamped) that the UI renders as the Containment Log.

If the Chromium sandbox conflicts with `--cap-drop=ALL`, launch Chromium with `--no-sandbox` **only inside the container** (the container is the boundary) and keep all the Docker restrictions above. Do not loosen Docker flags to make Chromium happy without asking.

---

## 7. Sandbox image and inspector

**Image** `phishchips-sandbox`: `python:3.12-slim` (or the official Playwright Python image), Playwright + Chromium installed at build time, a non-root `runner` user, `inspector.py` copied in, `CMD ["python","inspector.py"]`.

**inspector.py behavior** (runs inside the container):
1. Read `TARGET_URL` from env.
2. Launch Chromium headless, viewport 1280×800, `accept_downloads=False`.
3. Record every main-frame navigation URL (the **redirect chain**), and log any download attempt, popup, or `window.open`.
4. `goto` with a 20 s timeout, wait ~2 s for scripts, screenshot `/out/shot1.png`. Optionally scroll once and take `shot2.png`.
5. Extract: page title, final URL, visible text (truncate to ~5000 chars), list of forms and inputs (type, name, placeholder, id), counts of password fields and OTP/PIN/CVV/card-like fields, external domains the page loaded resources from or posted forms to, presence of an icon/logo image, and whether a TLS certificate error occurred.
6. Write `/out/result.json` and exit with code 0 even on navigation errors (put the error in the JSON).

**result.json schema (inspector output):**
```json
{
  "url": "original url",
  "final_url": "after redirects",
  "redirect_chain": ["..."],
  "title": "...",
  "text": "visible text, truncated",
  "fields": {"password": 0, "otp_like": 0, "card_like": 0, "inputs": []},
  "form_actions": ["domains forms post to"],
  "external_domains": ["..."],
  "blocked_events": [{"type": "download", "detail": "..."}],
  "screenshots": ["shot1.png"],
  "error": null
}
```

---

## 8. Backend (FastAPI)

**Endpoints**
- `POST /api/scan` body `{ "url": "https://..." }` → `{ "job_id": "..." }` (starts async job).
- `GET /api/scan/{job_id}` → status + events + result:
  ```json
  {
    "job_id": "...",
    "status": "queued|running|awaiting_approval|analyzing|done|error",
    "events": [{"ts": "ISO time", "msg": "Container created (id a1b2c3)"}],
    "screenshots": ["/api/scan/{job_id}/shot/shot1.png"],
    "result": null
  }
  ```
- `POST /api/scan/{job_id}/approve` body `{ "approve": true|false }` for the human approval step.
- `GET /api/scan/{job_id}/shot/{name}` serves screenshots (whitelist filenames, no path traversal).
- `GET /api/health`.
- Serve the frontend at `/`.

Polling every ~1 s from the frontend is fine (SSE optional).

**Job lifecycle:** create job folder → start sandbox → wait with timeout → read `/out/result.json` → destroy container → call LLM → merge heuristics → store result → schedule job folder cleanup.

**Configuration via environment variables** (loaded from `.env`, which is git-ignored):
```
VULTR_INFERENCE_API_KEY=...
VULTR_INFERENCE_BASE_URL=https://api.vultrinference.com/v1
VULTR_MODEL=<exact model name from console>
SCAN_TIMEOUT_SECONDS=45
MAX_CONCURRENT_SCANS=3
JOB_RETENTION_MINUTES=30
```
Also commit a `.env.example` with placeholders only.

---

## 9. AI analysis (Vultr Serverless Inference)

Use the OpenAI-compatible client:
```python
from openai import OpenAI
client = OpenAI(base_url=os.environ["VULTR_INFERENCE_BASE_URL"],
                api_key=os.environ["VULTR_INFERENCE_API_KEY"])
```
Send: the screenshot(s) as base64 `image_url` data URIs, the page text, the field counts, the redirect chain, the final domain, and form action domains.

**System prompt intent:** "You are a phishing analyst. Judge only from the evidence provided. Reply with JSON only, no markdown."

**Required JSON reply:**
```json
{
  "verdict": "SAFE | SUSPICIOUS | SCAM",
  "confidence": 0.0,
  "pretending_to_be": "brand or null",
  "asks_for": ["OTP", "card number"],
  "reasons": ["reason 1", "reason 2", "reason 3"]
}
```
Robustness: strip code fences, parse safely, retry once on invalid JSON, and if the model call fails, fall back to a **heuristics-only verdict** and say so in the UI. Never send secrets or the user's identity to the model.

**Code-level heuristics layered on top of the LLM (cheap, explainable):**
- **Brand-vs-domain mismatch:** LLM says the page imitates brand X, but the final domain is not X's real domain → strong scam signal. Keep a small allowlist map of common brands (SBI, HDFC, ICICI, Paytm, PhonePe, Google Pay, Amazon, Flipkart, India Post, DTDC, Income Tax, Aadhaar/UIDAI, etc.) to real domains.
- Password / OTP / PIN / card fields on a domain unrelated to the claimed brand.
- Long redirect chains, punycode / lookalike characters, raw IP URLs, very new or unusual TLDs, many subdomains, `@` in URL, URL shorteners.
- Form posting to a different domain than the page.
- Attempted automatic download.
Final verdict = combine LLM verdict with heuristic score. When they disagree, show both reasons and lean to the more cautious verdict.

**Optional bonus (only after everything else works):** a small scikit-learn (Random Forest/XGBoost) URL risk score trained **offline on a laptop** on a public phishing-URL dataset, saved as `model.pkl`, loaded by the backend as a first-stage score. Include precision/recall numbers on a small test set in the README. Never train on the server.

---

## 10. Frontend requirements

- Single page, fast, mobile-first, readable by non-technical people. Plain language, no jargon.
- Branding: name **Phish&Chips**, tagline "Fresh phish, fried in a sandbox", small 🐟🍟 motif, friendly but trustworthy. Dark/light friendly.
- Components: link input + "Scan" button, example links dropdown (our own safe demo pages), live progress stepper, screenshot timeline (click to enlarge), verdict card (🟢/🟡/🔴, pretending to be, asks for, 3 reasons, confidence), Containment Log panel (monospace, timestamped, ends with "🍟 Phish fried. Sandbox destroyed."), approval prompt UI, error states (timeout, unreachable site, model failure).
- A short "How it stays safe" explainer section listing the four containment guarantees.
- No third-party trackers. No secrets in frontend code.

---

## 11. Secret hygiene

- `VULTR_INFERENCE_API_KEY` exists **only** in the backend process environment on the VM (via `.env` / systemd `EnvironmentFile`).
- `.env` is in `.gitignore`. Provide `.env.example` only. Scan the repo for accidental keys before every push.
- The sandbox container receives **no** credentials, tokens, or host paths.
- Do not log API keys, full prompts containing user data beyond the scanned URL, or request headers.

---

## 12. Demo assets (needed for the video)

Build our **own fake phishing test pages** (hosted by us, harmless). Never use real malicious links.
- `fake-bank-login`: looks like a generic fake bank login asking for username, password and OTP (use a made-up bank name or a clearly fictional brand to avoid trademark issues).
- Make it **do sneaky things** to produce the **containment moment**:
  - auto-triggers a file download,
  - redirects through 2-3 hops,
  - JavaScript tries to fetch internal targets (`http://169.254.169.254/`, the Docker gateway, and a dummy "secret" service on the host such as `localhost:9999`).
- In the video, show these attempts **blocked/failing** from inside the sandbox, logged in the Containment Log, then the container destroyed.
- Also prepare: 2 harmless real sites (e.g. example.com, wikipedia.org) that should score 🟢, and 1 tricky ambiguous page.
- Optional: a 20-page labeled evaluation set and a script that reports accuracy/precision/recall for the README.

---

## 13. Repository layout

```
phish-and-chips/
├── README.md                 # product, architecture diagram, setup, containment explanation, demo link
├── PROJECT_BRIEF.md          # this file
├── .env.example
├── .gitignore
├── backend/
│   ├── main.py               # FastAPI app and routes
│   ├── scanner.py            # docker lifecycle: create, limit, wait, kill, cleanup
│   ├── analyzer.py           # Vultr Inference call + JSON parsing + fallbacks
│   ├── heuristics.py         # brand-vs-domain and URL/form rules
│   ├── events.py             # per-job containment event log
│   ├── validation.py         # URL validation and rate limiting
│   └── requirements.txt
├── sandbox/
│   ├── Dockerfile
│   └── inspector.py
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── styles.css
├── scripts/
│   ├── setup_network.sh      # phishnet + iptables rules (idempotent)
│   ├── verify_containment.sh # proves host/private/metadata are unreachable
│   └── deploy.sh             # install deps, build image, restart service
├── demo/
│   └── fake-pages/           # our own harmless fake phishing pages
├── deploy/
│   ├── phishchips.service    # systemd unit
│   └── nginx.conf            # optional
└── docs/
    └── architecture.png|md
```

---

## 14. Build order (milestones and acceptance checks)

1. **Sandbox works.** Build `phishchips-sandbox`; run with the full flag set on `https://example.com`. *Accept:* `shot1.png` and `result.json` appear; container is gone afterwards.
2. **Network rules.** `setup_network.sh` + `verify_containment.sh`. *Accept:* from inside a sandbox, public internet works; host, private ranges, metadata and Docker gateway are unreachable.
3. **Backend manager.** `POST /api/scan` and `GET /api/scan/{id}` with timeouts, forced kill, cleanup, event log, concurrency cap, validation. *Accept:* scan returns screenshots and structured data; a deliberately hanging page is killed at the timeout and cleaned up.
4. **AI analysis.** Vultr Inference call, JSON schema, fallbacks, heuristics, brand-vs-domain check. *Accept:* fake bank page returns SCAM/SUSPICIOUS with sensible reasons; example.com returns SAFE.
5. **Frontend.** Progress stepper, screenshots, verdict card, containment log. *Accept:* full flow works in a browser, including on a phone.
6. **Human approval pass.** Pause when forms exist; approve/deny; optional second sandbox pass with dummy values. *Accept:* approval changes what happens.
7. **Demo pages + evaluation.** Fake phishing page with sneaky behavior; test set; (optional) ML risk score. *Accept:* sneaky attempts visibly blocked and logged.
8. **Deploy on Vultr.** systemd service, firewall (`ufw`: allow 22, 80, 443 only), public URL, test from a phone on mobile data. *Accept:* judges can open the URL.
9. **Docs and video.** README with architecture diagram and containment section; demo video (2-3 min): scam story → paste link → live scan → containment moment → verdict. Submit well before the deadline.

---

## 15. Don'ts

- Don't run the browser or any untrusted code on the host or in the backend process.
- Don't mount the Docker socket, the repo, or home directories into sandboxes.
- Don't pass any API key into a container, in any form.
- Don't skip memory/CPU/PID/time limits "for testing".
- Don't commit `.env`, keys, private SSH keys or screenshots of real user data.
- Don't depend on Vultr GPUs.
- Don't hardcode the model name.
- Don't scan real malicious links during development.
- Don't add heavy frameworks or features that threaten the deadline; polish only after the end-to-end flow works.

---

## 16. Environment facts

- Server: Vultr VM, Shared CPU `vc2-4c-8gb` (4 vCPU / 8 GB), Bangalore, Ubuntu 24.04 LTS, backups off, SSH key auth (`~/.ssh/vultr` on the owner's Mac, host alias `phish`).
- Owner builds with Antigravity and VS Code (Remote-SSH into the VM). Docker is installed on the VM via the official convenience script.
- Credits come from the hackathon gift code; delete the VM after the event ends.

---

## 17. Definition of done

- A public URL where anyone can paste a link and get a verdict with screenshot proof.
- Every scan provably runs in an isolated, resource-limited, secret-free container that is destroyed afterwards, with a visible containment log.
- At least one clear **containment moment** is reproducible on demand for the video.
- README, architecture explanation, demo video and repo are ready, and the submission is filed before **Nov 9, 4:30 AM IST**.
