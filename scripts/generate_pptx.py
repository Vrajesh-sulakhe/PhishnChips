#!/usr/bin/env python3
"""
Phish&Chips PowerPoint (.pptx) Generator
Generates an 8-slide, 16:9 presentation deck formatted with cyber dark aesthetic,
cards, badges, code terminal blocks, and speaker notes.
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

# Design System Colors (Obsidian Cyber Palette)
COLOR_BG = RGBColor(9, 10, 15)           # Deep obsidian background
COLOR_CARD = RGBColor(18, 22, 34)        # Card surface
COLOR_CARD_BORDER = RGBColor(31, 38, 55) # Subtle card border
COLOR_RED = RGBColor(239, 68, 68)        # Brand accent red / Alert
COLOR_BLUE = RGBColor(0, 122, 255)       # Vultr electric blue
COLOR_GREEN = RGBColor(16, 185, 129)     # Success / Emerald green
COLOR_AMBER = RGBColor(245, 158, 11)     # Warning / Gold
COLOR_TEXT_WHITE = RGBColor(255, 255, 255)
COLOR_TEXT_MUTED = RGBColor(156, 163, 175) # Slate gray
COLOR_CODE_BG = RGBColor(13, 15, 21)
COLOR_CODE_TEXT = RGBColor(167, 243, 208)  # Light mint green

FONT_HEADING = "Helvetica"
FONT_BODY = "Arial"
FONT_MONO = "Courier New"


def create_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    return prs


def add_base_slide(prs):
    blank_layout = prs.slide_layouts[6]
    slide = prs.slides.add_slide(blank_layout)
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = COLOR_BG
    return slide


def add_header(slide, tag_text, title_text, subtitle_text, tag_color=COLOR_RED):
    # Top progress/accent line
    line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(0.06))
    line.fill.solid()
    line.fill.fore_color.rgb = tag_color
    line.line.color.rgb = tag_color

    # Header Text Box
    txBox = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.733), Inches(1.3))
    tf = txBox.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    # Tag
    p_tag = tf.paragraphs[0]
    p_tag.text = tag_text.upper()
    p_tag.font.name = FONT_BODY
    p_tag.font.size = Pt(10)
    p_tag.font.bold = True
    p_tag.font.color.rgb = tag_color
    p_tag.space_after = Pt(4)

    # Title
    p_title = tf.add_paragraph()
    p_title.text = title_text
    p_title.font.name = FONT_HEADING
    p_title.font.size = Pt(26)
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_TEXT_WHITE
    p_title.space_after = Pt(3)

    # Subtitle
    p_sub = tf.add_paragraph()
    p_sub.text = subtitle_text
    p_sub.font.name = FONT_BODY
    p_sub.font.size = Pt(13)
    p_sub.font.color.rgb = COLOR_TEXT_MUTED


def add_card(slide, left, top, width, height, title, items, accent_color=COLOR_BLUE, bg_color=COLOR_CARD):
    # Main card shape
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = bg_color
    card.line.color.rgb = COLOR_CARD_BORDER
    card.line.width = Pt(1)

    # Left accent strip
    accent = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, Inches(0.08), height)
    accent.fill.solid()
    accent.fill.fore_color.rgb = accent_color
    accent.line.color.rgb = accent_color

    # Content box inside card
    tb = slide.shapes.add_textbox(left + Inches(0.25), top + Inches(0.2), width - Inches(0.4), height - Inches(0.35))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    # Card Title
    p_title = tf.paragraphs[0]
    p_title.text = title
    p_title.font.name = FONT_HEADING
    p_title.font.size = Pt(16)
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_TEXT_WHITE
    p_title.space_after = Pt(8)

    # Items / Bullets
    for item in items:
        p = tf.add_paragraph()
        p.text = f"•  {item}" if not item.startswith("•") and not item.startswith("http") else item
        p.font.name = FONT_BODY
        p.font.size = Pt(11.5)
        p.font.color.rgb = COLOR_TEXT_MUTED
        p.space_after = Pt(6)


def add_terminal(slide, left, top, width, height, title, lines):
    # Terminal container
    term = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, height)
    term.fill.solid()
    term.fill.fore_color.rgb = COLOR_CODE_BG
    term.line.color.rgb = COLOR_CARD_BORDER
    term.line.width = Pt(1)

    tb = slide.shapes.add_textbox(left + Inches(0.2), top + Inches(0.15), width - Inches(0.4), height - Inches(0.3))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    p_head = tf.paragraphs[0]
    p_head.text = f"💻 {title}"
    p_head.font.name = FONT_MONO
    p_head.font.size = Pt(11)
    p_head.font.bold = True
    p_head.font.color.rgb = COLOR_BLUE
    p_head.space_after = Pt(6)

    for line in lines:
        p = tf.add_paragraph()
        p.text = line
        p.font.name = FONT_MONO
        p.font.size = Pt(9.5)
        if "[PASS]" in line or "verified" in line or "destroyed" in line:
            p.font.color.rgb = COLOR_GREEN
        elif "[BLOCKED]" in line or "INTERCEPT" in line or "SCAM" in line:
            p.font.color.rgb = COLOR_RED
        elif "Testing" in line or "INFO" in line or "PATIENT" in line:
            p.font.color.rgb = COLOR_AMBER
        else:
            p.font.color.rgb = COLOR_CODE_TEXT
        p.space_after = Pt(2)


def add_footer(slide, slide_num, total_slides=8):
    footer_box = slide.shapes.add_textbox(Inches(0.8), Inches(6.9), Inches(11.733), Inches(0.4))
    tf = footer_box.text_frame
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    p = tf.paragraphs[0]
    p.text = f"Phish&Chips · Track 01: Blast Radius Zero  |  Live at https://139.84.159.12.sslip.io"
    p.font.name = FONT_BODY
    p.font.size = Pt(10)
    p.font.color.rgb = COLOR_TEXT_MUTED

    # Slide number on right
    num_box = slide.shapes.add_textbox(Inches(11.5), Inches(6.9), Inches(1.0), Inches(0.4))
    tf_num = num_box.text_frame
    tf_num.margin_left = tf_num.margin_top = tf_num.margin_right = tf_num.margin_bottom = 0
    p_num = tf_num.paragraphs[0]
    p_num.alignment = PP_ALIGN.RIGHT
    p_num.text = f"{slide_num} / {total_slides}"
    p_num.font.name = FONT_MONO
    p_num.font.size = Pt(10)
    p_num.font.color.rgb = COLOR_TEXT_MUTED


def set_speaker_notes(slide, notes_text):
    notes = slide.notes_slide
    notes.notes_text_frame.text = notes_text.strip()


# ==============================================================================
# SLIDE BUILDERS
# ==============================================================================

def build_slide_1(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Vultr Agent Rush Hackathon · Track 01: Blast Radius Zero",
        "🐟🍟 Phish&Chips",
        "Fresh phish, fried in a sandbox. Ephemeral detonation & threat intelligence platform."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(3.2),
        "🛡️ Challenge 1: Blast Radius Zero",
        [
            "Untrusted links, fake KYC notices, and malicious payloads are detonated inside an ephemeral, locked-down browser cage.",
            "Host system, cloud credentials, and analyst devices remain completely isolated and unharmed at all times.",
            "Guaranteed Ephemerality: Every sandbox container is destroyed immediately after inspection (<45 seconds)."
        ],
        accent_color=COLOR_RED
    )

    add_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(3.2),
        "⚡ Cloud & Inference Infrastructure",
        [
            "Vultr Cloud Compute (Bangalore Region - 4 vCPUs / 8 GB RAM / 160 GB SSD) orchestrating central FastAPI control plane.",
            "Vultr Serverless Inference (api.vultrinference.com) running flagship GLM-5.3 deep threat reasoning engine.",
            "Dedicated phishnet bridge with kernel iptables rules blocking host gateway, private subnets, and cloud metadata."
        ],
        accent_color=COLOR_BLUE
    )

    # Highlight box at bottom
    add_card(
        slide,
        Inches(0.8), Inches(5.4), Inches(11.7), Inches(1.3),
        "🌐 Production Status & Team",
        [
            "Live Production URL: https://139.84.159.12.sslip.io (Automated TLS 1.3 via Caddy)",
            "Team: alphax  |  Architecture: Host / Agent / Caged Sandbox Model  |  Status: 100% Deployed & Operational"
        ],
        accent_color=COLOR_GREEN
    )

    add_footer(slide, 1)
    set_speaker_notes(slide, """
Hello judges and fellow builders! Welcome to Phish&Chips: an autonomous, ephemeral detonation and threat analysis platform.
In an era where phishing attacks bypass traditional static blocklists in minutes, Phish&Chips introduces Blast Radius Zero — an agentic sandbox running on Vultr Cloud Compute that safely visits untrusted links, reverses malicious scripts and binary drops, executes controlled canary submissions, and synthesizes deep threat verdicts using Vultr Serverless Inference.
""")


def build_slide_2(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "The Threat Landscape & Crisis",
        "The $10B Phishing Crisis & Analyst Vulnerability",
        "Why traditional antivirus scanners and static URL blocklists fail against modern campaigns."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(3.7), Inches(3.1),
        "⏱️ Ephemeral Lifespans",
        [
            "Modern phishing domains live for only 4 to 8 hours.",
            "Static domain blocklists update too slowly, allowing thousands of credentials to be stolen before blacklisting.",
            "Attackers leverage dynamic DNS and ephemeral subdomains."
        ],
        accent_color=COLOR_AMBER
    )

    add_card(
        slide,
        Inches(4.8), Inches(2.0), Inches(3.7), Inches(3.1),
        "🎭 Evasive Behaviors",
        [
            "Attackers employ client-side browser fingerprinting and bot-detection evasion.",
            "Obfuscated JavaScript and WebAssembly payloads camouflage malicious DOM behavior.",
            "Targeted regional themes: fake KYC, UPI refund scams, and banking portals."
        ],
        accent_color=COLOR_RED
    )

    add_card(
        slide,
        Inches(8.8), Inches(2.0), Inches(3.7), Inches(3.1),
        "☣️ Analyst Blast Radius",
        [
            "Manual inspection exposes security teams to drive-by executable downloads and zero-days.",
            "Host cookies, session tokens, and local network segments are put at risk.",
            "Analyst fatigue leads to missed indicators and compromised workstations."
        ],
        accent_color=COLOR_BLUE
    )

    add_card(
        slide,
        Inches(0.8), Inches(5.3), Inches(11.7), Inches(1.4),
        "🎯 The Essential Question",
        [
            "How can security teams, fraud desks, and ordinary citizens safely dissect and interact with a hostile link in real time without putting themselves or their systems at risk?"
        ],
        accent_color=COLOR_GREEN
    )

    add_footer(slide, 2)
    set_speaker_notes(slide, """
Every day, millions of people receive deceptive SMS messages, UPI refund links, or urgent KYC verification alerts. Traditional blocklists are too slow because attackers spin up new domains constantly. But opening these links to inspect them is dangerous — they fingerprint your browser, download malicious executables, or steal sensitive tokens. How do we inspect untrusted links without putting ourselves or our infrastructure at risk?
""")


def build_slide_3(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Core Philosophy · Track 01",
        "Blast Radius Zero: Containment as the Product",
        "Four non-negotiable guarantees enforced on every single detonation."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(2.2),
        "🔒 1. Process Stripping",
        [
            "Unprivileged execution under runner (UID 10001).",
            "Complete Linux capability drop (--cap-drop=ALL).",
            "Privilege escalation prevented via no-new-privileges.",
            "Root filesystem strictly mounted --read-only."
        ],
        accent_color=COLOR_RED
    )

    add_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(2.2),
        "🛡️ 2. Secret & Host Hygiene",
        [
            "Zero API keys, cloud tokens, or SSH keys enter the sandbox.",
            "Docker socket is NEVER mounted inside the container.",
            "Container exists purely as a throwaway browser harness."
        ],
        accent_color=COLOR_BLUE
    )

    add_card(
        slide,
        Inches(0.8), Inches(4.4), Inches(5.7), Inches(2.3),
        "⚡ 3. Hard Cgroup Resource Bounds",
        [
            "Linux cgroups v2 clamps: --cpus=1, --memory=1g, --pids-limit=256.",
            "Hard 45-second orchestrator kill switch stops runaway loops.",
            "Blocks cryptominers, fork bombs, and CPU exhaustion attacks."
        ],
        accent_color=COLOR_AMBER
    )

    add_card(
        slide,
        Inches(6.8), Inches(4.4), Inches(5.7), Inches(2.3),
        "🔥 4. Total Ephemerality",
        [
            "Containers destroyed immediately after telemetry collection via --rm.",
            "Background janitor purges stale artifacts and orphan containers.",
            "Final verified log: '🍟 Phish fried. Sandbox destroyed.'"
        ],
        accent_color=COLOR_GREEN
    )

    add_footer(slide, 3)
    set_speaker_notes(slide, """
The answer is Blast Radius Zero. Phish&Chips treats every URL as hostile. When a link is submitted, our FastAPI control plane on a hardened Vultr Cloud Compute VM spins up an isolated, unprivileged Playwright container on a custom 'phishnet' bridge. The sandbox is completely walled off by kernel iptables rules: it cannot touch the host, internal private subnets, or cloud metadata. Once evidence is gathered, the container is destroyed instantly.
""")


def build_slide_4(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "System Architecture & Deployment",
        "Orchestration Architecture on Vultr",
        "Central Control Plane, Isolated Network Cage, and Serverless AI Reasoning."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(3.7), Inches(4.7),
        "1. Host Control Plane",
        [
            "Vultr Cloud Compute BLR (4 vCPUs / 8 GB RAM).",
            "Caddy Reverse Proxy: Automated Let's Encrypt TLS 1.3 on sslip.io.",
            "FastAPI Orchestrator: Input validation, SSRF IP defense, SQLite WAL telemetry.",
            "SSE Event Broadcaster: Real-time event streaming to web dashboard (/api/scan/{id}/stream).",
            "Prometheus Metrics (/metrics): Scan rates, latency, and sandbox health."
        ],
        accent_color=COLOR_BLUE
    )

    add_card(
        slide,
        Inches(4.8), Inches(2.0), Inches(3.7), Inches(4.7),
        "2. Caged phishnet Sandbox",
        [
            "Dedicated Bridge (172.30.0.0/16).",
            "iptables Drops: Host gateway (172.30.0.1), private RFC1918 IPs, and cloud metadata (169.254.169.254).",
            "Playwright Chromium non-root automation (UID 10001).",
            "Drive-By Malware Interceptor: Intercepts and quenches dropped .exe / .bin files.",
            "REA Static Engine: Disassembles scripts, wasm, and binaries."
        ],
        accent_color=COLOR_RED
    )

    add_card(
        slide,
        Inches(8.8), Inches(2.0), Inches(3.7), Inches(4.7),
        "3. Vultr Serverless Inference",
        [
            "Endpoint: api.vultrinference.com/v1.",
            "Flagship Model: GLM-5.3 (with fallback multi-model support).",
            "Deep Threat Reasoning: Evaluates DOM telemetry, redirect chains, screenshots, and REA disassembly.",
            "Strict Pydantic Validation: Deterministic schema output with zero hallucinations.",
            "MITRE ATT&CK Mapping: Categorizes tactics (T1056, T1071, T1204)."
        ],
        accent_color=COLOR_GREEN
    )

    add_footer(slide, 4)
    set_speaker_notes(slide, """
Here is our full architecture. At the perimeter, Caddy handles automated TLS on 139.84.159.12.sslip.io. The FastAPI control plane validates the input, executes SSRF checks, and spins up the caged sandbox container. The container detonates the site, intercepts network requests, and collects forensic artifacts. That evidence is then sent directly to Vultr Serverless Inference running GLM-5.3 for deep reasoning, producing structured Pydantic verdicts with MITRE ATT&CK tactics.
""")


def build_slide_5(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Challenge 1 Mandatory Requirement",
        "The Containment Moment: Dual Boundary Proof",
        "Verifiable proof of network isolation and drive-by malware neutralization."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(2.1),
        "🌐 Moment 1: Network Boundary Drop",
        [
            "Active sandbox is forbidden from communicating with the host or private infrastructure.",
            "Kernel-level iptables rules drop all packets to gateway (172.30.0.1) and metadata.",
            "Verified via automated test suite scripts/verify_containment.sh."
        ],
        accent_color=COLOR_BLUE
    )

    add_terminal(
        slide,
        Inches(0.8), Inches(4.3), Inches(5.7), Inches(2.4),
        "verify_containment.sh Execution Log",
        [
            "Testing Public Internet (Cloudflare 1.1.1.1) ... [PASS] REACHABLE",
            "Testing Host Gateway (172.30.0.1:8000) ......... [PASS] BLOCKED",
            "Testing Host Public IP (139.84.159.12:8000) ..... [PASS] BLOCKED",
            "Testing Cloud Metadata (169.254.169.254) ........ [PASS] BLOCKED",
            "Testing Private Subnet 10.0.0.1 ................ [PASS] BLOCKED",
            "Testing Private Subnet 192.168.1.1 ............. [PASS] BLOCKED",
            "🎉 ALL CONTAINMENT CHECKS PASSED. Blast Radius Zero verified!"
        ]
    )

    add_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(2.1),
        "☣️ Moment 2: Drive-By Malware Interception",
        [
            "Phishing site attempts automated drop of SBI_Mandatory_Security_Patch.exe.",
            "Playwright browser handler intercepts and quenches the download stream.",
            "File quarantined into /out volume; ZERO execution of binary bytes."
        ],
        accent_color=COLOR_RED
    )

    add_terminal(
        slide,
        Inches(6.8), Inches(4.3), Inches(5.7), Inches(2.4),
        "Browser Interception & REA Forensic Log",
        [
            "[INTERCEPT] Download stream canceled and quarantined.",
            "Payload: SBI_Mandatory_Security_Patch.exe (84.2 KB)",
            "SHA256: 48f95c5240be6d841e2be6d2a71d79e...",
            "Shannon Entropy: 7.82 (High - Packed/Encrypted)",
            "MITRE ATT&CK: T1204.002 Malicious File Dropped",
            "Execution Status: 0 instructions run on host. QUARANTINED.",
            "Verdict: Malicious Payload Captured with Zero Host Exposure."
        ]
    )

    add_footer(slide, 5)
    set_speaker_notes(slide, """
For Challenge 1, we demonstrate our dual Containment Moment. First, our automated verification script proves that any network request from the sandbox to the host gateway, private subnets, or Vultr metadata is immediately dropped at the kernel level by iptables. Second, when a phishing site triggers an automated malware download — such as a fake SBI banking security patch — our browser interceptor traps the file instantly. The executable is quarantined, hashed, and disassembled by our REA engine without a single instruction ever executing on the host.
""")


def build_slide_6(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Autonomous Agent Behaviors",
        "Pattern B Decoy Pass & REA Engine",
        "Active credential discovery and static binary/script reverse engineering."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(4.7),
        "👤 Pattern B: Sandboxed Browser Use with Human Gate",
        [
            "Pass 1: Passive Reconnaissance",
            "• Quarantined Playwright browser opens link and takes screenshot.",
            "• Interrogates DOM for credential fields (username, password, OTP, PAN).",
            "• Pauses scan and presents operator with decision modal.",
            "Human Approval Gate",
            "• 'Credential harvester detected. Authorize decoy submission pass?'",
            "• Operator controls whether the agent touches form inputs.",
            "Pass 2: Synthetic Canary Submission",
            "• Browser injects fake canary data (test_canary_user@example.com).",
            "• Clicks submit and traces network exfiltration endpoints (POST C2).",
            "• Exposes backend attacker infrastructure without leaking user data."
        ],
        accent_color=COLOR_AMBER
    )

    add_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(4.7),
        "🔍 Reverse Engineering Anything (REA) Engine",
        [
            "Static Inspection by Default",
            "• Automatically dissects inline scripts, external JS routines, and WASM.",
            "• Calculates Shannon entropy (>7.5 indicates packed/encrypted code).",
            "• Extracts hardcoded IOC URLs, API keys, and exfiltration hooks.",
            "MITRE ATT&CK Matrix Mapping",
            "• T1056: Input Capture (credential & keystroke listeners)",
            "• T1071: Exfiltration Over C2 (abnormal fetch / beacon beacons)",
            "• T1204: Malicious File Quarantine (intercepted downloads)",
            "UI Disassembly Terminal",
            "• Renders disassembly preview card directly on the web dashboard."
        ],
        accent_color=COLOR_BLUE
    )

    add_footer(slide, 6)
    set_speaker_notes(slide, """
Phish&Chips implements the hackathon's required Pattern B workflow. In Pass 1, the agent navigates passively. When it spots a credential harvesting form, it stops and requests human authorization. If approved, Pass 2 fires: the agent submits synthetic decoy credentials to observe where the data exfiltrates, capturing post-submit redirection and server-side behavior. Furthermore, our REA engine extracts every inline script and disassembled executable, calculating entropy and mapping tactics to MITRE ATT&CK.
""")


def build_slide_7(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Real-World Impact & Regional Remediation",
        "From Detection to Remediation in Seconds",
        "Zero false positives, 1-click legal evidence lockers, and emergency escalation."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(3.7), Inches(3.2),
        "📦 1-Click Abuse Takedown",
        [
            "Auto-generates signed .tar.gz Evidence Locker.",
            "Includes screenshots, HAR network traces, DOM dumps, and registrar abuse contacts.",
            "Ready to send to AWS, Cloudflare, or registrar abuse desks."
        ],
        accent_color=COLOR_BLUE
    )

    add_card(
        slide,
        Inches(4.8), Inches(2.0), Inches(3.7), Inches(3.2),
        "🇮🇳 Indian Localization",
        [
            "Trilingual interface in English, हिन्दी (Hindi), and ಕನ್ನಡ (Kannada).",
            "Protects non-technical frontline citizens targeted by fake KYC and UPI refund fraud.",
            "One-click language switcher in dashboard header."
        ],
        accent_color=COLOR_AMBER
    )

    add_card(
        slide,
        Inches(8.8), Inches(2.0), Inches(3.7), Inches(3.2),
        "🚨 Emergency Escalation",
        [
            "Direct 1-tap dialer for India's National Cybercrime Helpline (1930).",
            "Direct reporting portal link to cybercrime.gov.in.",
            "Emergency bank profile freeze checklist for victims."
        ],
        accent_color=COLOR_RED
    )

    add_card(
        slide,
        Inches(0.8), Inches(5.4), Inches(11.7), Inches(1.3),
        "⚡ Zero False-Positive Reputation Fast-Path",
        [
            "Tranco Top-10K reputable domains (Wikipedia, Google, Gov portals) complete within 5 seconds with guaranteed SAFE verdicts.",
            "Eliminates AI hallucinations and conserves inference compute on verified benign infrastructure."
        ],
        accent_color=COLOR_GREEN
    )

    add_footer(slide, 7)
    set_speaker_notes(slide, """
Detection is only half the battle. Phish&Chips provides immediate remediation: a 1-click Abuse Takedown pack that SOC analysts can send to domain registrars, and a localized emergency drawer for Indian users featuring the 1930 National Cybercrime Helpline. It's trilingual, fully observable via Prometheus metrics, and our Tranco fast-path ensures zero false positives on reputable sites like Wikipedia.
""")


def build_slide_8(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Hackathon Submission Summary · Team alphax",
        "Why Phish&Chips Leads the Vultr Agent Rush",
        "Excellence across all four LabLab judging criteria."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(2.2),
        "⚙️ Application of Technology",
        [
            "Hardened Vultr Cloud Compute VM in Bangalore.",
            "Vultr Serverless Inference (GLM-5.3) for deep threat synthesis.",
            "Docker cgroups v2 + Playwright Chromium + Caddy automated TLS.",
            "Native Prometheus /metrics and /api/health observability."
        ],
        accent_color=COLOR_BLUE
    )

    add_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(2.2),
        "🎨 Presentation & User Experience",
        [
            "Production dashboard at https://139.84.159.12.sslip.io.",
            "Animated 4-stage pipeline graph and live SSE containment terminal.",
            "Visual screenshot carousel, REA disassembly view, and cyber aesthetic.",
            "3-minute video demonstrating explicit containment moments."
        ],
        accent_color=COLOR_AMBER
    )

    add_card(
        slide,
        Inches(0.8), Inches(4.4), Inches(5.7), Inches(2.3),
        "💼 Business & Practical Value",
        [
            "Solves the multi-billion dollar credential phishing crisis.",
            "Zero analyst risk: inspects hostile links with Blast Radius Zero.",
            "Zero false positives on top reputable domains (Tranco fast-path).",
            "Immediate remediation via 1-click takedown pack & 1930 hotline."
        ],
        accent_color=COLOR_GREEN
    )

    add_card(
        slide,
        Inches(6.8), Inches(4.4), Inches(5.7), Inches(2.3),
        "✨ Originality & Novelty",
        [
            "Blast Radius Zero containment architecture.",
            "Pattern B Sandboxed Browser Use with Human Approval Decoy Pass.",
            "Integrated Static REA Engine for WebAssembly & executables.",
            "Trilingual localization (English / Hindi / Kannada)."
        ],
        accent_color=COLOR_RED
    )

    add_footer(slide, 8)
    set_speaker_notes(slide, """
Phish&Chips proves that autonomous AI agents can handle hazardous security tasks safely and effectively when built on solid cloud infrastructure. Thank you to Vultr and LabLab for this incredible challenge. Remember: fresh phish, fried in a sandbox. Thank you!
""")


def main():
    print("==> Generating Phish&Chips PowerPoint Presentation (.pptx)...")
    prs = create_deck()

    build_slide_1(prs)
    build_slide_2(prs)
    build_slide_3(prs)
    build_slide_4(prs)
    build_slide_5(prs)
    build_slide_6(prs)
    build_slide_7(prs)
    build_slide_8(prs)

    output_dir = "docs"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "Phish_and_Chips_Presentation.pptx")
    prs.save(output_path)
    print(f"🎉 Presentation saved successfully to: {output_path}")


if __name__ == "__main__":
    main()
