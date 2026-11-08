#!/usr/bin/env python3
"""
Phish&Chips Executive Presentation (.pptx) Generator - Professional Redesign
Generates an executive-grade 8-slide presentation deck:
- 16:9 widescreen layout
- Modern dark executive palette (obsidian #0A0D14, elevated card surfaces #131825, subtle 1px strokes)
- High-res embedded cover image on Slide 1
- Zero overlapping or protruding sidebar shapes
- Plain English storytelling with deep technical precision
- Completely removes all 'native language' references
- Full speaker notes on every slide
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

# ==============================================================================
# COLOR PALETTE: Dark Executive Cyber Aesthetic
# ==============================================================================
COLOR_BG = RGBColor(10, 13, 20)           # Obsidian base (#0A0D14)
COLOR_CARD_BG = RGBColor(19, 24, 37)      # Elevated card surface (#131825)
COLOR_CARD_BORDER = RGBColor(32, 41, 62)  # Subtle clean border (#20293E)
COLOR_CARD_BORDER_ACCENT = RGBColor(0, 122, 255) # Vultr electric blue border

COLOR_RED = RGBColor(239, 68, 68)        # Threat / Alert Red (#EF4444)
COLOR_BLUE = RGBColor(0, 122, 255)       # Vultr Electric Blue (#007AFF)
COLOR_GREEN = RGBColor(16, 185, 129)     # Verified Safe / Emerald (#10B981)
COLOR_AMBER = RGBColor(245, 158, 11)     # Warning / Gold (#F59E0B)
COLOR_PURPLE = RGBColor(168, 85, 247)    # AI Reasoning (#A855F7)

COLOR_TEXT_WHITE = RGBColor(255, 255, 255) # Pure crisp white
COLOR_TEXT_PRIMARY = RGBColor(241, 245, 249) # Off-white body (#F1F5F9)
COLOR_TEXT_MUTED = RGBColor(148, 163, 184)   # Slate gray (#94A3B8)
COLOR_CODE_BG = RGBColor(13, 16, 24)        # Deep code background
COLOR_CODE_TEXT = RGBColor(167, 243, 208)    # Terminal mint green

FONT_HEADING = "Trebuchet MS"
FONT_BODY = "Calibri"
FONT_MONO = "Consolas"


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
    # Top slim progress line
    line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(0.05))
    line.fill.solid()
    line.fill.fore_color.rgb = tag_color
    line.line.color.rgb = tag_color

    # Header Text Box
    txBox = slide.shapes.add_textbox(Inches(0.8), Inches(0.38), Inches(11.733), Inches(1.3))
    tf = txBox.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    # Tag Badge
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
    p_title.font.size = Pt(25)
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_TEXT_WHITE
    p_title.space_after = Pt(3)

    # Subtitle
    p_sub = tf.add_paragraph()
    p_sub.text = subtitle_text
    p_sub.font.name = FONT_BODY
    p_sub.font.size = Pt(13)
    p_sub.font.color.rgb = COLOR_TEXT_MUTED


def add_clean_card(slide, left, top, width, height, badge_text, badge_color, title, items, border_color=COLOR_CARD_BORDER, body_size=Pt(11.5)):
    """
    Creates an executive-style card with a clean top badge pill, crisp title,
    subtle border stroke, and readable bullet hierarchy. No clunky side strips.
    """
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD_BG
    card.line.color.rgb = border_color
    card.line.width = Pt(1)

    tb = slide.shapes.add_textbox(left + Inches(0.25), top + Inches(0.2), width - Inches(0.5), height - Inches(0.4))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    # Top Badge Tag inside the card
    p_badge = tf.paragraphs[0]
    p_badge.text = badge_text.upper()
    p_badge.font.name = FONT_BODY
    p_badge.font.size = Pt(9.5)
    p_badge.font.bold = True
    p_badge.font.color.rgb = badge_color
    p_badge.space_after = Pt(4)

    # Card Title
    p_title = tf.add_paragraph()
    p_title.text = title
    p_title.font.name = FONT_HEADING
    p_title.font.size = Pt(15.5)
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_TEXT_WHITE
    p_title.space_after = Pt(8)

    # Body Bullets
    for item in items:
        p = tf.add_paragraph()
        p.text = f"•  {item}" if not item.startswith("•") and not item.startswith("http") else item
        p.font.name = FONT_BODY
        p.font.size = body_size
        p.font.color.rgb = COLOR_TEXT_PRIMARY
        p.space_after = Pt(5)


def add_terminal(slide, left, top, width, height, title, lines):
    term = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    term.fill.solid()
    term.fill.fore_color.rgb = COLOR_CODE_BG
    term.line.color.rgb = COLOR_CARD_BORDER
    term.line.width = Pt(1)

    tb = slide.shapes.add_textbox(left + Inches(0.25), top + Inches(0.18), width - Inches(0.5), height - Inches(0.36))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    p_head = tf.paragraphs[0]
    p_head.text = f"💻 {title}"
    p_head.font.name = FONT_MONO
    p_head.font.size = Pt(10.5)
    p_head.font.bold = True
    p_head.font.color.rgb = COLOR_BLUE
    p_head.space_after = Pt(5)

    for line in lines:
        p = tf.add_paragraph()
        p.text = line
        p.font.name = FONT_MONO
        p.font.size = Pt(9.5)
        if "[PASS]" in line or "Reachable" in line or "destroyed" in line or "Safe" in line:
            p.font.color.rgb = COLOR_GREEN
        elif "[BLOCKED]" in line or "ALERT" in line or "QUARANTINED" in line or "SCAM" in line:
            p.font.color.rgb = COLOR_RED
        elif "Testing" in line or "Entropy" in line or "Checking" in line:
            p.font.color.rgb = COLOR_AMBER
        else:
            p.font.color.rgb = COLOR_CODE_TEXT
        p.space_after = Pt(2)


def add_footer(slide, slide_num, total_slides=8):
    footer_box = slide.shapes.add_textbox(Inches(0.8), Inches(6.92), Inches(11.733), Inches(0.35))
    tf = footer_box.text_frame
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    p = tf.paragraphs[0]
    p.text = "Phish&Chips  ·  Track 01: Blast Radius Zero  ·  Live at https://139.84.159.12.sslip.io"
    p.font.name = FONT_BODY
    p.font.size = Pt(9.5)
    p.font.color.rgb = COLOR_TEXT_MUTED

    num_box = slide.shapes.add_textbox(Inches(11.5), Inches(6.92), Inches(1.0), Inches(0.35))
    tf_num = num_box.text_frame
    tf_num.margin_left = tf_num.margin_top = tf_num.margin_right = tf_num.margin_bottom = 0
    p_num = tf_num.paragraphs[0]
    p_num.alignment = PP_ALIGN.RIGHT
    p_num.text = f"{slide_num} / {total_slides}"
    p_num.font.name = FONT_MONO
    p_num.font.size = Pt(9.5)
    p_num.font.color.rgb = COLOR_TEXT_MUTED


def set_speaker_notes(slide, notes_text):
    notes = slide.notes_slide
    notes.notes_text_frame.text = notes_text.strip()


# ==============================================================================
# SLIDE BUILDERS (PROFESSIONAL REDESIGN)
# ==============================================================================

def build_slide_1(prs):
    """Slide 1: Executive Title with Hero Image split layout"""
    slide = add_base_slide(prs)

    # Top slim progress line
    line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(0.05))
    line.fill.solid()
    line.fill.fore_color.rgb = COLOR_RED
    line.line.color.rgb = COLOR_RED

    # Left Column: Branding, Value Proposition, Infrastructure
    left_tb = slide.shapes.add_textbox(Inches(0.8), Inches(0.55), Inches(6.5), Inches(6.1))
    tf = left_tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    # Tag Badge
    p_tag = tf.paragraphs[0]
    p_tag.text = "VULTR AGENT RUSH HACKATHON · TRACK 01: BLAST RADIUS ZERO"
    p_tag.font.name = FONT_BODY
    p_tag.font.size = Pt(10)
    p_tag.font.bold = True
    p_tag.font.color.rgb = COLOR_RED
    p_tag.space_after = Pt(6)

    # Hero Title
    p_title = tf.add_paragraph()
    p_title.text = "🐟🍟 Phish&Chips"
    p_title.font.name = FONT_HEADING
    p_title.font.size = Pt(32)
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_TEXT_WHITE
    p_title.space_after = Pt(4)

    # Tagline
    p_tagline = tf.add_paragraph()
    p_tagline.text = "Fresh phish, fried in a sandbox."
    p_tagline.font.name = FONT_BODY
    p_tagline.font.size = Pt(16)
    p_tagline.font.bold = True
    p_tagline.font.color.rgb = COLOR_AMBER
    p_tagline.space_after = Pt(16)

    # The Big Idea Narrative
    p_desc1 = tf.add_paragraph()
    p_desc1.text = "What if you could safely inspect ANY suspicious link with zero risk to your computer?"
    p_desc1.font.name = FONT_HEADING
    p_desc1.font.size = Pt(14)
    p_desc1.font.bold = True
    p_desc1.font.color.rgb = COLOR_TEXT_WHITE
    p_desc1.space_after = Pt(8)

    p_desc2 = tf.add_paragraph()
    p_desc2.text = "When attackers send deceptive links (fake banking portals, urgent KYC alerts, or invoice scams), visiting them normally risks credential theft and drive-by malware."
    p_desc2.font.name = FONT_BODY
    p_desc2.font.size = Pt(12)
    p_desc2.font.color.rgb = COLOR_TEXT_MUTED
    p_desc2.space_after = Pt(8)

    p_desc3 = tf.add_paragraph()
    p_desc3.text = "Phish&Chips opens hostile links inside an isolated, throwaway browser on Vultr Cloud. The threat is analyzed, neutralized, and destroyed in under 45 seconds—leaving your real computer 100% safe."
    p_desc3.font.name = FONT_BODY
    p_desc3.font.size = Pt(12)
    p_desc3.font.color.rgb = COLOR_TEXT_PRIMARY
    p_desc3.space_after = Pt(16)

    # Bottom Pill / Tech specs
    p_specs = tf.add_paragraph()
    p_specs.text = "⚡ Vultr Cloud Compute (BLR)  ·  Vultr Serverless Inference (GLM-5.3)  ·  Team alphax"
    p_specs.font.name = FONT_MONO
    p_specs.font.size = Pt(10)
    p_specs.font.color.rgb = COLOR_BLUE
    p_specs.space_after = Pt(4)

    p_url = tf.add_paragraph()
    p_url.text = "🌐 Live Production URL: https://139.84.159.12.sslip.io (Automated TLS 1.3)"
    p_url.font.name = FONT_MONO
    p_url.font.size = Pt(10)
    p_url.font.color.rgb = COLOR_GREEN

    # Right Column: Hero Cover Image inside a styled frame
    cover_path = "docs/cover_image.png"
    if os.path.exists(cover_path):
        frame = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(7.5), Inches(0.9), Inches(5.0), Inches(5.75))
        frame.fill.solid()
        frame.fill.fore_color.rgb = COLOR_CARD_BG
        frame.line.color.rgb = COLOR_CARD_BORDER_ACCENT
        frame.line.width = Pt(1.5)

        slide.shapes.add_picture(cover_path, Inches(7.6), Inches(1.0), Inches(4.8), Inches(4.8 * (9/16)))

        # Image caption box
        cap_tb = slide.shapes.add_textbox(Inches(7.6), Inches(3.9), Inches(4.8), Inches(2.6))
        cap_tf = cap_tb.text_frame
        cap_tf.word_wrap = True
        cap_tf.margin_left = cap_tf.margin_top = cap_tf.margin_right = cap_tf.margin_bottom = 0

        p_c1 = cap_tf.paragraphs[0]
        p_c1.text = "THE CONTAINMENT CAGE IN ACTION"
        p_c1.font.name = FONT_BODY
        p_c1.font.size = Pt(10.5)
        p_c1.font.bold = True
        p_c1.font.color.rgb = COLOR_RED
        p_c1.space_after = Pt(4)

        p_c2 = cap_tf.add_paragraph()
        p_c2.text = "Every detonation takes place within an isolated, unprivileged container governed by strict Linux cgroups limits and kernel firewalls. Even the most aggressive zero-day malware cannot break out."
        p_c2.font.name = FONT_BODY
        p_c2.font.size = Pt(11)
        p_c2.font.color.rgb = COLOR_TEXT_MUTED
        p_c2.space_after = Pt(4)

        p_c3 = cap_tf.add_paragraph()
        p_c3.text = "🍟 Phish fried. Sandbox destroyed."
        p_c3.font.name = FONT_MONO
        p_c3.font.size = Pt(10.5)
        p_c3.font.bold = True
        p_c3.font.color.rgb = COLOR_AMBER

    add_footer(slide, 1)
    set_speaker_notes(slide, """
Welcome to Phish&Chips!
In plain English: we solve the dangerous dilemma of clicking suspicious links.
When someone receives an urgent alert claiming their bank account is locked or offering an instant tax refund, they normally have only two bad choices: click it and risk getting hacked, or ignore it and stay blind.
Phish&Chips gives everyone a safe third option. You paste the link into Phish&Chips, and our autonomous agent opens it inside a sealed, throwaway browser running on Vultr Cloud. The agent inspects the visual interface, disassembles hidden background code, quenches any dropped viruses in mid-air, and delivers a clear verdict using Vultr Serverless Inference with GLM-5.3. When finished, the sandbox is vaporized. Zero risk, zero blast radius.
""")


def build_slide_2(prs):
    """Slide 2: The Crisis - 3 clear problem pillars + 1 core takeaway"""
    slide = add_base_slide(prs)
    add_header(
        slide,
        "The Threat Landscape · Multi-Billion Dollar Crisis",
        "The Real-World Crisis: Why Traditional Security Fails",
        "Why clicking a single link can compromise an organization—and why blocklists are too slow."
    )

    add_clean_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(3.7), Inches(3.2),
        "01 · The Deceptive Lure",
        COLOR_AMBER,
        "Urgent Social Engineering",
        [
            "Scammers send urgent SMS messages or emails mimicking banks, utility providers, and couriers.",
            "Crafted psychological urgency: 'Your account is frozen. Verify identity within 24 hours.'",
            "Targets both everyday consumers and corporate employees on mobile devices."
        ]
    )

    add_clean_card(
        slide,
        Inches(4.8), Inches(2.0), Inches(3.7), Inches(3.2),
        "02 · The Silent Trap",
        COLOR_RED,
        "Stealth Exploits & Theft",
        [
            "Victims land on an exact visual replica of their trusted banking or enterprise login portal.",
            "While entering credentials, the site silently triggers a background download of disguised malware.",
            "Obfuscated JavaScript and WebAssembly evade client-side browser protections."
        ]
    )

    add_clean_card(
        slide,
        Inches(8.8), Inches(2.0), Inches(3.7), Inches(3.2),
        "03 · Reactive Blocklists",
        COLOR_BLUE,
        "4 to 8 Hour Lifespans",
        [
            "Scammers register, abuse, and abandon dynamic domains every few hours.",
            "Traditional antivirus and DNS blocklists take days to detect and update feeds.",
            "By the time a blocklist updates, thousands of credentials have already been exfiltrated."
        ]
    )

    add_clean_card(
        slide,
        Inches(0.8), Inches(5.35), Inches(11.733), Inches(1.35),
        "💡 The Core Dilemma",
        COLOR_GREEN,
        "Why Analysts & Consumers Are Stuck",
        [
            "Security teams cannot safely inspect a suspicious website because opening the link on their own network risks workstation compromise and lateral movement.",
            "We needed active, containment-first detonation: visiting hostile links without exposing host infrastructure."
        ],
        body_size=Pt(11.5)
    )

    add_footer(slide, 2)
    set_speaker_notes(slide, """
Here is the everyday reality: phishing is a multi-billion dollar crisis because it exploits human urgency and trust.
Attackers send messages that look identical to official bank notices or corporate portals. But traditional security defenses are fundamentally reactive. A scam website only stays online for 4 to 8 hours. By the time security feeds flag it, the attackers have already moved on.
Worse, if a security analyst wants to verify a link, just opening it puts their own computer at risk of drive-by malware. We needed an active, containment-first defense.
""")


def build_slide_3(prs):
    """Slide 3: Blast Radius Zero - 4 ironclad containment guarantees"""
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Core Philosophy · Track 01 Mandate",
        "What Does 'Blast Radius Zero' Mean in Plain English?",
        "Four ironclad guarantees that ensure dangerous websites can never escape or harm anyone."
    )

    add_clean_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(2.2),
        "01 · The Disposable Room",
        COLOR_RED,
        "The Ephemeral Sandbox",
        [
            "Every link is opened in a freshly spawned virtual browser on our remote Vultr server.",
            "Completely isolated from your computer, your browser, cookies, and local files.",
            "The website interacts with a blank, quarantined environment that holds zero user data."
        ]
    )

    add_clean_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(2.2),
        "02 · Privilege Stripping",
        COLOR_BLUE,
        "Hands Tied Behind Its Back",
        [
            "The browser runs under an unprivileged user (runner, UID 10001).",
            "All Linux capabilities are permanently stripped (--cap-drop=ALL).",
            "Root filesystem is strictly mounted read-only (--read-only); system changes are impossible."
        ]
    )

    add_clean_card(
        slide,
        Inches(0.8), Inches(4.45), Inches(5.7), Inches(2.25),
        "03 · Network Shield",
        COLOR_AMBER,
        "Walled Off from Infrastructure",
        [
            "Strict kernel iptables rules isolate the phishnet bridge.",
            "Drops all traffic attempting to reach the host gateway, internal networks, or cloud metadata.",
            "The browser can only reach the target public link—never internal resources."
        ]
    )

    add_clean_card(
        slide,
        Inches(6.8), Inches(4.45), Inches(5.7), Inches(2.25),
        "04 · Total Ephemerality",
        COLOR_GREEN,
        "Vaporized in Under 45 Seconds",
        [
            "The moment telemetry is captured, the entire container is permanently deleted (--rm).",
            "A background janitor purges orphan containers and stale memory buffers.",
            "Zero persistence guaranteed: '🍟 Phish fried. Sandbox destroyed.'"
        ]
    )

    add_footer(slide, 3)
    set_speaker_notes(slide, """
What does 'Blast Radius Zero' mean in plain language?
It means that even if a link contains the nastiest zero-day exploit or malicious virus in existence, its blast radius is exactly zero.
The link is opened inside a throwaway container that has no administrator privileges, cannot modify files, is firewalled away from our server, and is destroyed in under 45 seconds. Even if the website tries to explode, it explodes inside an empty concrete bunker.
""")


def build_slide_4(prs):
    """Slide 4: System Architecture - 3-stage visual pipeline"""
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Cloud & AI Infrastructure · Orchestration Pipeline",
        "End-to-End Orchestration Architecture on Vultr",
        "How Vultr Cloud Compute and Serverless Inference power the entire investigation lifecycle."
    )

    add_clean_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(3.7), Inches(4.7),
        "Stage 01 · Ingress & Control",
        COLOR_BLUE,
        "Host Control Plane",
        [
            "Vultr Cloud Compute (BLR Region): Hardened Ubuntu 24.04 LTS host (4 vCPUs / 8 GB RAM / 160 GB SSD).",
            "Caddy Reverse Proxy: Automated Let's Encrypt TLS 1.3 on sslip.io.",
            "FastAPI Control Plane: Enforces SSRF defense, prevents private IP scans, and governs concurrency slots.",
            "Server-Sent Events (SSE): Streams real-time containment events (/api/scan/{id}/stream) to web dashboard.",
            "Prometheus Metrics: Live telemetry at /metrics and /api/health."
        ],
        body_size=Pt(11)
    )

    add_clean_card(
        slide,
        Inches(4.8), Inches(2.0), Inches(3.7), Inches(4.7),
        "Stage 02 · Detonation",
        COLOR_RED,
        "Caged phishnet Sandbox",
        [
            "Dedicated Bridge (172.30.0.0/16): Isolated Docker container governed by cgroups v2 resource clamps.",
            "Headless Playwright: Stealth browser navigates target URL, captures screenshots, and monitors redirects.",
            "Malware Quencher: Intercepts and blocks drive-by executable downloads in mid-air.",
            "Static REA Engine: Disassembles client-side JavaScript, WebAssembly routines, and binary drops."
        ],
        body_size=Pt(11)
    )

    add_clean_card(
        slide,
        Inches(8.8), Inches(2.0), Inches(3.7), Inches(4.7),
        "Stage 03 · AI Synthesis",
        COLOR_PURPLE,
        "Vultr Serverless Inference",
        [
            "Endpoint: api.vultrinference.com/v1.",
            "Flagship Model: GLM-5.3 deep threat reasoning engine (with multi-model fallback).",
            "Evidence Fusion: Synthesizes visual screenshots, DOM input fields, redirect hops, and REA disassembly.",
            "Strict Pydantic Validation: Deterministic schema enforcement eliminates model hallucinations.",
            "MITRE ATT&CK Mapping: Tags tactics (T1056 Input Capture, T1071 C2 Exfiltration, T1204 Malicious File)."
        ],
        body_size=Pt(11)
    )

    add_footer(slide, 4)
    set_speaker_notes(slide, """
Here is the full architecture of Phish&Chips.
At the edge, Caddy handles automated TLS on 139.84.159.12.sslip.io.
Our central FastAPI control plane on a hardened Vultr Cloud Compute VM in Bangalore validates the input, runs SSRF security checks, and spawns the caged sandbox.
The sandbox detonates the link, captures network requests, intercepts drive-by downloads, and extracts all code artifacts.
All that evidence is then sent directly to Vultr Serverless Inference running GLM-5.3, which analyzes the evidence and outputs a structured Pydantic verdict with MITRE ATT&CK mapping.
""")


def build_slide_5(prs):
    """Slide 5: Challenge 1 - Dual Containment Moments with side-by-side terminal logs"""
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Challenge 1 Mandatory Proof",
        "The Containment Moment: Trapping Threats in Mid-Air",
        "Two real moments where the platform catches and neutralizes attacks in real time."
    )

    add_clean_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(2.0),
        "Moment 01 · Network Shield",
        COLOR_BLUE,
        "Kernel-Level Firewall Drop",
        [
            "What if malicious code inside the sandbox tries to hack the host server?",
            "Kernel iptables rules drop all packets to the host gateway, corporate subnets, and cloud metadata.",
            "The threat is locked inside the container with zero avenues for lateral movement."
        ],
        body_size=Pt(11)
    )

    add_terminal(
        slide,
        Inches(0.8), Inches(4.15), Inches(5.7), Inches(2.6),
        "verify_containment.sh Execution Log",
        [
            "Checking Internet access (Cloudflare 1.1.1.1) .... [PASS] Reachable",
            "Checking Host Server Gateway (172.30.0.1:8000) .. [PASS] BLOCKED",
            "Checking Host Public IP (139.84.159.12) ........ [PASS] BLOCKED",
            "Checking Cloud Metadata (169.254.169.254) ...... [PASS] BLOCKED",
            "Checking Private Corporate Subnets (10.0.0.1) .. [PASS] BLOCKED",
            "Checking Private Corporate Subnets (192.168.1.1) [PASS] BLOCKED",
            "🎉 RESULT: All unauthorized exits are 100% BLOCKED."
        ]
    )

    add_clean_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(2.0),
        "Moment 02 · Malware Quencher",
        COLOR_RED,
        "Drive-By Executable Interception",
        [
            "When detonating demo://fake-bank, the page attempts an automated download of SBI_Mandatory_Security_Patch.exe.",
            "Our Playwright interceptor catches the download stream in mid-air and halts it.",
            "Quarantined into isolated storage; ZERO instructions executed on host system!"
        ],
        body_size=Pt(11)
    )

    add_terminal(
        slide,
        Inches(6.8), Inches(4.15), Inches(5.7), Inches(2.6),
        "Playwright Intercept & Forensic Quarantine Log",
        [
            "[ALERT] Hostile page attempted drive-by download!",
            "File: SBI_Mandatory_Security_Patch.exe (84.2 KB)",
            "Action: Download stream canceled and quarantined mid-air.",
            "Entropy Analysis: 7.82 / 8.0 (Packed / Obfuscated virus)",
            "Execution State: 0 lines of code executed on host.",
            "MITRE ATT&CK: T1204.002 Malicious File Dropped",
            "Status: QUARANTINED into isolated storage for inspection."
        ]
    )

    add_footer(slide, 5)
    set_speaker_notes(slide, """
For Challenge 1, we demonstrate our dual Containment Moments.
In Moment 1: our firewall verification script proves that the sandbox cannot reach our server gateway, internal company subnets, or Vultr cloud metadata. Any attempt to reach the host is blocked at the kernel level.
In Moment 2: when a scam banking site tries to secretly download a fake security update, our browser catches the file in mid-air. It cancels the download before it touches the operating system, hashes it, and inspects its code without ever running a single instruction. That is real containment.
""")


def build_slide_6(prs):
    """Slide 6: Agent Behaviors - Pattern B Decoy Pass & REA Static Code X-Ray"""
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Autonomous Agent Capabilities",
        "Smart Agent Features: Decoy Pass & Code X-Ray",
        "How the AI tricks scammers and inspects hidden code without user risk."
    )

    add_clean_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(4.7),
        "Pattern B · The Decoy Pass",
        COLOR_AMBER,
        "Human-in-the-Loop Credential Trapping",
        [
            "Pass 1: Passive Reconnaissance",
            "• The browser loads the untrusted link and inspects DOM input fields.",
            "• Identifies credential harvesters (username, password, PIN, OTP fields).",
            "• Pauses execution and alerts the human operator via a modal dialog.",
            "The Human Safety Gate",
            "• Modal asks: 'Credential harvester detected. Authorize unprivileged container to inject decoy canary credentials?'",
            "• Operator retains total control over whether the agent submits data.",
            "Pass 2: Synthetic Decoy Submission",
            "• If approved, browser types synthetic dummy data (test_canary_user).",
            "• Clicks Submit and tracks post-submission HTTP POST requests.",
            "• Unmasks the attacker's true C2 exfiltration server without leaking real user data!"
        ],
        body_size=Pt(11)
    )

    add_clean_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(4.7),
        "REA Engine · The Code X-Ray",
        COLOR_BLUE,
        "Static Reverse Engineering by Default",
        [
            "Automated Static Code Analysis",
            "• Every single scan automatically x-rays all inline scripts, external JS files, WebAssembly routines, and dropped binaries.",
            "• Evaluates code without running binary instructions on host.",
            "Shannon Entropy Scoring",
            "• Normal JavaScript has readable entropy (~4.5 to 5.5).",
            "• Packed, encrypted, or obfuscated malware scores >7.5.",
            "• High entropy triggers immediate MITRE ATT&CK T1027 tags.",
            "MITRE ATT&CK Matrix Mapping",
            "• T1056: Input Capture (credential listeners, keystroke loggers)",
            "• T1071: Exfiltration Over C2 (hidden fetch beacons)",
            "• T1204: Malicious File Quarantine (intercepted downloads)",
            "• UI Disassembly Card: Renders decompiled code previews directly on dashboard."
        ],
        body_size=Pt(11)
    )

    add_footer(slide, 6)
    set_speaker_notes(slide, """
Phish&Chips implements the hackathon's required Pattern B workflow.
In plain terms: when the AI sees a login box, it stops and asks the user for permission.
If approved, it executes the 'Fake Decoy' trick: feeding fake dummy credentials into the scam form to see where the data gets sent. This exposes the scammer's backend server while keeping real user information 100% safe.
At the same time, our REA engine acts like an X-ray machine: analyzing the hidden code on the page, checking if it's scrambled to evade antivirus, and translating the findings into clear categories.
""")


def build_slide_7(prs):
    """Slide 7: Practical Remediation - COMPLETELY REPLACES 'In Your Native Language'"""
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Practical Remediation & Real-World Utility",
        "From Threat Detection to Immediate Action",
        "Giving SOC teams, fraud desks, and everyday users the exact tools to shut down fraud."
    )

    add_clean_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(3.7), Inches(3.2),
        "01 · Abuse Takedown",
        COLOR_BLUE,
        "1-Click Evidence Locker",
        [
            "Don't just detect scams—shut them down.",
            "Auto-generates a signed .tar.gz Evidence Locker containing visual screenshots, HAR network traces, DOM dumps, and whois data.",
            "Includes pre-formatted registrar abuse desk complaint emails."
        ]
    )

    add_clean_card(
        slide,
        Inches(4.8), Inches(2.0), Inches(3.7), Inches(3.2),
        "02 · SOC Incident Triage",
        COLOR_AMBER,
        "Structured Telemetry",
        [
            "Exports standardized JSON incident reports ready for SIEM/SOAR ingestion (Splunk, Sentinel, Cortex).",
            "Includes complete MITRE ATT&CK tagging and indicator of compromise (IOC) lists.",
            "Enables enterprise security teams to block IOCs fleet-wide in seconds."
        ]
    )

    add_clean_card(
        slide,
        Inches(8.8), Inches(2.0), Inches(3.7), Inches(3.2),
        "03 · Emergency Escalation",
        COLOR_RED,
        "1-Tap Helpline Integration",
        [
            "Direct 1-tap dialer for the National Cybercrime Helpline (1930).",
            "Direct link to cybercrime.gov.in reporting portal.",
            "Emergency bank profile freeze checklist for victims whose credentials were compromised."
        ]
    )

    add_clean_card(
        slide,
        Inches(0.8), Inches(5.35), Inches(11.733), Inches(1.35),
        "⚡ Zero False-Positive Fast-Path",
        COLOR_GREEN,
        "Trusted Websites Pass in Under 3 Seconds",
        [
            "Nobody likes a security tool that cries wolf. Phish&Chips checks the Tranco Top-10K reputable domains (Wikipedia, Google, Gov portals).",
            "Scanning Wikipedia verifies in under 3 seconds with a guaranteed SAFE verdict—eliminating hallucinations and conserving inference compute."
        ],
        body_size=Pt(11.5)
    )

    add_footer(slide, 7)
    set_speaker_notes(slide, """
Finding a scam is only half the battle. What do you do once you find one?
Phish&Chips gives users immediate, practical remediation.
First: a 1-click abuse takedown pack that you can email to the hosting provider to get the fake website shut down.
Second: structured SOC incident escalation with full MITRE ATT&CK tagging and IOC export for enterprise SIEMs.
Third: an emergency helpline drawer with a 1-tap dialer for the 1930 Cybercrime helpline and bank freeze checklists.
And finally, trusted websites like Wikipedia are verified in under 3 seconds with zero false alarms via our Tranco fast-path.
""")


def build_slide_8(prs):
    """Slide 8: Hackathon Summary & Judge Scorecard Matrix"""
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Hackathon Evaluation Summary · Team alphax",
        "Why Phish&Chips Stands Out: Judge Scorecard",
        "Excellence across all four LabLab judging criteria."
    )

    add_clean_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(2.2),
        "⚙️ Application of Technology",
        COLOR_BLUE,
        "Production Vultr Integration",
        [
            "Hardened Vultr Cloud Compute VM in Bangalore.",
            "Vultr Serverless Inference (GLM-5.3) for deep threat reasoning.",
            "Docker cgroups v2, Caddy automated TLS, and Prometheus metrics."
        ]
    )

    add_clean_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(2.2),
        "🎨 Presentation & Clarity",
        COLOR_AMBER,
        "Intuitive User Experience",
        [
            "Production dashboard at https://139.84.159.12.sslip.io.",
            "Animated 4-stage pipeline graph and real-time streaming terminal.",
            "Plain-English reports with zero jargon barriers and visual proof."
        ]
    )

    add_clean_card(
        slide,
        Inches(0.8), Inches(4.45), Inches(5.7), Inches(2.25),
        "💼 Business & Practical Value",
        COLOR_GREEN,
        "Real-World Fraud Prevention",
        [
            "Protects everyday citizens and enterprise SOC teams from multi-billion dollar scams.",
            "Zero analyst risk: Blast Radius Zero guarantees safe investigation.",
            "Immediate remediation via 1-click takedown pack and 1930 helpline."
        ]
    )

    add_clean_card(
        slide,
        Inches(6.8), Inches(4.45), Inches(5.7), Inches(2.25),
        "✨ Originality & Novelty",
        COLOR_RED,
        "Unique Agentic Architecture",
        [
            "True containment-first design: sandbox vaporized after each scan.",
            "Pattern B Human Approval Decoy Pass outsmarts scammers with fake data.",
            "Built-in code x-ray (REA Engine) for WebAssembly and binary drops."
        ]
    )

    add_footer(slide, 8)
    set_speaker_notes(slide, """
To summarize: Phish&Chips proves that autonomous AI agents can handle dangerous cybersecurity tasks safely when built on Vultr's world-class cloud infrastructure.
It excels on technology by combining Vultr Cloud Compute and Vultr Serverless Inference with hardened containers. It excels on presentation with real-time streaming and plain-English clarity. It delivers massive real-world business and human value. And its Blast Radius Zero architecture is truly original.
Thank you to Vultr and LabLab. Remember: fresh phish, fried in a sandbox. Thank you!
""")


def main():
    print("==> Generating Professional Redesigned Phish&Chips Presentation (.pptx)...")
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
    print(f"🎉 Redesigned presentation saved successfully to: {output_path}")


if __name__ == "__main__":
    main()
