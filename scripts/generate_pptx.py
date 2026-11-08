#!/usr/bin/env python3
"""
Phish&Chips PowerPoint (.pptx) Generator - Plain English Edition
Generates an 8-slide, 16:9 presentation deck that explains everything
happening in clear, accessible, plain English while highlighting all
Vultr hackathon criteria, Challenge 1 containment, and technical rigor.
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
    # Top progress line
    line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(0.06))
    line.fill.solid()
    line.fill.fore_color.rgb = tag_color
    line.line.color.rgb = tag_color

    # Header Text Box
    txBox = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.733), Inches(1.35))
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
    p_title.space_after = Pt(4)

    # Subtitle
    p_sub = tf.add_paragraph()
    p_sub.text = subtitle_text
    p_sub.font.name = FONT_BODY
    p_sub.font.size = Pt(13)
    p_sub.font.color.rgb = COLOR_TEXT_MUTED


def add_card(slide, left, top, width, height, title, items, accent_color=COLOR_BLUE, bg_color=COLOR_CARD, title_size=Pt(16), body_size=Pt(11.5)):
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
    p_title.font.size = title_size
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_TEXT_WHITE
    p_title.space_after = Pt(8)

    # Items / Paragraphs
    for item in items:
        p = tf.add_paragraph()
        p.text = item
        p.font.name = FONT_BODY
        p.font.size = body_size
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
    p_head.font.size = Pt(10.5)
    p_head.font.bold = True
    p_head.font.color.rgb = COLOR_BLUE
    p_head.space_after = Pt(4)

    for line in lines:
        p = tf.add_paragraph()
        p.text = line
        p.font.name = FONT_MONO
        p.font.size = Pt(9.5)
        if "[PASS]" in line or "blocked" in line or "Safe" in line or "destroyed" in line:
            p.font.color.rgb = COLOR_GREEN
        elif "[BLOCKED]" in line or "INTERCEPT" in line or "QUARANTINED" in line or "SCAM" in line:
            p.font.color.rgb = COLOR_RED
        elif "Testing" in line or "NOTE" in line or "WHAT HAPPENS" in line:
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
# SLIDES: PLAIN ENGLISH & INTUITIVE FOR ANY READER
# ==============================================================================

def build_slide_1(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Vultr Agent Rush Hackathon · Track 01: Blast Radius Zero",
        "🐟🍟 Phish&Chips",
        "What if you could safely inspect ANY suspicious link with zero risk to your computer?"
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(3.2),
        "🛡️ The Big Idea: Blast Radius Zero",
        [
            "Imagine getting a suspicious SMS claiming your bank account is locked or offering an urgent tax refund.",
            "Opening the link on your phone or laptop could steal your passwords or secretly install malware.",
            "Phish&Chips opens the link for you inside a throwaway, digital containment room on Vultr Cloud. The threat is analyzed, dismantled, and deleted in seconds—leaving your real computer completely untouched."
        ],
        accent_color=COLOR_RED,
        body_size=Pt(12)
    )

    add_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(3.2),
        "⚡ Powered by Vultr Cloud & AI",
        [
            "Vultr Cloud Compute Host: A secure cloud server in Bangalore that manages every investigation and runs the isolated sandboxes.",
            "Vultr Serverless Inference (GLM-5.3): A smart AI reasoning engine that examines the visual webpage, hidden code, and network trails to give you a plain-English verdict.",
            "Complete Isolation: Built-in firewalls ensure malicious websites cannot talk to our server, access private files, or reach other computers."
        ],
        accent_color=COLOR_BLUE,
        body_size=Pt(12)
    )

    add_card(
        slide,
        Inches(0.8), Inches(5.4), Inches(11.7), Inches(1.3),
        "🌐 Live & Ready to Test",
        [
            "Live Production Website: https://139.84.159.12.sslip.io  (Fully secure HTTPS)",
            "Team: alphax  |  Status: 100% Operational  |  Try testing demo://fake-bank or https://wikipedia.org right now!"
        ],
        accent_color=COLOR_GREEN,
        body_size=Pt(12)
    )

    add_footer(slide, 1)
    set_speaker_notes(slide, """
Welcome to Phish&Chips!
In plain English: we solve the dangerous dilemma of clicking suspicious links.
When someone sends you a fake bank alert or a fishy KYC text, you normally have only two bad options: click it and risk getting hacked, or ignore it and stay in the dark.
Phish&Chips gives you a safe third option. You give us the link, and our autonomous agent opens it inside a sealed, throwaway browser on Vultr Cloud. The agent looks at the page, tests the forms, intercepts any viruses, and uses Vultr's GLM-5.3 AI to tell you exactly what it found. When it's done, the entire virtual room is destroyed. Zero risk, zero blast radius.
""")


def build_slide_2(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "The Everyday Phishing Trap",
        "The Real-World Crisis & Why Antivirus Isn't Enough",
        "Why clicking a single link can drain a bank account, and why traditional security tools fail."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(3.7), Inches(3.1),
        "📩 1. The Deceptive Lure",
        [
            "Scammers send urgent SMS messages or emails pretending to be State Bank of India, electricity providers, or courier deliveries.",
            "They create panic: 'Update your KYC within 24 hours or your account will be frozen!'"
        ],
        accent_color=COLOR_AMBER,
        body_size=Pt(12)
    )

    add_card(
        slide,
        Inches(4.8), Inches(2.0), Inches(3.7), Inches(3.1),
        "🪤 2. The Silent Trap",
        [
            "Victims land on an exact clone of their bank's login portal.",
            "While the user types their credentials, the site silently triggers a background download of a disguised virus or spyware."
        ],
        accent_color=COLOR_RED,
        body_size=Pt(12)
    )

    add_card(
        slide,
        Inches(8.8), Inches(2.0), Inches(3.7), Inches(3.1),
        "⏳ 3. Blocklists Are Too Slow",
        [
            "Scammers create new web addresses every 4 to 8 hours.",
            "By the time traditional antivirus companies add a site to their blocklist, thousands of people have already been scammed."
        ],
        accent_color=COLOR_BLUE,
        body_size=Pt(12)
    )

    add_card(
        slide,
        Inches(0.8), Inches(5.3), Inches(11.7), Inches(1.4),
        "💡 The Core Problem",
        [
            "Security analysts and everyday users cannot safely inspect a suspicious website because opening the link on their device could infect their workstation or expose corporate credentials. We needed a way to visit the danger zone without being in danger."
        ],
        accent_color=COLOR_GREEN,
        body_size=Pt(12)
    )

    add_footer(slide, 2)
    set_speaker_notes(slide, """
Here is the everyday reality: phishing is a multi-billion dollar crisis because it exploits urgency and trust.
Attackers send messages that look identical to official bank notices or electricity bills. But traditional security defenses are fundamentally reactive. A scam website only stays online for a few hours. By the time security blocklists flag it, the attackers have already moved to a new domain.
Worse, if a security analyst wants to verify a link, just opening it puts their own computer at risk of drive-by malware. We needed an active, containment-first defense.
""")


def build_slide_3(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "How We Keep You Safe · Track 01 Mandate",
        "What Does 'Blast Radius Zero' Mean in Plain English?",
        "Four simple rules that guarantee dangerous websites can never escape or harm anyone."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(2.2),
        "🚪 1. A Disposable Digital Room (The Sandbox)",
        [
            "Every link is opened in a freshly created virtual browser.",
            "It has no connection to your computer, your browser, or your personal files. It runs on a remote Vultr server."
        ],
        accent_color=COLOR_RED,
        body_size=Pt(11.5)
    )

    add_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(2.2),
        "🤐 2. Hands Tied Behind Its Back (Process Stripping)",
        [
            "The browser has all administrator powers permanently stripped away.",
            "It cannot install new programs, change system settings, or view any passwords or cloud keys."
        ],
        accent_color=COLOR_BLUE,
        body_size=Pt(11.5)
    )

    add_card(
        slide,
        Inches(0.8), Inches(4.4), Inches(5.7), Inches(2.3),
        "🧱 3. Walled Off from the World (Network Shield)",
        [
            "Strict firewall rules block the sandbox from talking to the host server, internal corporate networks, or cloud account metadata.",
            "The browser can only load the target webpage—nothing else."
        ],
        accent_color=COLOR_AMBER,
        body_size=Pt(11.5)
    )

    add_card(
        slide,
        Inches(6.8), Inches(4.4), Inches(5.7), Inches(2.3),
        "💥 4. Vaporized in 45 Seconds (Total Ephemerality)",
        [
            "The moment the investigation finishes, the entire digital room is permanently destroyed.",
            "Nothing survives. Zero trace, zero persistence: 'Phish fried. Sandbox destroyed.'"
        ],
        accent_color=COLOR_GREEN,
        body_size=Pt(11.5)
    )

    add_footer(slide, 3)
    set_speaker_notes(slide, """
What does 'Blast Radius Zero' mean in plain language?
It means that even if a link contains the nastiest zero-day exploit or malicious virus in existence, its blast radius is exactly zero.
The link is opened inside a throwaway container that has no administrator privileges, cannot modify files, is firewalled away from our server, and is destroyed in under 45 seconds. Even if the website tries to explode, it explodes inside an empty concrete bunker.
""")


def build_slide_4(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Under the Hood · Orchestration Pipeline",
        "How Phish&Chips Works Step-by-Step",
        "What actually happens behind the scenes from the moment you paste a URL."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(3.7), Inches(4.7),
        "Step 1: The Request",
        [
            "1. You paste a suspicious link into the dashboard at 139.84.159.12.sslip.io.",
            "2. Our central FastAPI control plane checks the URL to ensure it isn't an internal address.",
            "3. It prepares an isolated virtual sandbox slot (limiting server load to prevent overload).",
            "4. A live animated graph shows the investigation starting in real time."
        ],
        accent_color=COLOR_BLUE,
        body_size=Pt(12)
    )

    add_card(
        slide,
        Inches(4.8), Inches(2.0), Inches(3.7), Inches(4.7),
        "Step 2: The Detonation",
        [
            "1. An unprivileged headless browser enters the quarantined 'phishnet' network.",
            "2. It navigates to the untrusted link, taking visual screenshots and recording every hop.",
            "3. If the page tries to drop an executable file, the interceptor traps it immediately.",
            "4. Our REA engine extracts and disassembles all hidden scripts on the page."
        ],
        accent_color=COLOR_RED,
        body_size=Pt(12)
    )

    add_card(
        slide,
        Inches(8.8), Inches(2.0), Inches(3.7), Inches(4.7),
        "Step 3: The AI Verdict",
        [
            "1. Forensic telemetry, code snippets, and screenshots are sent to Vultr Serverless Inference.",
            "2. Flagship AI model GLM-5.3 reasons through all evidence like a senior security analyst.",
            "3. It delivers a clear verdict: SAFE, SUSPICIOUS, or SCAM with confidence scores.",
            "4. The container is destroyed, and the user receives a clean report."
        ],
        accent_color=COLOR_GREEN,
        body_size=Pt(12)
    )

    add_footer(slide, 4)
    set_speaker_notes(slide, """
Here is the step-by-step journey of an investigation in plain English.
First: you paste a link. Our control plane on Vultr validates it and spins up the digital sandbox.
Second: the quarantined browser visits the site, snaps screenshots, logs redirect hops, and traps any hidden viruses or credential forms.
Third: all that evidence is handed over to Vultr Serverless Inference. Our GLM-5.3 AI reviews everything and gives you a definitive, easy-to-understand verdict. Then the sandbox is vaporized.
""")


def build_slide_5(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Challenge 1 Mandatory Proof",
        "The Containment Moment: Trapping the Threat Live",
        "Two real moments where the platform catches and neutralizes attacks in mid-air."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(2.1),
        "🛡️ Moment 1: The Firewall Shield in Action",
        [
            "What if malicious code inside the sandbox tries to hack the host server?",
            "Our firewall rules instantly detect and drop any attempt to talk to the server gateway, internal company subnets, or Vultr cloud metadata.",
            "The threat is locked inside the room with nowhere to escape."
        ],
        accent_color=COLOR_BLUE,
        body_size=Pt(11.5)
    )

    add_terminal(
        slide,
        Inches(0.8), Inches(4.3), Inches(5.7), Inches(2.4),
        "What the Server Sees: verify_containment.sh",
        [
            "Checking Internet access (Cloudflare 1.1.1.1) .... [PASS] Reachable",
            "Checking Host Server Gateway (172.30.0.1) ........ [PASS] BLOCKED",
            "Checking Host Public IP Address ................. [PASS] BLOCKED",
            "Checking Vultr Cloud Metadata (169.254.169.254) .. [PASS] BLOCKED",
            "Checking Private Corporate Subnets .............. [PASS] BLOCKED",
            "🎉 RESULT: All unauthorized exits are 100% BLOCKED."
        ]
    )

    add_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(2.1),
        "☣️ Moment 2: Catching a Virus in Mid-Air",
        [
            "When testing fake banking websites, the page secretly triggers an automated download of a fake security tool ('SBI_Security_Patch.exe').",
            "Our browser catches the download stream in mid-air and stops it.",
            "Zero bytes ever execute on the machine. It is quarantined and analyzed safely."
        ],
        accent_color=COLOR_RED,
        body_size=Pt(11.5)
    )

    add_terminal(
        slide,
        Inches(6.8), Inches(4.3), Inches(5.7), Inches(2.4),
        "What the Interceptor Catches: Malware Intercept Log",
        [
            "[ALERT] Hostile page attempted drive-by download!",
            "File: SBI_Mandatory_Security_Patch.exe (84.2 KB)",
            "Interception: Download stopped and quenched instantly.",
            "Entropy Analysis: 7.82 / 8.0 (Packed / Obfuscated virus)",
            "Execution State: 0 lines of code executed on host.",
            "Status: QUARANTINED into isolated storage for inspection."
        ]
    )

    add_footer(slide, 5)
    set_speaker_notes(slide, """
For Challenge 1, we demonstrate our dual Containment Moments.
In Moment 1: our firewall tests prove that the sandbox cannot reach our server gateway, internal subnets, or cloud account keys. Any attempt to reach the host is blocked at the kernel level.
In Moment 2: when a scam banking site tries to secretly download a fake security update, our browser catches the file in mid-air. It cancels the download before it touches the operating system, hashes it, and inspects its code without ever running a single instruction. That is real containment.
""")


def build_slide_6(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Smart Autonomous Agent Features",
        "Smart Features: The 'Decoy Pass' & The Code X-Ray",
        "How the AI tricks scammers and inspects their hidden code without risking your data."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(4.7),
        "🎭 Pattern B: The 'Fake Decoy' Trick (Human Gate)",
        [
            "Phase 1: Finding the Trap (Passive Look)",
            "• The browser loads the page and spots username & password boxes.",
            "• Instead of typing blindly, the agent immediately pauses.",
            "The Human Safety Gate",
            "• A pop-up asks you: 'I detected a password harvester. May I feed it fake decoy credentials to see where they send the data?'",
            "• You remain in full control of whether the agent interacts.",
            "Phase 2: Feeding the Decoy",
            "• If you approve, the browser types fake dummy data ('test_canary_user') and clicks Submit.",
            "• It tracks where the scammer exfiltrates the password, exposing their hidden server address without risking any real user's data!"
        ],
        accent_color=COLOR_AMBER,
        body_size=Pt(11.5)
    )

    add_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(4.7),
        "🔬 REA Engine: The Code X-Ray",
        [
            "Static Analysis by Default",
            "• Every single scan automatically x-rays the website's background code (JavaScript, WebAssembly, and dropped files).",
            "Measuring Code Randomness (Entropy)",
            "• Normal code looks readable. Malware code is often heavily scrambled or encrypted to hide from antivirus.",
            "• Our engine calculates an 'entropy' score: high entropy means hidden danger.",
            "Mapping Scammer Tricks (MITRE ATT&CK)",
            "• Translates technical tricks into clear threat categories: 'Input Capture' (keystroke stealing), 'Exfiltration' (sending data to hacker servers), or 'Malicious File'."
        ],
        accent_color=COLOR_BLUE,
        body_size=Pt(11.5)
    )

    add_footer(slide, 6)
    set_speaker_notes(slide, """
Phish&Chips implements the hackathon's required Pattern B workflow.
In plain terms: when the AI sees a login box, it stops and asks the user for permission.
If approved, it executes the 'Fake Decoy' trick: feeding fake dummy credentials into the scam form to see where the data gets sent. This exposes the scammer's backend server while keeping real user information 100% safe.
At the same time, our REA engine acts like an X-ray machine: analyzing the hidden code on the page, checking if it's scrambled to evade antivirus, and translating the findings into clear categories.
""")


def build_slide_7(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Real-World Help for Everyday People",
        "From Threat Detection to Immediate Action",
        "Giving victims, everyday citizens, and security teams the exact tools to fight back."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(3.7), Inches(3.2),
        "📦 1-Click Takedown Pack",
        [
            "Don't just detect scams—shut them down.",
            "With one click, download a signed evidence pack (.tar.gz) with screenshots and logs ready to send to web hosts to get the fake site taken offline."
        ],
        accent_color=COLOR_BLUE,
        body_size=Pt(12)
    )

    add_card(
        slide,
        Inches(4.8), Inches(2.0), Inches(3.7), Inches(3.2),
        "🇮🇳 In Your Native Language",
        [
            "Scammers specifically target elderly or non-technical people in regional languages.",
            "Phish&Chips supports English, हिन्दी (Hindi), and ಕನ್ನಡ (Kannada) so anyone can use it with confidence."
        ],
        accent_color=COLOR_AMBER,
        body_size=Pt(12)
    )

    add_card(
        slide,
        Inches(8.8), Inches(2.0), Inches(3.7), Inches(3.2),
        "🚨 1-Tap 1930 Helpline",
        [
            "If a scam is confirmed, the app gives Indian users an instant 1-tap dialer for the National Cybercrime Helpline (1930).",
            "Direct link to cybercrime.gov.in and emergency bank freeze checklists."
        ],
        accent_color=COLOR_RED,
        body_size=Pt(12)
    )

    add_card(
        slide,
        Inches(0.8), Inches(5.4), Inches(11.7), Inches(1.3),
        "⚡ Zero False Alarms: Trusted Sites Pass in 3 Seconds",
        [
            "Nobody likes an overzealous security tool that cries wolf.",
            "Phish&Chips checks the Tranco Top-10K reputable domains (like Wikipedia, Google, or government portals). If you scan Wikipedia, it confirms it as SAFE in under 3 seconds with zero false alarms."
        ],
        accent_color=COLOR_GREEN,
        body_size=Pt(12)
    )

    add_footer(slide, 7)
    set_speaker_notes(slide, """
Finding a scam is only half the battle. What do you do once you find one?
Phish&Chips gives users immediate, practical remediation.
First: a 1-click takedown pack that you can email to the hosting provider to get the fake website shut down.
Second: full multilingual support in English, Hindi, and Kannada, because frontline victims in India are heavily targeted in their local languages.
Third: an emergency helpline drawer with a 1-tap dialer for India's 1930 Cybercrime helpline.
And finally, trusted websites like Wikipedia are verified in 3 seconds with zero false alarms.
""")


def build_slide_8(prs):
    slide = add_base_slide(prs)
    add_header(
        slide,
        "Hackathon Summary · Team alphax",
        "Why Phish&Chips Stands Out",
        "How our project addresses every single judging criterion with excellence."
    )

    add_card(
        slide,
        Inches(0.8), Inches(2.0), Inches(5.7), Inches(2.2),
        "⚙️ Application of Technology",
        [
            "Real production deployment on Vultr Cloud Compute (Bangalore).",
            "Vultr Serverless Inference powering deep AI reasoning via GLM-5.3.",
            "Hardened Docker cgroups v2, Caddy automated TLS, and Prometheus metrics."
        ],
        accent_color=COLOR_BLUE,
        body_size=Pt(11.5)
    )

    add_card(
        slide,
        Inches(6.8), Inches(2.0), Inches(5.7), Inches(2.2),
        "🎨 Presentation & Clarity",
        [
            "Live interactive dashboard at https://139.84.159.12.sslip.io.",
            "Real-time streaming terminal and animated 4-stage pipeline graph.",
            "Everything explained in plain, intuitive English with clear visual proof."
        ],
        accent_color=COLOR_AMBER,
        body_size=Pt(11.5)
    )

    add_card(
        slide,
        Inches(0.8), Inches(4.4), Inches(5.7), Inches(2.3),
        "💼 Real Business & Human Value",
        [
            "Protects everyday citizens and enterprise SOC teams from multi-billion dollar scams.",
            "Completely eliminates analyst infection risk: Blast Radius Zero.",
            "Provides instant evidence lockers and emergency reporting hotlines."
        ],
        accent_color=COLOR_GREEN,
        body_size=Pt(11.5)
    )

    add_card(
        slide,
        Inches(6.8), Inches(4.4), Inches(5.7), Inches(2.3),
        "✨ Originality & Novelty",
        [
            "True containment-first design: the sandbox is vaporized after each scan.",
            "Pattern B Human Approval Decoy Pass outsmarts scammers with fake data.",
            "Built-in code x-ray (REA Engine) for WebAssembly and binary drops."
        ],
        accent_color=COLOR_RED,
        body_size=Pt(11.5)
    )

    add_footer(slide, 8)
    set_speaker_notes(slide, """
To summarize: Phish&Chips proves that autonomous AI agents can handle dangerous cybersecurity tasks safely when built on Vultr's world-class cloud infrastructure.
It excels on technology by combining Vultr Cloud Compute and Vultr Serverless Inference with hardened containers. It excels on presentation with real-time streaming and plain-English clarity. It delivers massive real-world business and human value. And its Blast Radius Zero architecture is truly original.
Thank you to Vultr and LabLab. Remember: fresh phish, fried in a sandbox. Thank you!
""")


def main():
    print("==> Generating Plain English Phish&Chips PowerPoint Presentation (.pptx)...")
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
