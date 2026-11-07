"""
reputation.py - Apex-domain reputation gate (Tier 1 grounding).

Separates *reputation grounding* from *dynamic anomaly detection*:
  * A reputable apex (Tranco top-N) is never treated as a brand-impersonation target
    of itself, and never flagged on lexical signals alone.
  * User-content / multi-tenant platforms (github.io, blogspot.com, sites.google.com,
    object storage, ...) are NEVER fast-passed - they always get full inspection,
    because anyone can host a phishing page under a reputable apex.

The list is an exact in-memory frozenset: for 10K entries it is smaller than a Bloom
filter's sizing slack and, unlike a Bloom filter, cannot produce a false *whitelist* hit.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, Optional
from urllib.parse import urlparse

DATA_DIR = Path(__file__).resolve().parent / "data"
REPUTATION_LIST = Path(os.getenv("REPUTATION_LIST_PATH", str(DATA_DIR / "tranco_top10k.txt")))
REPUTATION_TOP_N = int(os.getenv("REPUTATION_TOP_N", "10000"))

# Public-suffix entries with more than one label (compact subset covering common ccSLDs).
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "sch.uk",
    "co.in", "gov.in", "nic.in", "ac.in", "edu.in", "org.in", "net.in", "res.in", "firm.in", "gen.in", "ind.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "govt.nz", "ac.nz", "org.nz",
    "co.jp", "ac.jp", "go.jp", "or.jp", "ne.jp", "com.br", "gov.br", "edu.br", "org.br", "net.br",
    "com.cn", "gov.cn", "edu.cn", "org.cn", "net.cn", "com.hk", "com.sg", "edu.sg", "gov.sg",
    "co.za", "gov.za", "ac.za", "org.za", "com.mx", "gob.mx", "edu.mx", "com.ar", "gob.ar", "com.tr", "gov.tr",
    "edu.tr", "co.kr", "go.kr", "ac.kr", "com.tw", "gov.tw", "edu.tw", "com.pk", "gov.pk", "edu.pk",
    "com.ng", "gov.ng", "edu.ng", "co.id", "go.id", "ac.id", "com.my", "gov.my", "edu.my", "co.il", "gov.il",
    "ac.il", "com.ua", "gov.ua", "com.pl", "gov.pl", "com.ru", "com.eg", "gov.eg", "com.sa", "gov.sa", "com.vn",
    "gov.vn", "co.th", "go.th", "ac.th", "com.ph", "gov.ph", "edu.ph", "com.co", "gov.co", "com.pe", "gob.pe",
    "com.es", "gob.es", "com.pt", "gov.pt", "com.gr", "gov.gr", "com.de", "co.de",
}

# Hosting/multi-tenant apexes where the *subdomain or path owner is not the apex owner*.
# Matching is on the registrable apex OR a suffix (e.g. "s3.amazonaws.com", "storage.googleapis.com").
USER_CONTENT_HOSTS: FrozenSet[str] = frozenset({
    "github.io", "githubusercontent.com", "gitlab.io", "bitbucket.io", "sourceforge.io",
    "blogspot.com", "blogger.com", "wordpress.com", "wixsite.com", "wix.com", "weebly.com", "squarespace.com",
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "forms.office.com",
    "googleusercontent.com", "storage.googleapis.com", "firebaseapp.com", "firebasestorage.googleapis.com",
    "web.app", "appspot.com", "cloudfunctions.net", "run.app", "pages.dev", "workers.dev", "r2.dev",
    "netlify.app", "vercel.app", "herokuapp.com", "onrender.com", "fly.dev", "glitch.me", "repl.co", "replit.app",
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "blob.core.windows.net", "azureedge.net",
    "windows.net", "sharepoint.com", "onedrive.live.com", "1drv.ms", "dropbox.com", "dropboxusercontent.com",
    "notion.site", "notion.so", "medium.com", "substack.com", "tumblr.com", "typedream.app", "carrd.co",
    "webflow.io", "framer.website", "framer.app", "bubbleapps.io", "godaddysites.com", "mystrikingly.com",
    "myshopify.com", "ipfs.io", "dweb.link", "trycloudflare.com", "ngrok.io", "ngrok-free.app", "000webhostapp.com",
    "infinityfreeapp.com", "rf.gd", "epizy.com", "bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly", "ow.ly",
    "linktr.ee", "lnk.to", "canva.site", "zoho.com", "typeform.com", "airtable.com", "wufoo.com", "jotform.com",
    "surge.sh", "now.sh", "onion.to", "mediafire.com", "wetransfer.com", "we.tl", "scribd.com", "pastebin.com",
})


def extract_host(url_or_host: str) -> str:
    s = (url_or_host or "").strip().lower()
    if "://" not in s:
        s = "//" + s
    try:
        host = urlparse(s).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".")


def apex_domain(url_or_host: str) -> str:
    """Registrable domain (eTLD+1) using a compact public-suffix subset."""
    host = extract_host(url_or_host)
    if not host or host.replace(".", "").isdigit() or ":" in host:
        return host  # IP literals have no apex
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_user_content_host(url_or_host: str) -> bool:
    host = extract_host(url_or_host)
    if not host:
        return False
    parts = host.split(".")
    return any(".".join(parts[i:]) in USER_CONTENT_HOSTS for i in range(len(parts) - 1))


@lru_cache(maxsize=1)
def _load_reputable() -> FrozenSet[str]:
    domains = set()
    try:
        with open(REPUTATION_LIST, "r", encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if i >= REPUTATION_TOP_N:
                    break
                d = line.strip().lower()
                if d:
                    domains.add(d)
    except OSError:
        pass
    # Public-sector / education TLDs are treated as reputable by structure, not by list rank.
    return frozenset(d for d in domains if d not in USER_CONTENT_HOSTS)


def reputation_list_size() -> int:
    return len(_load_reputable())


def is_government_or_edu(host: str) -> bool:
    h = extract_host(host)
    return bool(h) and (
        h.endswith((".gov", ".edu", ".mil"))
        or any(h.endswith(s) for s in (".gov.uk", ".gov.in", ".nic.in", ".ac.uk", ".edu.au", ".gov.au", ".ac.in", ".edu.in", ".gc.ca", ".gouv.fr", ".europa.eu"))
    )


def classify_reputation(url_or_host: str) -> Optional[str]:
    """Returns 'reputable' for verified non-user-content apexes, else None.

    Note: this is *grounding only*. It never produces a verdict by itself; the
    dynamic sandbox must still confirm no open redirect / credential exfiltration.
    """
    host = extract_host(url_or_host)
    if not host or is_user_content_host(host):
        return None
    if apex_domain(host) in _load_reputable() or is_government_or_edu(host):
        return "reputable"
    return None


def is_reputable(url_or_host: str) -> bool:
    return classify_reputation(url_or_host) == "reputable"


def same_site(a: str, b: str) -> bool:
    return bool(apex_domain(a)) and apex_domain(a) == apex_domain(b)

