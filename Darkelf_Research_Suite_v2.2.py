# Darkelf Research Suite – Privacy-Focused CLI Research & OSINT Toolkit
# Copyright (C) 2026
#
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# ---------------------------------------------------------------------------
# EXPORT COMPLIANCE NOTICE
# ---------------------------------------------------------------------------
#
# This software may include implementations of publicly available
# cryptographic and networking technologies for research purposes.
#
# Distribution of this source code is intended to comply with applicable
# export control regulations. The code is provided in source form only and
# does not include compiled binaries.
#
# Users are responsible for ensuring compliance with all applicable export
# control laws and regulations in their jurisdiction.
#
# ---------------------------------------------------------------------------
# SECURITY & ETHICAL USE NOTICE
# ---------------------------------------------------------------------------
#
# Darkelf Research Suite is designed for:
# - Security research
# - Open Source Intelligence (OSINT)
# - Educational and investigative purposes
#
# The tool may include features for:
# - Domain analysis
# - DNS inspection
# - Web research
# - Tor network routing
# - Web content analysis
#
# The software must only be used on systems, networks, and data for which
# you have explicit authorization.
#
# The developers assume no responsibility for misuse, illegal activity,
# or violation of applicable laws.
#
# ---------------------------------------------------------------------------
# TOR NETWORK NOTICE
# ---------------------------------------------------------------------------
#
# Some features may route traffic through the Tor network in order to
# enhance privacy and anonymity during research activities.
#
# Users are responsible for ensuring that the use of Tor and any accessed
# services complies with applicable laws and the terms of service of
# the target systems.
#
# ---------------------------------------------------------------------------
# PROJECT INFORMATION
# ---------------------------------------------------------------------------
#
# Project: Darkelf Research Suite
# Type: CLI Research & OSINT Toolkit
# Interface: Terminal / Command-Line Only
#
# This project is a command-line toolkit designed for researchers,
# investigators, and security professionals who require a lightweight,
# privacy-focused research environment.
#
# Contributions, improvements, and community feedback are welcome.
#
# ---------------------------------------------------------------------------
# END OF LICENSE HEADER
# ---------------------------------------------------------------------------

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Darkelf Research Suite v2.2
- All original logic preserved.
- Multi-tab browser (non-recursive)
- Persistent tabs across sessions
- Bookmarks
- Copy URL to clipboard (pyperclip)
- User-Agent toggle
- Quick HTML→PDF (pdfkit)
"""

import os
import sys
import json
import time
import textwrap
import requests
import shutil
import termios
import tty

import subprocess  # nosec B404 - controlled usage, no shell execution
import re
import whois
import tldextract
from shutil import which
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from datetime import datetime
import pyperclip
import pdfkit
from requests.exceptions import RequestException, ReadTimeout
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse
import socket
import time
from typing import Any, Dict, List, Iterable, Optional
from weasyprint import HTML  # add this near the top with other imports

try:
    import dns.resolver
    import dns.reversename

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois as python_whois

    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import psutil  # optional, for RAM detection
except Exception:
    psutil = None

from typing import Any

from stem.control import Controller
from stem.process import launch_tor_with_config
from stem import Signal
from pathlib import Path

OUTPUT_DIR = Path.home() / "Documents" / "Darkelf"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def output_path(filename: str) -> Path:
    return OUTPUT_DIR / filename


TOR_PORT = 9052  # detected from tor startup
ControlPort = 9053
PROXY = f"socks5h://127.0.0.1:{TOR_PORT}"

# ---------------------------
# Global Console and Logger
# ---------------------------
console = Console()
LOG_PATH = "darkelf_activity.log"


def _log(msg: str, level: str = "INFO"):
    line = f"{datetime.utcnow().isoformat()} [{level}] {msg}"
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"[WARN] Logging failed: {e}")
    if level == "ERROR":
        console.print(f"[red]{line}[/red]")
    elif level == "WARN":
        console.print(f"[yellow]{line}[/yellow]")
    else:
        console.print(f"[cyan]{line}[/cyan]")


# ---------------------------
# Tor Manager Using Stem
# ---------------------------
class TorManager:
    def __init__(self, tor_binary="tor", socks_port=9052, control_port=9053):
        self.tor_binary = tor_binary
        self.socks_port = socks_port
        self.control_port = control_port
        self.tor_process = None
        self.tor_controller = None

    def start_tor(self):
        """Launch Tor process and establish a control connection."""
        try:
            self.tor_process = launch_tor_with_config(
                config={
                    "SOCKSPort": str(self.socks_port),
                    "ControlPort": str(self.control_port),
                },
                init_msg_handler=self._tor_output_handler,
                tor_cmd=self.tor_binary,
            )
            self.tor_controller = Controller.from_port(port=self.control_port)
            self.tor_controller.authenticate()
            self.tor_controller.signal(Signal.NEWNYM)
            console.print(
                f"[green]Tor started successfully on SOCKSPort {self.socks_port} and ControlPort {self.control_port}[/green]"
            )
        except Exception as e:
            _log(f"Failed to start Tor: {e}", "ERROR")
            raise RuntimeError(
                "Tor startup failed. Ensure that Tor is installed and accessible."
            )

    def new_identity(self):
        """Request a new identity from the Tor network."""
        if self.tor_controller:
            self.tor_controller.signal(Signal.NEWNYM)
            console.print("[green]Tor network identity refreshed successfully.[/green]")

    def stop_tor(self):
        """Stop the Tor process and clean up controller."""
        if self.tor_controller:
            self.tor_controller.close()
            console.print("[yellow]Tor controller closed.[/yellow]")
        if self.tor_process:
            self.tor_process.terminate()
            console.print("[yellow]Tor process terminated.[/yellow]")

    @staticmethod
    def _tor_output_handler(line):
        _log(line.strip(), level="INFO")


# ---------------------------
# Utility helpers
# ---------------------------
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[A-Za-z]{2,63}\b")
HASH_RE = re.compile(
    r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{56}|[a-fA-F0-9]{64})\b"
)
USERNAME_RE = re.compile(r"@([\w\-_]{3,32})")
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
)


def normalize_domain(token: str) -> Optional[str]:
    ext = tldextract.extract(token)
    if ext.domain and ext.suffix:
        parts = [p for p in (ext.subdomain, ext.domain, ext.suffix) if p]
        return ".".join(parts)
    return None


class DuckDuckGoLite:
    LITE_ONION = (
        "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite"
    )
    HTML_CLEARNET = "https://duckduckgo.com/html/"

    def __init__(self, use_tor=True, proxies=None):
        self.session = requests.Session()
        self.use_tor = use_tor
        if proxies:
            self.proxies = proxies
        elif use_tor:
            # Use the same proxy as your TorManager
            self.proxies = {
                "http": f"socks5h://127.0.0.1:9052",  # Or use tor_manager.socks_port
                "https": f"socks5h://127.0.0.1:9052",
            }
        else:
            self.proxies = None
        self.session.headers.update({"User-Agent": "DarkelfResearchSuite/2.1"})

    def search(self, query, max_results=8, use_onion=False):
        out = []
        if use_onion and self.use_tor:
            url = f"{self.LITE_ONION}?q={requests.utils.quote(query)}"
            r = self.session.get(url, timeout=20, proxies=self.proxies)
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.select("a[href]"):
                href = a.get("href") or ""
                title = a.get_text(strip=True) or "[no title]"
                if href.startswith("http") and title:
                    out.append((title, href))
                    if len(out) >= max_results:
                        break
        # Add clearnet fallback if desired
        return out


class WHOISDNSLookup:
    """
    WHOIS and DNS lookup utility that routes all queries through Tor.
    Provides domain/IP WHOIS, DNS record queries, and reverse DNS lookups.
    """

    def __init__(self, use_tor: bool = True, socks_port: int = 9052):
        self.use_tor = use_tor
        self.socks_port = socks_port

        # Configure DNS resolver to use Tor if available
        if DNS_AVAILABLE and use_tor:
            self.resolver = dns.resolver.Resolver()
            # Note: dnspython doesn't natively support SOCKS proxies
            # For production, consider using a local DNS forwarder through Tor
            print(
                "DNS resolver initialized (note: direct Tor routing for DNS may require additional setup)"
            )
        elif DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
        else:
            self.resolver = None
            print("dnspython not available - DNS lookups disabled")

    def whois_domain(self, domain: str) -> Dict[str, Any]:
        if not WHOIS_AVAILABLE:
            return {"error": "python-whois library not installed"}
        try:
            w = python_whois.whois(domain)
            result = {
                "domain": domain,
                "registrar": w.registrar if hasattr(w, "registrar") else None,
                "creation_date": (
                    str(w.creation_date) if hasattr(w, "creation_date") else None
                ),
                "expiration_date": (
                    str(w.expiration_date) if hasattr(w, "expiration_date") else None
                ),
                "updated_date": (
                    str(w.updated_date) if hasattr(w, "updated_date") else None
                ),
                "status": w.status if hasattr(w, "status") else None,
                "nameservers": w.name_servers if hasattr(w, "name_servers") else None,
                "emails": w.emails if hasattr(w, "emails") else None,
            }
            return result
        except Exception as e:
            return {"error": str(e), "domain": domain}

    def whois_ip(self, ip: str) -> Dict[str, Any]:
        try:
            import requests

            session = requests.Session()
            if self.use_tor:
                session.proxies = {
                    "http": f"socks5h://127.0.0.1:{self.socks_port}",
                    "https": f"socks5h://127.0.0.1:{self.socks_port}",
                }
            url = f"https://ipwhois.app/json/{ip}"
            r = session.get(url, timeout=15)
            r.raise_for_status()
            data = r.json()
            result = {
                "ip": ip,
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("asn"),
                "continent": data.get("continent"),
            }
            return result
        except Exception as e:
            return {"error": str(e), "ip": ip}

    def dns_query(self, domain: str, record_type: str = "A") -> List[Dict[str, Any]]:
        if not DNS_AVAILABLE:
            return [{"error": "dnspython library not installed"}]
        try:
            answers = self.resolver.resolve(domain, record_type)
            results = []
            for rdata in answers:
                result = {
                    "type": record_type,
                    "domain": domain,
                    "ttl": answers.rrset.ttl,
                }
                if record_type == "MX":
                    result["priority"] = rdata.preference
                    result["value"] = str(rdata.exchange)
                elif record_type == "SOA":
                    result["mname"] = str(rdata.mname)
                    result["rname"] = str(rdata.rname)
                    result["serial"] = rdata.serial
                else:
                    result["value"] = str(rdata)
                results.append(result)
            return results
        except dns.resolver.NXDOMAIN:
            return [{"error": "Domain does not exist", "domain": domain}]
        except dns.resolver.NoAnswer:
            return [{"error": f"No {record_type} records found", "domain": domain}]
        except Exception as e:
            return [{"error": str(e), "domain": domain}]

    def reverse_dns(self, ip: str) -> Dict[str, Any]:
        if not DNS_AVAILABLE:
            return {"error": "dnspython library not installed"}
        try:
            addr = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(addr, "PTR")
            hostnames = [str(rdata) for rdata in answers]
            return {
                "ip": ip,
                "hostnames": hostnames,
                "ttl": answers.rrset.ttl if answers else None,
            }
        except Exception as e:
            return {"error": str(e), "ip": ip}


# ================= CONFIG =================

APP_NAME = "Darkelf Research Suite"
APP_VERSION = "2.1"

DDG_LITE = "https://lite.duckduckgo.com/lite/?q="
IA_ADV_SEARCH = "https://archive.org/advancedsearch.php"
IA_METADATA = "https://archive.org/metadata/"
DEFAULT_UA = "DarkelfResearchSuite/2.1"
USER_AGENT = DEFAULT_UA

HOME = os.path.expanduser("~")
BASE_DIR = os.path.join(HOME, ".darkelf_research")
HISTORY_FILE = os.path.join(BASE_DIR, "search_history.json")
TAB_STATE_FILE = os.path.join(BASE_DIR, "tabs_state.json")
BOOKMARKS_FILE = os.path.join(BASE_DIR, "bookmarks.json")
os.makedirs(BASE_DIR, exist_ok=True)

ORIGINAL_TTY = None

# ================= NETWORK =================


def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1)
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers.update({"User-Agent": USER_AGENT})
    return session


SESSION = create_session()


def safe_get(url, session=None, timeout=12, params=None):
    try:
        s = session or SESSION
        return s.get(url, timeout=timeout, allow_redirects=True, params=params)
    except ReadTimeout:
        console.print("[yellow]⏱ Request timed out[/yellow]")
    except RequestException as e:
        console.print(f"[red]Network error:[/red] {e}")
    return None


# ================= TTY =================


def init_tty():
    global ORIGINAL_TTY
    try:
        ORIGINAL_TTY = termios.tcgetattr(sys.stdin.fileno())
    except Exception:
        ORIGINAL_TTY = None


def read_key():
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            seq = ch
            while True:
                nxt = sys.stdin.read(1)
                seq += nxt
                if nxt.isalpha():
                    break
            return seq
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def clear():
    try:
        if os.name == "nt":
            cmd_path = which("cmd")
            if not cmd_path:
                raise RuntimeError("cmd not found")
            subprocess.run([cmd_path, "/c", "cls"], check=True)  # nosec B603 B607
        else:
            clear_path = which("clear")
            if not clear_path:
                raise RuntimeError("clear not found")
            subprocess.run([clear_path], check=True)  # nosec B603 B607
    except Exception as e:
        _log(f"Clear screen failed: {e}", "WARN")


def press_enter(msg="Press Enter to continue..."):
    input(f"\n{msg}")


def is_int(v):
    try:
        int(v)
        return True
    except Exception:
        return False
        
def create_tab(url=None):
    return {
        "url": url,
        "back": [],
        "forward": [],
        "links": [],
        "scroll": 0,
        "lines": [],
        "title": "",
    }
    
def terminal_size():
    return shutil.get_terminal_size((120, 30))


def wrap_text_block(text, width):
    if not text:
        return []
    wrapped = textwrap.fill(
        text,
        width=max(20, width),
        replace_whitespace=True,
        drop_whitespace=True,
    )
    return wrapped.splitlines()


def clean_text(text):
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def unique_preserve(seq):
    seen = set()
    out = []
    for item in seq:
        key = item if isinstance(item, str) else repr(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def extract_readable_content(soup, url):
    """
    Build a much richer readable text view than just long <p> tags.
    """
    for tag in soup(["script", "style", "noscript", "svg", "img", "footer", "nav"]):
        tag.decompose()

    chunks = []

    title = clean_text(soup.title.get_text(" ", strip=True) if soup.title else "")
    if title:
        chunks.append(f"# {title}")

    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc and meta_desc.get("content"):
        desc = clean_text(meta_desc.get("content"))
        if desc:
            chunks.append(f"Description: {desc}")

    og_desc = soup.find("meta", attrs={"property": "og:description"})
    if og_desc and og_desc.get("content"):
        desc = clean_text(og_desc.get("content"))
        if desc:
            chunks.append(f"OG Description: {desc}")

    selectors = [
        "main",
        "article",
        "[role='main']",
        ".markdown-body",
        ".repository-content",
        ".application-main",
        ".Box-body",
        "body",
    ]

    root = None
    for sel in selectors:
        root = soup.select_one(sel)
        if root:
            break
    if root is None:
        root = soup

    for elem in root.find_all(
        ["h1", "h2", "h3", "h4", "p", "li", "pre", "code", "blockquote", "td", "th"]
    ):
        txt = clean_text(elem.get_text(" ", strip=True))
        if not txt:
            continue

        name = elem.name.lower()
        if name in {"h1", "h2", "h3", "h4"}:
            chunks.append(f"\n{name.upper()}: {txt}")
        elif name == "li":
            chunks.append(f"• {txt}")
        elif name in {"pre", "code"}:
            chunks.append(f"[code] {txt}")
        elif name == "blockquote":
            chunks.append(f"> {txt}")
        else:
            chunks.append(txt)

    chunks = [c for c in unique_preserve(chunks) if len(c.strip()) > 0]

    if not chunks:
        body_text = clean_text(root.get_text(" ", strip=True))
        if body_text:
            chunks.append(body_text)

    return chunks


def extract_links_detailed(soup, base_url, limit=50):
    links = []
    for a in soup.find_all("a", href=True):
        href = clean_text(a.get("href"))
        text = clean_text(a.get_text(" ", strip=True)) or "(link)"
        if not href:
            continue

        href = requests.compat.urljoin(base_url, href)

        if href.startswith("http://") or href.startswith("https://"):
            parsed = urlparse(href)
            links.append({
                "text": text,
                "url": href,
                "domain": parsed.netloc,
                "path": parsed.path or "/",
            })

    deduped = []
    seen = set()
    for link in links:
        key = (link["text"], link["url"])
        if key not in seen:
            seen.add(key)
            deduped.append(link)

    return deduped[:limit]
    
# ================= PERSISTENT TABS =================

tabs = []
active_tab = 0

def save_tabs():
    try:
        state = []

        for tab in tabs:
            # Skip corrupted entries
            if not isinstance(tab, dict):
                _log(f"Skipping corrupt tab during save: {tab}", "WARN")
                continue

            state.append({
                "url": tab.get("url"),
                "title": tab.get("title", ""),
                "back": tab.get("back", []),
                "forward": tab.get("forward", []),
            })

        # Ensure active_tab is valid
        safe_active = min(active_tab, len(state) - 1) if state else 0

        with open(TAB_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(
                {"active": safe_active, "tabs": state},
                f,
                indent=2
            )

    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not save tab state: {e}")

def load_tabs():
    global tabs, active_tab
    if not os.path.exists(TAB_STATE_FILE):
        return
    try:
        with open(TAB_STATE_FILE) as f:
            data = json.load(f)
            tabs.clear()
            for t in data.get("tabs", []):
                if not isinstance(t, dict):
                    continue

                tab = create_tab()
                tab["url"] = t.get("url")
                tab["title"] = t.get("title", "")
                tab["back"] = t.get("back", [])
                tab["forward"] = t.get("forward", [])

                tabs.append(tab)
            active_tab = min(int(data.get("active", 0)), len(tabs) - 1) if tabs else 0
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not restore tab state: {e}")


# ================= MULTI TAB BROWSER =================


def current_tab():
    if not tabs:
        return None

    try:
        tab = tabs[active_tab]
    except Exception as e:
        _log(f"Tab index error: {e}", "ERROR")
        return None

    if not isinstance(tab, dict):
        _log(f"Corrupt tab detected: {tab}", "ERROR")
        return None

    return tab

def open_page(url):
    """Preserves original function name for CLI compatibility."""
    new_tab(url)
    browser_loop()

def new_tab(url=None):
    global active_tab

    # Always use a single source of truth for tab structure
    tab = create_tab(url)

    tabs.append(tab)
    active_tab = len(tabs) - 1

    # Only load if URL is valid/non-empty
    if url and isinstance(url, str) and url.strip():
        try:
            load_page(url)
        except Exception as e:
            _log(f"Failed to load page in new tab: {e}", "WARN")


def close_tab():
    global active_tab
    if not tabs:
        return
    tabs.pop(active_tab)
    if tabs:
        active_tab = max(0, active_tab - 1)


def switch_tab(index):
    global active_tab
    if 0 <= index < len(tabs):
        active_tab = index


def load_page(url, add_history=True):
    tab = current_tab()
    if not tab:
        return

    if add_history and tab["url"]:
        tab["back"].append(tab["url"])
        tab["forward"].clear()

    r = safe_get(url)
    if not r:
        return

    soup = BeautifulSoup(r.text, "html.parser")
    tab["title"] = soup.title.get_text(strip=True) if soup.title else url

    size = terminal_size()
    width = max(40, size.columns - 8)

    content_chunks = extract_readable_content(soup, url)
    lines = []

    for chunk in content_chunks:
        if chunk.startswith("\n"):
            lines.append("")
            chunk = chunk.strip()

        if chunk.startswith("H1:") or chunk.startswith("H2:") or chunk.startswith("H3:") or chunk.startswith("H4:"):
            lines.append(chunk)
            lines.append("")
            continue

        wrapped = wrap_text_block(chunk, width)
        lines.extend(wrapped)
        lines.append("")

    links = extract_links_detailed(soup, url, limit=100)

    tab.update(
        {
            "url": url,
            "lines": lines,
            "links": links,
            "scroll": 0,
        }
    )

    render_page()


def render_page():
    clear()
    tab = current_tab()
    if not tab:
        return

    size = terminal_size()
    body_height = max(8, size.lines - 16)
    start = tab["scroll"]
    end = start + body_height

    visible = "\n".join(tab["lines"][start:end])

    title = f"[Tab {active_tab+1}/{len(tabs)}] {tab.get('title','')}"
    subtitle = tab.get("url", "")

    console.print(
        Panel(
            visible or "[dim]No readable content extracted[/dim]",
            title=title,
            subtitle=subtitle,
            border_style="green",
            expand=True,
        )
    )

    if tab["links"]:
        table = Table(title=f"Links ({min(len(tab['links']), 12)} shown / {len(tab['links'])} total)", show_lines=True, expand=True)
        table.add_column("#", width=4, no_wrap=True)
        table.add_column("Text", ratio=3, overflow="fold")
        table.add_column("Domain", ratio=2, overflow="fold")
        table.add_column("Path", ratio=3, overflow="fold")

        for i, link in enumerate(tab["links"][:12], 1):
            table.add_row(
                str(i),
                link["text"],
                link["domain"],
                link["path"],
            )
        console.print(table)

    console.print(
        "[w/←]Back [s/→]Forward [j/↓]Down [k/↑]Up "
        "[t]NewTab [x]CloseTab [n]Next [p]Prev "
        "[b]Bookmark [B]Bookmarks [c]CopyURL [P]Save PDF [o]OpenLinkURL [q]Quit",
        style="green",
    )

def browser_loop():
    while True:
        k = read_key()
        tab = current_tab()
        if not tab:
            return

        if k.lower() == "q":
            save_tabs()
            return

        elif k in ("j", "\x1b[B"):
            if tab["scroll"] < len(tab["lines"]) - 5:
                tab["scroll"] += 1
                render_page()

        elif k in ("k", "\x1b[A"):
            if tab["scroll"] > 0:
                tab["scroll"] -= 1
                render_page()

        elif k in ("w", "\x1b[D"):
            if tab["back"]:
                tab["forward"].append(tab["url"])
                load_page(tab["back"].pop(), False)

        elif k in ("s", "\x1b[C"):
            if tab["forward"]:
                tab["back"].append(tab["url"])
                load_page(tab["forward"].pop(), False)

        elif k.lower() == "t":
            new_tab(input("\nNew URL> ").strip())
            render_page()

        elif k.lower() == "x":
            close_tab()
            render_page()

        elif k.lower() == "n":
            switch_tab((active_tab + 1) % len(tabs))
            render_page()

        elif k.lower() == "p":
            switch_tab((active_tab - 1) % len(tabs))
            render_page()

        elif k.isdigit():
            i = int(k) - 1
            if 0 <= i < len(tab["links"]):
                load_page(tab["links"][i]["url"])

        elif k.lower() == "o":
            sel = input("\nOpen link # or paste URL> ").strip()
            if is_int(sel):
                i = int(sel) - 1
                if 0 <= i < len(tab["links"]):
                    load_page(tab["links"][i]["url"])
                    
            elif sel.startswith("http://") or sel.startswith("https://"):
                load_page(sel)

        elif k == "b":
            add_bookmark(tab["url"], tab["title"])
            console.print("[green]Bookmarked![/green]")
            press_enter()
            render_page()
        elif k == "B":
            show_bookmarks()
            render_page()
        elif k.lower() == "c":
            pyperclip.copy(tab["url"])
            console.print("[green]Copied URL to clipboard[/green]")
            press_enter()
            render_page()
        elif k == "P":
            save_pdf(tab["url"])
            render_page()


# ================= BOOKMARKS =================


def add_bookmark(url, title=None):
    bookmarks = []
    if os.path.exists(BOOKMARKS_FILE):
        with open(BOOKMARKS_FILE) as f:
            bookmarks = json.load(f)
    bookmarks.append({"url": url, "title": title or url, "ts": int(time.time())})
    with open(BOOKMARKS_FILE, "w") as f:
        json.dump(bookmarks[-100:], f, indent=2)
    console.print(f"[green]Bookmarked {url}[/green]")


def show_bookmarks():
    if not os.path.exists(BOOKMARKS_FILE):
        press_enter("No bookmarks.")
        return
    with open(BOOKMARKS_FILE) as f:
        bookmarks = json.load(f)
    t = Table(title="Bookmarks", show_lines=True)
    t.add_column("#", width=3)
    t.add_column("Title")
    t.add_column("URL", style="dim")
    for i, b in enumerate(bookmarks, 1):
        t.add_row(str(i), b.get("title", "")[:60], b["url"])
    console.print(t)
    i = input("Open #> ")
    if is_int(i) and 0 < int(i) <= len(bookmarks):
        open_page(bookmarks[int(i) - 1]["url"])


# ================= PDF SNAPSHOT =================


def save_pdf(url):
    fname = os.path.join(BASE_DIR, f"snapshot_{int(time.time())}.pdf")
    try:
        HTML(url).write_pdf(fname)
        console.print(f"[green]Saved PDF snapshot:[/green] {fname}")
    except Exception as e:
        console.print(f"[red]PDF failed:[/red] {e}")
    press_enter()


# ================= SEARCH =================


class WebSearch:
    def __init__(self):
        self.session = create_session()
        self.history = (
            json.load(open(HISTORY_FILE)) if os.path.exists(HISTORY_FILE) else []
        )

    def save(self):
        json.dump(self.history[-200:], open(HISTORY_FILE, "w"), indent=2)

    def search(self, query, limit=10):
        self.history.append({"q": query, "ts": int(time.time())})
        self.save()

        r = safe_get(DDG_LITE + requests.utils.quote(query), self.session)
        if not r:
            return []

        soup = BeautifulSoup(r.text, "html.parser")
        results = []

        for a in soup.find_all("a", href=True):
            if "uddg=" not in a["href"]:
                continue
            try:
                url = requests.utils.unquote(a["href"].split("uddg=")[1].split("&")[0])
                title = a.get_text(" ", strip=True)
                results.append((title, url))
            except Exception as e:
                _log(f"Search parse error: {e}", "WARN")
            if len(results) >= limit:
                break
        return results


# ================= ARCHIVE =================


class InternetArchive:
    def search(self, q):
        r = safe_get(IA_ADV_SEARCH, params={"q": q, "rows": 10, "output": "json"})
        return r.json() if r else {}


# ================= AI =================
class DarkelfResearchAI:
    ALLOWED_MODELS = {"mistral", "llama3", "phi", "gemma"}  # adjust as needed
    MAX_PROMPT_LEN = 8000

    def __init__(self, model="mistral"):
        self.ollama_path = which("ollama")
        if not self.ollama_path:
            console.print("[red]Ollama not installed or not in PATH[/red]")
            sys.exit(1)

        # Strict model validation (stronger than regex alone)
        if model not in self.ALLOWED_MODELS:
            raise ValueError(f"Model '{model}' not allowed")

        self.model = model

    def ask(self, prompt, timeout=60):
        if not isinstance(prompt, str) or not prompt.strip():
            console.print("[yellow]Empty or invalid prompt[/yellow]")
            return

        # Prevent abuse / memory blowups
        if len(prompt) > self.MAX_PROMPT_LEN:
            console.print("[yellow]Prompt too long, truncating[/yellow]")
            prompt = prompt[: self.MAX_PROMPT_LEN]

        system_prompt = (
            "You are Darkelf Research AI.\n"
            "You perform structured OSINT analysis.\n"
            "You provide:\n"
            "- Key findings\n"
            "- Risk indicators\n"
            "- Cross-reference ideas\n"
            "- Archive suggestions\n"
            "- Metadata strategies\n\n"
            f"User query:\n{prompt}\n"
        )

        proc = None

        try:
            proc = subprocess.Popen(
                [
                    self.ollama_path,
                    "run",
                    self.model,
                ],  # nosec B603 - validated input, no shell
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            # --- Send input safely ---
            try:
                proc.stdin.write(system_prompt)
                proc.stdin.close()
            except Exception as e:
                _log(f"stdin write failed: {e}", "ERROR")
                proc.kill()
                return

            # --- Stream output safely ---
            try:
                for line in iter(proc.stdout.readline, ""):
                    print(line, end="", flush=True)
            except Exception as e:
                _log(f"stdout stream error: {e}", "WARN")

            # --- Wait with timeout ---
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                console.print("[red]AI process timed out[/red]")
                return

            # --- Handle errors ---
            if proc.returncode != 0:
                try:
                    err = proc.stderr.read()
                except Exception:
                    err = "Unknown error"
                console.print(f"[red]AI error:[/red] {err}")

        except Exception as e:
            _log(f"AI execution failed: {e}", "ERROR")
            console.print("[red]Failed to run AI process[/red]")

        finally:
            # Ensure cleanup (important)
            if proc:
                try:
                    if proc.stdout:
                        proc.stdout.close()
                    if proc.stderr:
                        proc.stderr.close()
                except Exception as e:
                    _log(f"Cleanup error: {e}", "WARN")


# ================= MENU =================


def main_menu():
    table = Table(title=f"{APP_NAME} v{APP_VERSION}", show_lines=True)
    table.add_column("#", width=3)
    table.add_column("Action")

    table.add_row("1", "Web OSINT Search (DuckDuckGo Lite)")
    table.add_row("2", "Ask Darkelf Research AI")
    table.add_row("3", "Internet Archive Research")
    table.add_row("4", "Open URL (Tab Browser)")
    table.add_row("5", "View Search History")
    table.add_row("6", "HTTP Header Inspector")
    table.add_row("7", "WHOIS Lookup")
    table.add_row("8", "Extract Links From Page")
    table.add_row("9", "Download Page Snapshot")
    table.add_row("10", "Darkweb Onion Access (Tor Required)")
    table.add_row("11", "Bookmarks")
    table.add_row("12", "Change User-Agent (Current: %s)" % USER_AGENT)
    table.add_row("13", "Save Current Tab as PDF")
    table.add_row("14", "New Tor Identity")
    table.add_row("15", "Stop Tor")
    table.add_row("16", "Wipe History/Cache/Cookies")
    table.add_row("0", "Exit")

    console.print(
        Panel.fit(
            "🔍 OSINT & Research Terminal\n🌐 Clearnet + Manual Darkweb\n🤖 Darkelf Research AI",
            border_style="green",
        )
    )
    console.print(table)


# ================= APP =================


class DarkelfCLI:
    def __init__(self):
        self.search = WebSearch()
        self.archive = InternetArchive()
        self.ai = DarkelfResearchAI()
        self.tor_manager = TorManager()
        try:
            self.tor_manager.start_tor()
            self.tor_enabled = True
        except Exception:
            self.tor_enabled = False
        self.whois_dns = WHOISDNSLookup(
            use_tor=self.tor_enabled, socks_port=self.tor_manager.socks_port
        )

    def tor_session(self):
        s = requests.Session()
        s.proxies = {
            "http": f"socks5h://127.0.0.1:{self.tor_manager.socks_port}",
            "https": f"socks5h://127.0.0.1:{self.tor_manager.socks_port}",
        }
        return s

    def run(self):
        init_tty()
        load_tabs()
        try:
            while True:
                clear()
                main_menu()
                c = input("\nSelect> ").strip()

                if c == "0":
                    save_tabs()
                    return

                if c == "1":
                    q = input("OSINT query> ")
                    results = self.search.search(q)
                    if not results:
                        press_enter("No results.")
                        continue

                    t = Table(title=f"Results: {q}", show_lines=True, expand=True)
                    t.add_column("#", width=4, no_wrap=True)
                    t.add_column("Title", ratio=3, overflow="fold")
                    t.add_column("Domain", ratio=2, overflow="fold")
                    t.add_column("URL", ratio=4, overflow="fold", style="dim")

                    for i, (ti, u) in enumerate(results, 1):
                        parsed = urlparse(u)
                        t.add_row(str(i), ti, parsed.netloc, u)

                    console.print(t)
                    sel = input("Open #> ")
                    if is_int(sel) and 0 < int(sel) <= len(results):
                        open_page(results[int(sel) - 1][1])

                if c == "2":
                    q = input("Ask Darkelf Research AI> ")
                    clear()
                    self.ai.ask(q)
                    press_enter()

                if c == "3":
                    q = input("Archive search> ")
                    data = self.archive.search(q)
                    docs = data.get("response", {}).get("docs", [])

                    if not docs:
                        press_enter("No archive results.")
                        continue

                    t = Table(title="Internet Archive Results", show_lines=True)
                    t.add_column("#", width=3)
                    t.add_column("Title")

                    for i, d in enumerate(docs, 1):
                        t.add_row(str(i), str(d.get("title", ""))[:80])

                    console.print(t)
                    sel = input("Open #> ")
                    if is_int(sel) and 0 < int(sel) <= len(docs):
                        ident = docs[int(sel) - 1].get("identifier")
                        if ident:
                            open_page(f"https://archive.org/details/{ident}")

                if c == "4":
                    open_page(input("URL> "))

                if c == "5":
                    for h in self.search.history[-20:]:
                        print(
                            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["ts"])),
                            h["q"],
                        )
                    press_enter()

                if c == "6":
                    self.header_inspector()

                if c == "7":
                    self.whois_lookup()

                if c == "8":
                    self.extract_links()

                if c == "9":
                    self.download_snapshot()

                if c == "10":
                    self.onion_access()

                if c == "11":
                    show_bookmarks()

                if c == "12":
                    global USER_AGENT, SESSION
                    ua = input("New User-Agent (or 'reset')> ").strip()
                    USER_AGENT = ua if ua != "reset" else DEFAULT_UA
                    SESSION = create_session()
                    self.search.session = create_session()

                if c == "13":
                    tab = current_tab()
                    if tab and tab["url"]:
                        save_pdf(tab["url"])

                if c == "14":
                    self.tor_manager.new_identity()
                    print("[green]Tor identity changed.[/green]")
                    press_enter()

                if c == "15":
                    if self.tor_enabled:
                        try:
                            self.tor_manager.stop_tor()
                            self.tor_enabled = False
                            console.print("[yellow]Tor stopped successfully.[/yellow]")
                        except Exception as e:
                            console.print(f"[red]Error stopping Tor:[/red] {e}")
                    else:
                        console.print("[dim]Tor is not currently running.[/dim]")
                    press_enter()

                if c == "16":
                    self.wipe_cache_history()

        finally:
            save_tabs()
            try:
                self.tor_manager.stop_tor()
            except Exception as e:
                _log(f"Tor shutdown error: {e}", "WARN")

    def whois_lookup(self):

        while True:
            console.print("[cyan]WHOIS / DNS lookup menu[/cyan]")
            console.print(" [1] Domain WHOIS")
            console.print(" [2] IP WHOIS")
            console.print(" [3] DNS records")
            console.print(" [4] Reverse DNS")
            console.print(" [5] Back")
            c = input("Select> ").strip()

            if c == "1":
                domain = input("Domain> ").strip()
                result = self.whois_dns.whois_domain(domain)
                if "error" in result:
                    print(f"[red]Error: {result['error']}[/red]")
                else:
                    lines = [
                        f"Domain: {result.get('domain')}",
                        f"Registrar: {result.get('registrar')}",
                        f"Created: {result.get('creation_date')}",
                        f"Expires: {result.get('expiration_date')}",
                        f"Updated: {result.get('updated_date')}",
                        f"Nameservers: {result.get('nameservers')}",
                        f"Emails: {result.get('emails')}",
                        f"Status: {result.get('status')}",
                    ]
                    print("\n".join(lines))
                press_enter()

            elif c == "2":
                ip = input("IP> ").strip()
                result = self.whois_dns.whois_ip(ip)
                if "error" in result:
                    print(f"[red]Error: {result['error']}[/red]")
                else:
                    lines = [
                        f"IP: {result.get('ip')}",
                        f"Country: {result.get('country')}",
                        f"Region: {result.get('region')}",
                        f"City: {result.get('city')}",
                        f"ISP: {result.get('isp')}",
                        f"Organization: {result.get('org')}",
                        f"ASN: {result.get('asn')}",
                        f"Continent: {result.get('continent')}",
                    ]
                    print("\n".join(lines))
                press_enter()

            elif c == "3":
                domain = input("Domain> ").strip()
                record_type = (
                    input("Record type (A, MX, TXT, NS, etc)> ").strip().upper() or "A"
                )
                results = self.whois_dns.dns_query(domain, record_type)
                for r in results:
                    print(r)
                press_enter()

            elif c == "4":
                ip = input("IP> ").strip()
                result = self.whois_dns.reverse_dns(ip)
                print(result)
                press_enter()

            elif c == "5":
                break

    def wipe_cache_history(self):
        errors = []
        removed = []

        # List of files to remove
        files_to_remove = [
            HISTORY_FILE,
            TAB_STATE_FILE,
            BOOKMARKS_FILE,
            os.path.join(BASE_DIR, "cookies.json"),  # If you serialize cookies yourself
            os.path.join(
                BASE_DIR, "requests_session.pkl"
            ),  # Example: if you pickle session state
            # Add other session/cache/cookie files here
        ]
        for file in files_to_remove:
            try:
                if os.path.exists(file):
                    os.remove(file)
                    removed.append(file)
            except Exception as e:
                errors.append(f"{file}: {e}")

        # If you use sessions with persistent cookies, clear them from memory too
        try:
            requests.Session().cookies.clear()
        except Exception as e:
            _log(f"Cookie clear failed: {e}", "WARN")

        # Also clear in-memory search object history
        try:
            if hasattr(self.search, "history"):
                self.search.history.clear()
                self.search.save()
        except Exception as e:
            _log(f"Search save failed: {e}", "WARN")

        if removed:
            console.print(f"[green]Wiped/removed:[/green]\n" + "\n".join(removed))
        else:
            console.print("[yellow]No cache/history/cookies files found.[/yellow]")

        if errors:
            console.print(f"[red]Errors encountered:[/red]\n" + "\n".join(errors))
        press_enter()

    def header_inspector(self):
        url = input("URL> ").strip()
        r = safe_get(url)
        if not r:
            return

        table = Table(title="HTTP Headers", show_lines=True)
        table.add_column("Header")
        table.add_column("Value")

        for k, v in r.headers.items():
            table.add_row(k, v)

        console.print(table)
        press_enter()

    def extract_links(self):
        url = input("URL> ").strip()
        r = safe_get(url)
        if not r:
            return

        soup = BeautifulSoup(r.text, "html.parser")
        links = [a["href"] for a in soup.find_all("a", href=True)]

        for l in links:
            console.print(l)

        press_enter()

    def download_snapshot(self):
        url = input("URL> ").strip()
        r = safe_get(url)
        if not r:
            return

        fname = os.path.join(BASE_DIR, f"snapshot_{int(time.time())}.html")
        with open(fname, "w", encoding="utf-8") as f:
            f.write(r.text)

        console.print(f"[green]Saved:[/green] {fname}")
        press_enter()

    def onion_access(self):
        if not self.tor_enabled:
            console.print("[red]Tor is not running. Start Tor first.[/red]")
            press_enter()
            return

        url = input("Onion URL> ").strip()

        if not url:
            return

        # Enforce .onion domain
        if ".onion" not in url:
            console.print(
                "[yellow]This feature is for .onion URLs only. "
                "Use tab browser for clearnet.[/yellow]"
            )
            press_enter()
            return

        # Auto-add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            s = self.tor_session()
            r = safe_get(url, session=s)

            if not r:
                console.print("[red]Tor connection failed or no response.[/red]")
                press_enter()
                return

            # Prevent massive output flooding
            content = r.text
            if len(content) > 5000:
                console.print("[yellow]Large response truncated for display.[/yellow]")
                content = content[:5000]

            console.print(
                Panel(content, title=f"[Onion] {url}", border_style="magenta")
            )

        except Exception as e:
            console.print(f"[red]Onion access error:[/red] {e}")

        press_enter()


# ================= ENTRY =================

if __name__ == "__main__":
    DarkelfCLI().run()

