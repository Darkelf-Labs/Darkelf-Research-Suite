# 🔍 Darkelf Research Suite

**Privacy-Focused CLI Research & OSINT Toolkit**

Darkelf Research Suite is a modern command-line research environment designed for investigators, security professionals, students, and OSINT practitioners. It combines web research, domain intelligence, Tor integration, Internet Archive access, AI-assisted analysis, and browser utilities into a single cross-platform terminal application.

---

## Features

- 🌐 DuckDuckGo Lite web search
- 🧅 Optional Tor network integration
- 🔒 Isolated Tor data directory
- 🤖 Optional Ollama AI research assistant
- 📚 Internet Archive search
- 🌍 WHOIS domain lookup
- 🌐 DNS record inspection
- 🔁 Reverse DNS lookup
- 📄 Save webpages as PDF
- 📑 HTML page snapshots
- 📂 Multi-tab terminal browser
- 🔖 Persistent bookmarks
- 📜 Search history
- 🛡️ HTTP header inspection
- 🧹 Cache, history, and session cleanup
- 🖥️ Cross-platform support (Windows, macOS, Linux)

---

## Installation

### Install from PyPI

```bash
pip install darkelf-research-suite
```

Launch:

```bash
darkelf-research
```

or

```bash
python -m darkelf_research_suite
```

---

## Optional Components

Certain features require optional software.

### Tor

Tor is only required for Onion browsing and anonymous routing.

Install Tor:

- macOS (Homebrew)

```bash
brew install tor
```

- Ubuntu

```bash
sudo apt install tor
```

- Windows

Install the official Tor Expert Bundle or Tor Browser.

If Tor is unavailable, Darkelf Research Suite continues operating normally with Onion features disabled.

---

### Ollama AI

AI-assisted research requires Ollama.

Install from:

https://ollama.com

Example:

```bash
ollama pull mistral
```

If Ollama is not installed, all other functionality remains available.

---

## Main Menu

Darkelf Research Suite includes:

- Web OSINT Search
- AI Research Assistant
- Internet Archive Research
- Multi-tab Browser
- Search History
- HTTP Header Inspector
- WHOIS Lookup
- DNS Lookup
- Reverse DNS
- Onion Browser
- Bookmarks
- User-Agent Switching
- PDF Export
- Tor Identity Rotation
- Tor Management
- Cache & History Wipe

---

## Privacy

Darkelf Research Suite is designed with privacy in mind.

- No telemetry
- No analytics
- No cloud account required
- Tor support is optional
- AI is optional
- Local bookmark storage
- Local search history
- User-controlled data

---

## Supported Platforms

- macOS
- Linux
- Windows

Python 3.11+

---

## Dependencies

Core dependencies include:

- requests
- beautifulsoup4
- rich
- stem
- dnspython
- python-whois
- tldextract
- weasyprint
- pdfkit
- pyperclip

Optional:

- Tor
- Ollama

---

## Security Notice

Darkelf Research Suite is intended for:

- Open Source Intelligence (OSINT)
- Security research
- Digital investigations
- Educational purposes
- Defensive cybersecurity

Users are responsible for ensuring they have authorization before investigating systems, services, or data.

---

## License

Licensed under the GNU Lesser General Public License v3.0 (LGPL-3.0-or-later).

See the LICENSE.md file for details.

---

## Author

**Dr. Kevin Moore**

Creator and Lead Developer of the Darkelf Project

---

## Disclaimer

Darkelf Research Suite is provided "as is" without warranty of any kind. The authors assume no liability for misuse, damages, or violations of applicable laws resulting from use of this software.
