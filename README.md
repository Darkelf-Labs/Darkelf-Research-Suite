# Darkelf Research Suite

Darkelf Research Suite is a powerful command‑line research toolkit
designed for advanced web investigation, OSINT workflows, and domain
analysis.\
It combines networking tools, HTML parsing, Tor integration, DNS
inspection, and export utilities into a single interactive CLI
environment.

------------------------------------------------------------------------

## Features

-   **Advanced HTTP Requests**
    -   Robust requests with retry logic
    -   Error handling and timeout protection
-   **Domain & Website Analysis**
    -   WHOIS lookups
    -   TLD extraction
    -   DNS resolution and inspection
-   **HTML Parsing**
    -   Extract structured content from web pages
    -   Parse and analyze page elements
-   **Tor Integration**
    -   Launch Tor sessions
    -   Route research traffic through the Tor network
-   **Rich Terminal UI**
    -   Interactive CLI interface using the `rich` library
    -   Tables, panels, and improved readability
-   **Export Capabilities**
    -   Export pages to PDF
    -   Save structured research results
-   **Clipboard Integration**
    -   Copy extracted data directly to the clipboard
-   **Session Management**
    -   Tabs and bookmarks for persistent research sessions

------------------------------------------------------------------------

## Installation

### 1. Clone the Repository

``` bash
git clone https://github.com/yourusername/darkelf-research-suite.git
cd darkelf-research-suite
```

### 2. Install Dependencies

``` bash
pip install -r requirements.txt
```

------------------------------------------------------------------------

## Requirements

Create a `requirements.txt` file with:

    requests
    rich
    beautifulsoup4
    tldextract
    python-whois
    stem
    dnspython
    pyperclip
    pdfkit
    weasyprint
    psutil

------------------------------------------------------------------------

## Usage

Run the main script:

``` bash
python Darkelf_Research_Suite_v1_8_FINAL.py
```

Example tasks you can perform:

-   Investigate a domain
-   Inspect DNS records
-   Fetch and parse web pages
-   Route requests through Tor
-   Export pages to PDF
-   Save bookmarks for research sessions

------------------------------------------------------------------------

## Project Structure (Recommended)

For future improvements, consider restructuring the project:

    darkelf/
    │
    ├── cli.py
    ├── browser.py
    ├── dns_tools.py
    ├── tor_manager.py
    ├── exporter.py
    ├── research.py
    └── main.py

This modular layout improves maintainability and readability.

------------------------------------------------------------------------

## Security Notice

Darkelf Research Suite is intended for:

-   security research
-   OSINT investigation
-   educational purposes

Always ensure you follow local laws and ethical guidelines when
performing network investigations.

------------------------------------------------------------------------

## Roadmap

Possible future improvements:

-   Modular architecture
-   Plugin support
-   Async networking
-   Integrated search APIs
-   Headless browser support

------------------------------------------------------------------------

## License

LGPL License

You are free to use, modify, and distribute this software.

------------------------------------------------------------------------

## Author

Darkelf Research Suite\
Open‑source research toolkit for advanced CLI investigations.
