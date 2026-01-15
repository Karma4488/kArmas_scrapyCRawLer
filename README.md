# kArmas_scrapyCRawLer

## Description
kArmas_scrapyCRawLer is a red-team-focused web crawler with built-in tools for SQL Injection (SQLi), Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), and header testing. Tailored for advanced usage, the script automates vulnerability detection and pentesting tasks.

## Features
- SQL Injection testing, including error-, blind-, and time-based methods.
- XSS payload injection and DOM sink detection.
- CSRF token validation.
- Automated SQLmap integration for deeper vulnerability exploitation.

This tool is designed for professionals who need precision-built scripts for offensive security.

## Installation
```bash
# Clone the repository
git clone https://github.com/Karma4488/kArmas_scrapyCRawLer.git
cd kArmas_scrapyCRawLer

# Install dependencies
pip install -r requirements.txt

# Start the crawler with a target URL
python3 main.py --target 'https://example.com'
```

## Usage
The tool supports various arguments to customize its behavior:

```bash
usage: main.py [-h] [--cookie COOKIE] [--auth AUTH] [--sqlmap-auto]
               [--tamper-tier {1,2,3}]
               target

kArmas_scrapyCRawLer: Advanced Red-Team Web Crawler

positional arguments:
  target                Starting URL (https://...)

optional arguments:
  -h, --help            show this help message and exit
  --cookie COOKIE       Cookie header value
  --auth AUTH           Auth header, e.g., Authorization: Bearer <token>
  --sqlmap-auto         Auto-run sqlmap on HIGH findings
  --tamper-tier {1,2,3} Tamper tier: 1=light, 2=medium, 3=heavy (default: 1)
```

## Notes
- SQLmap integration requires the `sqlmap.py` script to be located at `~/sqlmap/sqlmap.py`. Adjust `SQLMAP_PATH` in `main.py` otherwise.
- For detailed vulnerability logs, access `results.json` or the `karmas_shadows.db` SQLite database.