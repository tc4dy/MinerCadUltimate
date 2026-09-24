![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![Crawler](https://img.shields.io/badge/Crawler-Web%20Traversal-blue)
![OSINT](https://img.shields.io/badge/OSINT-Intelligence-red)
![Recon](https://img.shields.io/badge/Recon-Recognition-purple)

# MinerCad Recon & Osint Tool

A modular reconnaissance framework for security research and digital asset discovery.

MinerCad performs automated information gathering against a target domain, covering DNS, WHOIS, TLS certificates, open ports, subdomains, HTTP crawling, and content pattern extraction. Findings are consolidated into structured reports (HTML, XML, JSON).

---

## Capabilities

- **DNS enumeration** – A, AAAA, MX, NS, TXT, CNAME and SOA record lookups.
- **WHOIS lookup** – registrar, dates, name servers, and registered contact emails.
- **TLS analysis** – protocol version, cipher, certificate subject, issuer and SANs.
- **Port scanning** – parallel TCP connect scan across 20 common service ports.
- **Subdomain brute force** – dictionary-based resolution using a curated wordlist.
- **Web crawling** – breadth-first traversal with configurable depth and concurrency.
- **Pattern extraction** – API keys, cloud credentials, tokens, internal IPs, config and backup files, API endpoints and technology fingerprints.
- **Security headers audit** – presence and absence of HSTS, CSP, XFO, XCTO, and related headers.
- **WAF detection** – heuristic fingerprinting of common web application firewalls.
- **JavaScript analysis** – extraction of API endpoints, secrets and function names from linked scripts.

---

## Output Formats

| Format | Description |
| :--- | :--- |
| JSON | Structured report suitable for downstream tooling and pipelines. |
| HTML | Self-contained visual report for review and sharing. |
| XML  | Machine-readable report for SIEM and integration workflows. |

Statistics for every scan (categories, data points, coverage) are printed to the console and included in exports.

---

## Requirements

Python 3.8 or later.

```bash
pip install requests beautifulsoup4 dnspython python-whois urllib3
```

### Usage

```bash
pip install -r requirements.txt
python minercad.py
```

Workflow:

1. Enter the target domain (e.g. `example.com`).
2. The scanner runs DNS, WHOIS, TLS, port, subdomain, crawl and JS analysis stages sequentially.
3. Review the console report.
4. Export the findings as JSON, HTML or XML, or print scan statistics.

The interactive menu after the scan accepts:

[1] New scan   [2] JSON   [3] HTML   [4] XML   [5] Stats   [6] Exit

---

## Configuration

Scan parameters are defined in the `Config` class at the top of `minercad.py`:

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `DEPTH` | 4 | Maximum crawl depth. |
| `THREADS` | 15 | Concurrent workers for crawling and scanning. |
| `TIMEOUT` | 12 | HTTP timeout in seconds. |
| `RATE_LIMIT` | 0.1 | Delay between HTTP requests in seconds. |
| `MAX_LINKS_PER_LEVEL` | 100 | Cap on discovered URLs per crawl level. |
| `COMMON_PORTS` | 20 ports | Ports targeted during the scan. |

---

# Legal Notice

This tool is intended for authorized security testing, research, and educational use only. Do not run it against systems you do not own or do not have explicit written permission to test. The author assumes no liability for misuse or damage caused by this software.

