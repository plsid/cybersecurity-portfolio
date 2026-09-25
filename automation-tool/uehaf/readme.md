# OmniScan 🛡️ 

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity)

**OmniScan** (formerly UEHAF) is a high-performance, multi-threaded Automated Vulnerability Assessment and Penetration Testing framework. Built for security engineers and penetration testers, it maps external attack surfaces, identifies misconfigurations, and verifies known vulnerabilities across networks, web apps, APIs, and cloud infrastructure.

> **⚠️ Legal Disclaimer:** OmniScan is strictly for authorized security auditing, educational purposes, and professional penetration testing. Unauthorized scanning of systems or networks is illegal. The developers assume no liability for misuse. Always obtain explicit, written permission before testing.

---

## 📋 Table of Contents
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Module Breakdown](#-module-breakdown)
- [Reporting](#-reporting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

- **Concurrent Execution:** Highly threaded architecture for rapid network and web scanning.
- **Web & API Security:** Detects OWASP Top 10 vulnerabilities (SQLi, XSS, LFI, RCE, IDOR, Mass Assignment).
- **Cloud Auditing:** Identifies exposed AWS S3, Azure Blob, GCP buckets, and Kubernetes endpoints.
- **Exploit Verification:** Validates critical CVEs (e.g., Log4Shell, EternalBlue) and auto-generates Metasploit `.rc` scripts.
- **Smart Brute-Forcing:** Rate-limited credential testing for SSH, FTP, MySQL, and HTTP Basic Auth.
- **Wireless Auditing:** Scans 802.11 networks for weak encryption (WEP/Open) and WPS vulnerabilities.

---

## ⚙️ Prerequisites

- **OS:** Kali Linux, Parrot OS, or any Debian-based distribution (recommended)
- **Python:** Version 3.8 or higher
- **System Tools:** `nmap`, `dnsutils` (for `dig`), `scapy`, `wireless-tools` (for `iwlist`), `network-manager`

---

## 🚀 Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/plsid/omniscan.git](https://github.com/plsid/omniscan.git)
   cd omniscan
