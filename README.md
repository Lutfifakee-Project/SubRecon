# 🔎 SubRecon - Advanced Subdomain Enumeration Tool

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0-orange.svg)](https://github.com/Lutfifakee-Project/SubRecon)

**SubRecon** is a fast and advanced subdomain enumeration tool designed for penetration testers, bug bounty hunters, and security researchers.

It combines multiple passive intelligence sources, high-speed brute-force enumeration, subdomain takeover detection, and professional reporting into a single lightweight tool.

---

# ✨ Features

- 🔍 **Multi-Source Enumeration**
  - crt.sh
  - AlienVault OTX
  - BufferOver
  - RapidDNS
  - CertSpotter

- ⚡ **Fast Brute-force Engine**
  - Multi-threaded scanning
  - 1,600+ subdomains/second (hardware dependent)

- 🚨 **Subdomain Takeover Detection**
  - Detects 20+ common takeover fingerprints
  - GitHub Pages
  - Heroku
  - AWS S3
  - Azure
  - Netlify
  - Vercel
  - Firebase
  - And many more

- 📊 **Multiple Output Formats**
  - JSON
  - CSV
  - TXT
  - HTML

- 🎨 **Professional HTML Report**
  - Modern dark theme
  - Easy to read
  - Suitable for client reports

- 🎯 **Flexible Output Selection**
  - Generate only the formats you need using `--format`

- 📁 **Automatic Wordlist Loading**
  - Loads `wordlists/common.txt` automatically

---

# 📦 Installation

Clone the repository:

```bash
git clone https://github.com/Lutfifakee-Project/SubRecon.git
```

Move into the project directory:

```bash
cd SubRecon
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

# 🚀 Usage

## Basic Scan

```bash
python subrecon.py -d example.com
```

---

## Scan with Brute-force

```bash
python subrecon.py -d example.com -b -o results
```

---

## Full Scan

Passive enumeration + brute-force + takeover detection.

```bash
python subrecon.py \
    -d example.com \
    -b \
    --takeover \
    -o full_report
```

---

## Select Output Formats

Generate only JSON:

```bash
python subrecon.py \
    -d example.com \
    -o results \
    --format json
```

Generate JSON + CSV:

```bash
python subrecon.py \
    -d example.com \
    -o results \
    --format json,csv
```

Generate JSON + HTML:

```bash
python subrecon.py \
    -d example.com \
    -o report \
    --format json,html
```

Generate all formats:

```bash
python subrecon.py \
    -d example.com \
    -o report \
    --format all
```

---

## Custom Wordlist

```bash
python subrecon.py \
    -d example.com \
    -b \
    -w wordlists/custom.txt \
    -o results
```

---

## Increase Thread Count

```bash
python subrecon.py \
    -d google.com \
    -b \
    --takeover \
    -t 100 \
    -o google
```

---

# 📊 Output Formats

| Format | Extension | Purpose |
|---------|-----------|----------|
| JSON | `.json` | API integration & automation |
| CSV | `.csv` | Excel / Google Sheets |
| TXT | `.txt` | Human-readable report |
| HTML | `.html` | Professional visual report |

---

# 📄 Example JSON Output

```json
{
  "domain": "example.com",
  "timestamp": "2026-07-06T13:42:44.641965",
  "total_subdomains": 2,
  "alive_subdomains": 1,
  "takeover_vulnerable": [],
  "subdomains": {
    "all": [
      "*.example.com",
      "www.example.com"
    ],
    "alive": {
      "www.example.com": {
        "url": "https://www.example.com",
        "status": 200,
        "title": "Example Domain",
        "server": "cloudflare",
        "content_length": 559
      }
    }
  }
}
```

---

# 🛠️ Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-d`, `--domain` | Target domain | **Required** |
| `-o`, `--output` | Output filename (without extension) | - |
| `-t`, `--threads` | Number of threads | `50` |
| `-b`, `--bruteforce` | Enable brute-force | Disabled |
| `-w`, `--wordlist` | Custom wordlist | `wordlists/common.txt` |
| `--takeover` | Check for takeover vulnerabilities | Disabled |
| `-v`, `--verbose` | Verbose output | Disabled |
| `--format` | Output formats (`json,csv,txt,html` or `all`) | `all` |

---

# 📁 Project Structure

```text
SubRecon/
│
├── subrecon.py
├── requirements.txt
├── README.md
├── LICENSE
│
└── wordlists/
    └── common.txt
```

---

# ⚡ Performance

| Target | Total Subdomains | Alive | Time |
|---------|-----------------|-------|------|
| example.com | 7 | 1 | ~7 sec |
| google.com | 179 | 65 | ~73 sec |
| github.com | 100+ | 50+ | ~60 sec |

> **Note:** Results depend on network quality, target size, and thread count.

---

# 🌐 Passive Data Sources

SubRecon collects subdomains from publicly available intelligence sources:

- crt.sh
- AlienVault OTX
- BufferOver.run
- RapidDNS
- CertSpotter

---

# ⚠️ Disclaimer

This project is intended **only for educational purposes and authorized security testing**.

- Only scan domains that you own or have explicit permission to test.
- Do not use this tool for unauthorized activities.
- The author assumes no responsibility for misuse or damage caused by this software.
- Always comply with applicable laws and regulations in your jurisdiction.

---

# 🤝 Contributing

Contributions are welcome!

If you have ideas, improvements, or bug fixes:

1. Fork the repository.
2. Create a new branch.
3. Commit your changes.
4. Open a Pull Request.

Issues and feature requests are also appreciated.

---

# 📜 License

This project is licensed under the **MIT License**.

See the [LICENSE](LICENSE) file for more information.
