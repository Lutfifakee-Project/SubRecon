# SubRecon - Advanced Subdomain Enumeration Tool

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0-orange)](https://github.com/Lutfifakee-Project/SubRecon)

**SubRecon** is an advanced subdomain enumeration tool with multi-source support, fast bruteforce, subdomain takeover detection, and 4 output formats.

## Features

- Multi-Source Enumeration - 5 passive sources (crt.sh, AlienVault, BufferOver, RapidDNS, CertSpotter)
- Fast Bruteforce - 1,600+ subdomains/second with threading
- Takeover Detection - 20+ service patterns (GitHub Pages, Heroku, AWS S3, etc.)
- 4 Output Formats - JSON, CSV, TXT, HTML
- Professional HTML Report - Dark mode with modern styling
- Flexible Format Selection - Choose formats with --format
- Auto Wordlist - Automatically loads from wordlists/common.txt

## Installation

git clone https://github.com/Lutfifakee-Project/SubRecon
cd SubRecon
pip install -r requirements.txt

## Usage

Basic Scan (Terminal Only):
python subrecon.py -d example.com

Scan with Bruteforce:
python subrecon.py -d example.com -b -o results

Full Scan with All Features:
python subrecon.py -d example.com -b --takeover -o full_report

Select Specific Output Formats:
Only JSON:
python subrecon.py -d example.com -o results --format json

JSON + CSV:
python subrecon.py -d example.com -o results --format json,csv

JSON + HTML (client report):
python subrecon.py -d example.com -o report --format json,html

Custom Wordlist:
python subrecon.py -d example.com -b -w wordlists/custom.txt -o results

Large Domain with More Threads:
python subrecon.py -d google.com -b --takeover -t 100 -o google

## Output Formats

Format: JSON
Extension: .json
Use Case: API integration & other tools

Format: CSV
Extension: .csv
Use Case: Analysis in Excel/Google Sheets

Format: TXT
Extension: .txt
Use Case: Human-readable text report

Format: HTML
Extension: .html
Use Case: Professional visual report (dark mode)

Example JSON Output:
{
  "domain": "example.com",
  "timestamp": "2026-07-06T13:42:44.641965",
  "total_subdomains": 2,
  "alive_subdomains": 1,
  "takeover_vulnerable": [],
  "subdomains": {
    "all": ["*.example.com", "www.example.com"],
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

## Arguments

-d, --domain : Target domain (Required)
-o, --output : Output filename (without extension)
-t, --threads : Number of threads (default: 50)
-b, --bruteforce : Enable subdomain bruteforce
-w, --wordlist : Custom wordlist (default: wordlists/common.txt)
--takeover : Check for subdomain takeover
-v, --verbose : Verbose output
--format : Output formats: json,csv,txt,html or all (default: all)

## Project Structure

SubRecon/
├── subrecon.py          # Main script
├── requirements.txt     # Dependencies
├── wordlists/           # Wordlist folder
│   └── common.txt      # Wordlist (142 entries)
├── README.md           # Documentation
└── LICENSE             # MIT License

## Performance

example.com: 7 subdomains, 1 alive, 7 seconds
google.com: 179 subdomains, 65 alive, 73 seconds
github.com: 100+ subdomains, 50+ alive, ~60 seconds

## Data Sources

This tool uses public data sources:
- crt.sh - Certificate Transparency Logs
- AlienVault OTX - Open Threat Exchange
- BufferOver.run - DNS Recon
- RapidDNS - Subdomain Database
- CertSpotter - Certificate Monitoring

## Disclaimer

This tool is made for educational and authorized security testing purposes only.
- Use only on domains you own or have permission to test.
- The author is not responsible for any misuse of this tool.
- Comply with all applicable laws and regulations in your jurisdiction.

## Contributing

Contributions are welcome! Please open an Issue or Pull Request if you have suggestions or improvements.

## License

MIT License - see LICENSE file for details.
---

Don't forget to star this project if you find it useful!
