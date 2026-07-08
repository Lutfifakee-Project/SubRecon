#!/usr/bin/env python3
"""
SubRecon - Advanced Subdomain Enumeration Tool
Author: Lutfifakee
Description: Multi-source subdomain discovery with takeover detection
"""

import argparse
import csv
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
import dns.resolver
import dns.exception
from colorama import init, Fore, Style
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# Banner
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║                    {Fore.YELLOW}SUBRECon v1.0{Fore.CYAN}                     ║
║        {Fore.GREEN}Advanced Subdomain Enumeration Tool{Fore.CYAN}           ║
║                  {Fore.MAGENTA}By Lutfifakee{Fore.CYAN}                      ║
╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

class SubRecon:
    def __init__(self, domain, output=None, threads=50, bruteforce=False, takeover=False, verbose=False, output_format='all', wordlist=None):
        self.domain = domain
        self.output = output
        self.threads = threads
        self.bruteforce = bruteforce
        self.takeover = takeover
        self.verbose = verbose
        self.output_format = output_format
        self.wordlist = wordlist
        self.subdomains = set()
        self.alive_subdomains = {}
        self.takeover_vulnerable = []
        self.start_time = datetime.now()

        # Headers untuk request
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        # Session untuk reuse connection
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()

    def _log(self, message, level="INFO"):
        """Logging dengan warna"""
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "TAKEOVER": Fore.MAGENTA,
        }
        print(f"{colors.get(level, Fore.WHITE)}[{level}] {message}{Style.RESET_ALL}")

    # ==================== SOURCE FUNCTIONS ====================

    def _fetch_crt_sh(self):
        """crt.sh - Certificate Transparency logs"""
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub.endswith(f".{self.domain}") and sub != self.domain:
                                self.subdomains.add(sub)
        except Exception as e:
            if self.verbose:
                self._log(f"crt.sh error: {e}", "WARNING")

    def _fetch_alienvault(self):
        """AlienVault OTX"""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('passive_dns', []):
                    sub = item.get('hostname', '')
                    if sub and sub.endswith(f".{self.domain}"):
                        self.subdomains.add(sub.lower())
        except Exception as e:
            if self.verbose:
                self._log(f"AlienVault error: {e}", "WARNING")

    def _fetch_bufferover(self):
        """BufferOver.run"""
        url = f"https://dns.bufferover.run/dns?q={self.domain}"
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for sub in data.get('FDNS_A', []):
                    if isinstance(sub, list) and len(sub) > 1:
                        host = sub[1] if len(sub) > 1 else sub[0]
                        if host.endswith(f".{self.domain}"):
                            self.subdomains.add(host.lower())
        except Exception as e:
            if self.verbose:
                self._log(f"BufferOver error: {e}", "WARNING")

    def _fetch_rapiddns(self):
        """RapidDNS"""
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                text = response.text
                matches = re.findall(rf'([a-zA-Z0-9\-_]+\.{re.escape(self.domain)})', text)
                for sub in matches:
                    self.subdomains.add(sub.lower())
        except Exception as e:
            if self.verbose:
                self._log(f"RapidDNS error: {e}", "WARNING")

    def _fetch_certspotter(self):
        """CertSpotter"""
        url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    for dns_name in entry.get('dns_names', []):
                        dns_name = dns_name.strip().lower()
                        if dns_name.endswith(f".{self.domain}") and dns_name != self.domain:
                            self.subdomains.add(dns_name)
        except Exception as e:
            if self.verbose:
                self._log(f"CertSpotter error: {e}", "WARNING")

    def _enumerate_sources(self):
        """Enumerasi dari semua sumber secara paralel"""
        self._log("Enumerating subdomains from sources...", "INFO")
        
        sources = [
            self._fetch_crt_sh,
            self._fetch_alienvault,
            self._fetch_bufferover,
            self._fetch_rapiddns,
            self._fetch_certspotter,
        ]
        
        with ThreadPoolExecutor(max_workers=len(sources)) as executor:
            futures = [executor.submit(source) for source in sources]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if self.verbose:
                        self._log(f"Source error: {e}", "WARNING")
        
        self._log(f"Found {len(self.subdomains)} unique subdomains from sources", "SUCCESS")

    # ==================== BRUTEFORCE ====================

    def _load_wordlist(self):
        """Load wordlist untuk bruteforce"""
        wordlist = []
        
        # Jika user memberikan wordlist custom
        if self.wordlist:
            try:
                with open(self.wordlist, 'r', encoding='utf-8') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                self._log(f"Loaded custom wordlist: {self.wordlist} ({len(wordlist)} entries)", "SUCCESS")
                return wordlist
            except FileNotFoundError:
                self._log(f"Wordlist not found: {self.wordlist}", "WARNING")
        
        # Coba load dari folder wordlists/
        default_paths = [
            'wordlists/common.txt',
            'wordlists/subdomains.txt',
            'common.txt',
            'subdomains.txt'
        ]
        
        for path in default_paths:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                if wordlist:
                    self._log(f"Loaded wordlist from: {path} ({len(wordlist)} entries)", "SUCCESS")
                    return wordlist
            except FileNotFoundError:
                continue
        
        # Jika tidak ada wordlist, gunakan default minimal
        if not wordlist:
            self._log("No wordlist found, using default minimal wordlist", "WARNING")
            wordlist = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
                'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
                'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
                'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
                'web', 'media', 'email', 'images', 'img', 'video', 'download', 'dns',
                'staging', 'api', 'app', 'stage', 'cdn', 'webmail2', 'server', 'cms',
                'backup', 'portal', 'panel', 'monitor', 'source', 'ci', 'jenkins', 'grafana',
                'prometheus', 'elk', 'kibana', 'elasticsearch', 'sso', 'auth', 'login',
                'account', 'my', 'dashboard', 'analytics', 'report', 'log', 'logs',
                'storage', 'cloud', 'office', 'remote', 'exchange', 'share', 'files',
                'drive', 'sync', 'chat', 'call', 'video', 'stream', 'cdn2', 'cdn3',
                'api2', 'app2', 'test2', 'dev2', 'stage2', 'prod', 'production', 'staging2',
                'admin2', 'portal2', 'panel2', 'monitor2', 'backup2', 'storage2', 'cloud2',
                'mail3', 'mx1', 'mx2', 'ns4', 'ns5', 'dns2', 'ftp2', 'smtp2', 'pop2',
                'imap2', 'ldap', 'radius', 'tacacs', 'syslog', 'snmp', 'ntp', 'dhcp',
                'k8s', 'kubernetes', 'docker', 'registry', 'artifactory', 'nexus',
                'sonarqube', 'jira', 'confluence', 'bitbucket', 'gitlab', 'gitea'
            ]
        
        return wordlist

    def _resolve_dns(self, domain):
        """Resolusi DNS untuk validasi subdomain"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            answers = resolver.resolve(domain, 'A')
            if answers:
                return domain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            pass
        return None

    def _bruteforce_subdomains(self):
        """Bruteforce subdomain dengan wordlist"""
        self._log("Starting subdomain bruteforce...", "INFO")
        wordlist = self._load_wordlist()
        found = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for sub in wordlist:
                full = f"{sub}.{self.domain}"
                futures[executor.submit(self._resolve_dns, full)] = full
            
            for future in tqdm(as_completed(futures), total=len(futures), desc="Bruteforcing", unit="sub"):
                sub = futures[future]
                try:
                    result = future.result()
                    if result:
                        found.append(sub)
                        self.subdomains.add(sub)
                        self._log(f"Found: {sub}", "SUCCESS")
                except Exception:
                    pass
        
        self._log(f"Bruteforce found {len(found)} new subdomains", "SUCCESS")

    # ==================== CHECK ALIVE & TAKEOVER ====================

    def _check_alive(self, domain):
        """Cek apakah subdomain aktif"""
        urls = [f"https://{domain}", f"http://{domain}"]
        
        for url in urls:
            try:
                response = self.session.get(
                    url, 
                    timeout=5,
                    allow_redirects=True
                )
                if response.status_code < 500:
                    return {
                        'url': url,
                        'status': response.status_code,
                        'title': self._extract_title(response.text),
                        'server': response.headers.get('Server', 'unknown'),
                        'content_length': len(response.content)
                    }
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue
        return None

    def _extract_title(self, html):
        """Extract title dari HTML"""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()
            return title[:50] + '...' if len(title) > 50 else title
        return 'No Title'

    def _check_takeover(self, domain):
        """Cek potensi subdomain takeover"""
        takeover_patterns = {
            'github.io': 'GitHub Pages',
            'herokuapp.com': 'Heroku',
            'netlify.app': 'Netlify',
            'vercel.app': 'Vercel',
            'readthedocs.io': 'ReadTheDocs',
            's3.amazonaws.com': 'AWS S3',
            's3-website': 'AWS S3',
            'cloudfront.net': 'AWS CloudFront',
            'azurewebsites.net': 'Azure App Service',
            'pages.github.com': 'GitHub Pages',
            'surge.sh': 'Surge',
            'firebaseapp.com': 'Firebase',
            'bitbucket.io': 'Bitbucket',
            'cname.heroku-dns.com': 'Heroku',
            'gitlab.io': 'GitLab Pages',
            'stormkit.io': 'Stormkit',
            'render.com': 'Render',
            'fly.dev': 'Fly.io',
            'railway.app': 'Railway',
            'koyeb.app': 'Koyeb',
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            answers = resolver.resolve(domain, 'CNAME')
            
            for rdata in answers:
                cname = str(rdata.target).rstrip('.')
                for pattern, service in takeover_patterns.items():
                    if pattern in cname:
                        try:
                            response = self.session.get(f"http://{domain}", timeout=5)
                            if response.status_code in [404, 403, 400]:
                                return {
                                    'cname': cname,
                                    'service': service,
                                    'vulnerable': True,
                                    'evidence': f'CNAME points to {cname} (status {response.status_code})'
                                }
                            if any(keyword in response.text.lower() for keyword in ['not found', 'no such', 'does not exist', 'repository not found']):
                                return {
                                    'cname': cname,
                                    'service': service,
                                    'vulnerable': True,
                                    'evidence': 'Service returns "not found" response'
                                }
                        except requests.exceptions.ConnectionError:
                            return {
                                'cname': cname,
                                'service': service,
                                'vulnerable': True,
                                'evidence': f'CNAME points to {cname} but domain is not resolvable'
                            }
                        except:
                            pass
                        return None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            pass
        return None

    # ==================== OUTPUT METHODS ====================

    def _get_output_filename(self, extension):
        """Generate output filename with proper extension"""
        if self.output:
            base = self.output.rsplit('.', 1)[0]
            return f"{base}.{extension}"
        return f"{self.domain}.{extension}"

    def _save_output(self):
        """Save results to JSON"""
        output_data = {
            'domain': self.domain,
            'timestamp': self.start_time.isoformat(),
            'total_subdomains': len(self.subdomains),
            'alive_subdomains': len(self.alive_subdomains),
            'takeover_vulnerable': self.takeover_vulnerable,
            'subdomains': {
                'all': sorted(list(self.subdomains)),
                'alive': self.alive_subdomains
            }
        }
        
        try:
            json_file = self._get_output_filename('json')
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, default=str)
            self._log(f"Results saved to {json_file}", "SUCCESS")
        except Exception as e:
            self._log(f"Failed to save JSON: {e}", "ERROR")

    def _save_csv(self):
        """Save results to CSV file"""
        if not self.alive_subdomains and not self.subdomains:
            self._log("No data to export to CSV", "WARNING")
            return None
        
        csv_file = self._get_output_filename('csv')
        
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                writer.writerow(['=== SUBRECON SCAN REPORT ==='])
                writer.writerow(['Target Domain', self.domain])
                writer.writerow(['Scan Date', self.start_time.isoformat()])
                writer.writerow(['Total Subdomains Found', len(self.subdomains)])
                writer.writerow(['Alive Subdomains', len(self.alive_subdomains)])
                writer.writerow(['Takeover Vulnerable', len(self.takeover_vulnerable)])
                elapsed = (datetime.now() - self.start_time).total_seconds()
                writer.writerow(['Time Elapsed', f"{elapsed:.2f} seconds"])
                writer.writerow([])
                
                if self.takeover_vulnerable:
                    writer.writerow(['=== TAKEOVER VULNERABLE DOMAINS ==='])
                    writer.writerow(['Domain', 'CNAME', 'Service', 'Evidence'])
                    for item in self.takeover_vulnerable:
                        writer.writerow([
                            item.get('domain', ''),
                            item.get('cname', ''),
                            item.get('service', ''),
                            item.get('evidence', '')
                        ])
                    writer.writerow([])
                else:
                    writer.writerow(['=== TAKEOVER VULNERABILITIES ==='])
                    writer.writerow(['No takeover vulnerabilities found'])
                    writer.writerow([])
                
                if self.alive_subdomains:
                    writer.writerow(['=== ALIVE SUBDOMAINS ==='])
                    writer.writerow(['Subdomain', 'URL', 'Status Code', 'Title', 'Server', 'Content Length'])
                    for sub, info in sorted(self.alive_subdomains.items()):
                        writer.writerow([
                            sub,
                            info.get('url', ''),
                            info.get('status', 0),
                            info.get('title', 'No Title'),
                            info.get('server', 'unknown'),
                            info.get('content_length', 0)
                        ])
                    writer.writerow([])
                else:
                    writer.writerow(['=== ALIVE SUBDOMAINS ==='])
                    writer.writerow(['No alive subdomains found'])
                    writer.writerow([])
                
                if self.subdomains:
                    writer.writerow(['=== ALL SUBDOMAINS (Including Non-Alive) ==='])
                    writer.writerow(['Subdomain'])
                    for sub in sorted(self.subdomains):
                        writer.writerow([sub])
                
                writer.writerow([])
                writer.writerow(['=== METADATA ==='])
                writer.writerow(['Tool', 'SubRecon v1.0'])
                writer.writerow(['Author', 'Lutfifakee'])
                writer.writerow(['Bruteforce', 'ON' if self.bruteforce else 'OFF'])
                writer.writerow(['Takeover Check', 'ON' if self.takeover else 'OFF'])
                writer.writerow(['Threads Used', self.threads])
            
            self._log(f"CSV results saved to {csv_file}", "SUCCESS")
            return csv_file
            
        except Exception as e:
            self._log(f"Failed to save CSV: {e}", "ERROR")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return None

    def _save_txt(self):
        """Save results to TXT file"""
        if not self.alive_subdomains and not self.subdomains:
            self._log("No data to export to TXT", "WARNING")
            return None
        
        txt_file = self._get_output_filename('txt')
        
        try:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write("="*70 + "\n")
                f.write(f"  SUBRECON SCAN REPORT\n")
                f.write(f"  Target: {self.domain}\n")
                f.write(f"  Date: {self.start_time.isoformat()}\n")
                f.write("="*70 + "\n\n")
                
                f.write("📊 SUMMARY\n")
                f.write("-"*70 + "\n")
                f.write(f"  Total Subdomains Found : {len(self.subdomains)}\n")
                f.write(f"  Alive Subdomains       : {len(self.alive_subdomains)}\n")
                f.write(f"  Takeover Vulnerable    : {len(self.takeover_vulnerable)}\n")
                f.write(f"  Time Elapsed           : {elapsed:.2f} seconds\n")
                f.write(f"  Bruteforce             : {'ON' if self.bruteforce else 'OFF'}\n")
                f.write(f"  Takeover Check         : {'ON' if self.takeover else 'OFF'}\n")
                f.write(f"  Threads Used           : {self.threads}\n")
                f.write("-"*70 + "\n\n")
                
                if self.takeover_vulnerable:
                    f.write("🚨 TAKEOVER VULNERABLE DOMAINS\n")
                    f.write("-"*70 + "\n")
                    for item in self.takeover_vulnerable:
                        f.write(f"  ▶ {item.get('domain', '')}\n")
                        f.write(f"    CNAME     : {item.get('cname', '')}\n")
                        f.write(f"    Service   : {item.get('service', '')}\n")
                        f.write(f"    Evidence  : {item.get('evidence', '')}\n")
                        f.write("\n")
                    f.write("-"*70 + "\n\n")
                else:
                    f.write("✅ No takeover vulnerabilities found\n\n")
                
                if self.alive_subdomains:
                    f.write("🌐 ALIVE SUBDOMAINS\n")
                    f.write("-"*70 + "\n")
                    for sub, info in sorted(self.alive_subdomains.items()):
                        f.write(f"  {sub}\n")
                        f.write(f"    URL      : {info.get('url', '')}\n")
                        f.write(f"    Status   : {info.get('status', 0)}\n")
                        f.write(f"    Title    : {info.get('title', 'No Title')}\n")
                        f.write(f"    Server   : {info.get('server', 'unknown')}\n")
                        f.write(f"    Length   : {info.get('content_length', 0)} bytes\n")
                        f.write("\n")
                    f.write("-"*70 + "\n\n")
                
                if self.subdomains:
                    f.write("📋 ALL SUBDOMAINS (Including Non-Alive)\n")
                    f.write("-"*70 + "\n")
                    for sub in sorted(self.subdomains):
                        f.write(f"  {sub}\n")
                    f.write("-"*70 + "\n")
                
                f.write("\n" + "="*70 + "\n")
                f.write(f"  Generated by SubRecon v1.0 | Author: Lutfifakee\n")
                f.write("="*70 + "\n")
            
            self._log(f"TXT report saved to {txt_file}", "SUCCESS")
            return txt_file
            
        except Exception as e:
            self._log(f"Failed to save TXT: {e}", "ERROR")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return None

    def _save_html(self):
        """Save results to HTML file"""
        if not self.alive_subdomains and not self.subdomains:
            self._log("No data to export to HTML", "WARNING")
            return None
        
        html_file = self._get_output_filename('html')
        
        try:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            
            html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubRecon Report - {self.domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #161b22;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }}
        h1 {{
            color: #58a6ff;
            border-bottom: 2px solid #30363d;
            padding-bottom: 15px;
            margin-bottom: 25px;
        }}
        h2 {{
            color: #f0883e;
            margin: 25px 0 15px 0;
            padding-bottom: 10px;
            border-bottom: 1px solid #30363d;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-card {{
            background: #21262d;
            padding: 15px 20px;
            border-radius: 8px;
            border-left: 4px solid #58a6ff;
        }}
        .summary-card .label {{
            font-size: 12px;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .summary-card .value {{
            font-size: 24px;
            font-weight: bold;
            color: #f0f6fc;
            margin-top: 5px;
        }}
        .summary-card.danger {{ border-left-color: #da3633; }}
        .summary-card.success {{ border-left-color: #3fb950; }}
        .summary-card.warning {{ border-left-color: #d29922; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            font-size: 14px;
        }}
        th {{
            background: #21262d;
            color: #f0f6fc;
            padding: 12px 15px;
            text-align: left;
            border-bottom: 2px solid #30363d;
        }}
        td {{
            padding: 10px 15px;
            border-bottom: 1px solid #21262d;
        }}
        tr:hover {{
            background: #1c2128;
        }}
        .status-200 {{ color: #3fb950; }}
        .status-300 {{ color: #d29922; }}
        .status-400 {{ color: #f85149; }}
        .status-500 {{ color: #da3633; }}
        
        .takeover-box {{
            background: #21262d;
            padding: 15px 20px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid #da3633;
        }}
        .takeover-box strong {{
            color: #f85149;
        }}
        
        .subdomain-list {{
            columns: 3;
            column-gap: 20px;
            padding: 10px 0;
        }}
        .subdomain-list li {{
            list-style: none;
            padding: 3px 0;
            font-size: 13px;
            color: #8b949e;
            break-inside: avoid;
        }}
        .subdomain-list li::before {{
            content: "• ";
            color: #58a6ff;
        }}
        
        .footer {{
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #30363d;
            text-align: center;
            font-size: 12px;
            color: #8b949e;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
        }}
        .badge-success {{ background: #1f3a2a; color: #3fb950; }}
        .badge-danger {{ background: #3a1f1f; color: #f85149; }}
        .badge-warning {{ background: #3a2f1f; color: #d29922; }}
        
        @media (max-width: 768px) {{
            .subdomain-list {{ columns: 2; }}
            .summary-grid {{ grid-template-columns: 1fr 1fr; }}
        }}
        @media (max-width: 480px) {{
            .subdomain-list {{ columns: 1; }}
            .summary-grid {{ grid-template-columns: 1fr; }}
            table {{ font-size: 12px; }}
            td, th {{ padding: 8px 10px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 SubRecon Scan Report</h1>
        <p><strong>Target:</strong> {self.domain}</p>
        <p><strong>Date:</strong> {self.start_time.isoformat()}</p>
        
        <h2>📊 Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="label">Total Subdomains</div>
                <div class="value">{len(self.subdomains)}</div>
            </div>
            <div class="summary-card success">
                <div class="label">Alive Subdomains</div>
                <div class="value">{len(self.alive_subdomains)}</div>
            </div>
            <div class="summary-card danger">
                <div class="label">Takeover Vulnerable</div>
                <div class="value">{len(self.takeover_vulnerable)}</div>
            </div>
            <div class="summary-card warning">
                <div class="label">Time Elapsed</div>
                <div class="value">{elapsed:.2f}s</div>
            </div>
        </div>
        
        <div style="display: flex; gap: 10px; flex-wrap: wrap; margin: 15px 0;">
            <span class="badge badge-success">Bruteforce: {'ON' if self.bruteforce else 'OFF'}</span>
            <span class="badge badge-warning">Takeover Check: {'ON' if self.takeover else 'OFF'}</span>
            <span class="badge">Threads: {self.threads}</span>
        </div>
'''

            if self.takeover_vulnerable:
                html_content += '''
        <h2>🚨 Takeover Vulnerable Domains</h2>
'''
                for item in self.takeover_vulnerable:
                    html_content += f'''
        <div class="takeover-box">
            <strong>▶ {item.get('domain', '')}</strong><br>
            CNAME: {item.get('cname', '')}<br>
            Service: {item.get('service', '')}<br>
            Evidence: {item.get('evidence', '')}
        </div>
'''
            else:
                html_content += '''
        <h2>✅ Takeover Vulnerabilities</h2>
        <p style="color: #3fb950;">No takeover vulnerabilities found.</p>
'''

            if self.alive_subdomains:
                html_content += '''
        <h2>🌐 Alive Subdomains</h2>
        <table>
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>Status</th>
                    <th>Title</th>
                    <th>Server</th>
                    <th>Length</th>
                </tr>
            </thead>
            <tbody>
'''
                for sub, info in sorted(self.alive_subdomains.items()):
                    status = info.get('status', 0)
                    status_class = ''
                    if status < 300:
                        status_class = 'status-200'
                    elif status < 400:
                        status_class = 'status-300'
                    elif status < 500:
                        status_class = 'status-400'
                    else:
                        status_class = 'status-500'
                    
                    html_content += f'''
                <tr>
                    <td><strong>{sub}</strong></td>
                    <td class="{status_class}">{status}</td>
                    <td>{info.get('title', 'No Title')[:50]}</td>
                    <td>{info.get('server', 'unknown')}</td>
                    <td>{info.get('content_length', 0)}</td>
                </tr>
'''
                html_content += '''
            </tbody>
        </table>
'''

            if self.subdomains:
                html_content += f'''
        <h2>📋 All Subdomains ({len(self.subdomains)})</h2>
        <ul class="subdomain-list">
'''
                for sub in sorted(self.subdomains):
                    html_content += f'            <li>{sub}</li>\n'
                html_content += '''
        </ul>
'''

            html_content += f'''
        <div class="footer">
            Generated by <strong>SubRecon v1.0</strong> | Author: Lutfifakee<br>
            {self.start_time.strftime("%Y-%m-%d %H:%M:%S")}
        </div>
    </div>
</body>
</html>
'''
            
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self._log(f"HTML report saved to {html_file}", "SUCCESS")
            return html_file
            
        except Exception as e:
            self._log(f"Failed to save HTML: {e}", "ERROR")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return None

    def _generate_output(self):
        """Generate output results based on format selection"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}SUMMARY REPORT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"Target Domain    : {self.domain}")
        print(f"Total Subdomains : {len(self.subdomains)}")
        print(f"Alive Subdomains : {len(self.alive_subdomains)}")
        print(f"Time Elapsed     : {elapsed:.2f} seconds")
        if self.takeover:
            print(f"Takeover Vuln.   : {len(self.takeover_vulnerable)}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

        if self.takeover_vulnerable:
            print(f"{Fore.RED}🚨 TAKEOVER VULNERABLE DOMAINS:{Style.RESET_ALL}")
            for item in self.takeover_vulnerable:
                print(f"  {Fore.MAGENTA}▶ {item['domain']}{Style.RESET_ALL}")
                print(f"    CNAME     : {item['cname']}")
                print(f"    Service   : {item['service']}")
                print(f"    Evidence  : {item['evidence']}")
                print()
        
        if self.alive_subdomains:
            print(f"{Fore.GREEN}🌐 ALIVE SUBDOMAINS:{Style.RESET_ALL}")
            for sub, info in sorted(self.alive_subdomains.items()):
                status_color = Fore.GREEN if info['status'] < 400 else Fore.RED
                print(f"  {status_color}{sub}{Style.RESET_ALL}")
                print(f"    URL      : {info['url']}")
                print(f"    Status   : {info['status']}")
                print(f"    Title    : {info['title']}")
                print(f"    Server   : {info['server']}")
                print()

        if self.output:
            if self.output_format == 'all':
                formats = ['json', 'csv', 'txt', 'html']
            else:
                formats = [f.strip() for f in self.output_format.split(',')]
            
            if 'json' in formats:
                self._save_output()
            if 'csv' in formats:
                self._save_csv()
            if 'txt' in formats:
                self._save_txt()
            if 'html' in formats:
                self._save_html()

    # ==================== MAIN PROCESS ====================

    def run(self):
        """Main execution"""
        print(BANNER)
        self._log(f"Target: {self.domain}", "INFO")
        self._log(f"Threads: {self.threads}", "INFO")
        self._log(f"Bruteforce: {'ON' if self.bruteforce else 'OFF'}", "INFO")
        self._log(f"Takeover Check: {'ON' if self.takeover else 'OFF'}", "INFO")
        self._log(f"Output Format: {self.output_format}", "INFO")
        print()

        self._enumerate_sources()

        if self.bruteforce:
            self._bruteforce_subdomains()

        if self.subdomains:
            self._log(f"Checking {len(self.subdomains)} subdomains...", "INFO")
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {}
                for sub in self.subdomains:
                    futures[executor.submit(self._check_alive, sub)] = sub
                
                for future in tqdm(as_completed(futures), total=len(futures), desc="Validating", unit="host"):
                    sub = futures[future]
                    try:
                        result = future.result()
                        if result:
                            self.alive_subdomains[sub] = result
                            self._log(f"Alive: {sub} ({result['status']})", "SUCCESS")
                    except Exception:
                        pass

            self._log(f"Found {len(self.alive_subdomains)} alive subdomains", "SUCCESS")

        if self.takeover and self.alive_subdomains:
            self._log("Checking for subdomain takeover vulnerabilities...", "INFO")
            for sub in self.alive_subdomains:
                result = self._check_takeover(sub)
                if result and result.get('vulnerable'):
                    self.takeover_vulnerable.append({
                        'domain': sub,
                        'cname': result.get('cname'),
                        'service': result.get('service'),
                        'evidence': result.get('evidence')
                    })
                    self._log(f"TAKEOVER VULNERABLE: {sub} -> {result.get('cname')}", "TAKEOVER")

        self._generate_output()


def main():
    parser = argparse.ArgumentParser(
        description="SubRecon - Advanced Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan (terminal only)
  python subrecon.py -d example.com

  # Full scan with all formats
  python subrecon.py -d example.com -b --takeover -o results

  # Only JSON output
  python subrecon.py -d example.com -o results --format json

  # JSON + CSV only
  python subrecon.py -d example.com -o results --format json,csv

  # JSON + HTML for client report
  python subrecon.py -d example.com -o report --format json,html

  # All formats (explicit)
  python subrecon.py -d example.com -o results --format all

  # Custom wordlist
  python subrecon.py -d example.com -b -w wordlists/custom.txt -o results
        """
    )
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-o', '--output', help='Output filename (without extension)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('-b', '--bruteforce', action='store_true', help='Enable subdomain bruteforce')
    parser.add_argument('-w', '--wordlist', default='wordlists/common.txt', help='Custom wordlist for bruteforce (default: wordlists/common.txt)')
    parser.add_argument('--takeover', action='store_true', help='Check for subdomain takeover')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--format', default='all', 
                       help='Output formats: json,csv,txt,html or all (default: all)')
    
    args = parser.parse_args()
    
    domain = args.domain.lower().strip()
    if not re.match(r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$', domain):
        print(f"{Fore.RED}Error: Invalid domain format{Style.RESET_ALL}")
        sys.exit(1)
    
    try:
        recon = SubRecon(
            domain=domain,
            output=args.output,
            threads=args.threads,
            bruteforce=args.bruteforce,
            takeover=args.takeover,
            verbose=args.verbose,
            output_format=args.format,
            wordlist=args.wordlist
        )
        recon.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()