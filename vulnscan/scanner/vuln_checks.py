# scanner/vuln_checks.py

import json
import os

class VulnChecker:
    def __init__(self, db_path=None):
        """Initialize with vulnerability database"""
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'vuln_db', 'services.json')
        
        self.vuln_db = self._load_db(db_path)
    
    def _load_db(self, db_path):
        """Load vulnerability database from JSON"""
        default_db = {
            "vsftpd 2.3.4": {
                "cve": "CVE-2011-2523",
                "severity": "Critical",
                "description": "Backdoor vulnerability - opens shell on port 6200",
                "check_type": "version"
            },
            "openssh 4.7": {
                "cve": "CVE-2008-5161",
                "severity": "Medium", 
                "description": "Information disclosure in CBC mode",
                "check_type": "version"
            },
            "openssh 4.6": {
                "cve": "CVE-2008-5161",
                "severity": "Medium",
                "description": "Information disclosure in CBC mode",
                "check_type": "version"
            },
            "apache 2.2.8": {
                "cve": "CVE-2011-3192",
                "severity": "High",
                "description": "Range header DoS vulnerability",
                "check_type": "version"
            },
            "mysql 5.0.51a": {
                "cve": "CVE-2008-2079",
                "severity": "Medium",
                "description": "Privilege escalation vulnerability",
                "check_type": "version"
            },
            "php 5.2.4": {
                "cve": "CVE-2007-1001",
                "severity": "High",
                "description": "Multiple vulnerabilities in PHP",
                "check_type": "version"
            },
            "proftpd 1.3.1": {
                "cve": "CVE-2010-4652",
                "severity": "Medium",
                "description": "SQL injection vulnerability",
                "check_type": "version"
            },
            "samba 3.0.20": {
                "cve": "CVE-2007-2447",
                "severity": "Critical",
                "description": "Remote code execution via MS-RPC",
                "check_type": "version"
            },
            "anonymous_ftp": {
                "cve": None,
                "severity": "Low",
                "description": "Anonymous FTP login allowed",
                "check_type": "config"
            }
        }
        
        try:
            if os.path.exists(db_path):
                with open(db_path, 'r') as f:
                    return json.load(f)
            else:
                # Create default database if file doesn't exist
                os.makedirs(os.path.dirname(db_path), exist_ok=True)
                with open(db_path, 'w') as f:
                    json.dump(default_db, f, indent=2)
                return default_db
        except Exception as e:
            print(f"[-] Error loading vuln DB: {e}")
            return default_db
    
    def check_version(self, banner):
        """Check if banner matches known vulnerable versions"""
        banner_lower = banner.lower()
        findings = []
        
        for service, vuln_info in self.vuln_db.items():
            if vuln_info.get('check_type') == 'version':
                # Check if service version is in banner
                if service.lower() in banner_lower:
                    findings.append({
                        'service': service,
                        'banner': banner[:100],
                        **vuln_info
                    })
        
        return findings
    
    def check_anonymous_ftp(self, target, port=21):
        """Check if FTP allows anonymous login"""
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            response = sock.recv(1024).decode()
            
            # Try anonymous login
            sock.send(b"USER anonymous\r\n")
            response1 = sock.recv(1024).decode()
            
            sock.send(b"PASS anonymous\r\n")
            response2 = sock.recv(1024).decode()
            
            sock.send(b"QUIT\r\n")
            sock.close()
            
            if "230" in response2:  # 230 = login successful
                return [{
                    'service': 'ftp',
                    'banner': response[:100],
                    **self.vuln_db.get('anonymous_ftp', {})
                }]
        except:
            pass
        
        return []
    
    def check_all(self, target, port, banner):
        """Run all vulnerability checks"""
        findings = []
        
        # Version-based checks
        if banner:
            findings.extend(self.check_version(banner))
        
        # Config-based checks
        if port == 21:
            findings.extend(self.check_anonymous_ftp(target, port))
        
        return findings


def check_vulnerabilities(target, port, banner):
    """Quick function to check vulnerabilities"""
    checker = VulnChecker()
    return checker.check_all(target, port, banner)
