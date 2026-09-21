#!/usr/bin/env python3
import argparse
import sys
import os
from scanner.host_discovery import arp_scan
from scanner.port_scanner import syn_scan
from scanner.service_detect import grab_banner
from scanner.vuln_checks import check_vulnerabilities


def main():
    parser = argparse.ArgumentParser(
        description='VulnScan - Network Vulnerability Scanner',
        epilog='Example: sudo python3 main.py -t 192.168.56.101 -p 1-1000'
    )
    parser.add_argument(
        '-t', '--target', 
        required=True, 
        help='Target IP or network (e.g., 192.168.56.101 or 192.168.56.0/24)'
    )
    parser.add_argument(
        '-p', '--ports', 
        default='1-1000', 
        help='Port range to scan (default: 1-1000, or use comma-separated: 21,22,80,443)'
    )
    parser.add_argument(
        '--discovery', 
        action='store_true', 
        help='Run host discovery only (ARP scan)'
    )
    parser.add_argument(
        '--banner', 
        action='store_true', 
        help='Grab banners from open ports'
    )
    parser.add_argument(
        '--vuln-check', 
        action='store_true', 
        help='Check for known vulnerabilities'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("VulnScan - Network Vulnerability Scanner")
    print("=" * 60)
    print(f"[*] Target: {args.target}")
    
    # Host Discovery Mode
    if args.discovery:
        print("[*] Running ARP host discovery...")
        print("-" * 60)
        hosts = arp_scan(args.target)
        if hosts:
            print(f"[+] Found {len(hosts)} live host(s):")
            for host in hosts:
                print(f"    [+] {host}")
        else:
            print("[-] No hosts found")
        return
    
    # Port Scan Mode
    print(f"[*] Port range: {args.ports}")
    print("-" * 60)
    
    # Parse port range
    ports = []
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = list(range(start, end + 1))
    elif ',' in args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    else:
        ports = [int(args.ports)]
    
    print(f"[*] Scanning {len(ports)} port(s)...")
    print()
    
    # Run SYN scan
    open_ports = syn_scan(args.target, ports)
    
    vuln_count = 0
    
    if open_ports:
        print(f"[+] Found {len(open_ports)} open port(s):")
        print()
        
        for port in open_ports:
            print(f"    [+] Port {port}/tcp - OPEN")
            
            banner = None
            
            # Banner grabbing if requested
            if args.banner or args.vuln_check:
                banner = grab_banner(args.target, port)
                if banner:
                    # Clean up banner for display
                    banner_clean = banner.replace('\n', ' ').replace('\r', '')[:100]
                    print(f"        Banner: {banner_clean}")
                else:
                    print(f"        Banner: [No response]")
            
            # Vulnerability checking
            if args.vuln_check:
                vulns = check_vulnerabilities(args.target, port, banner)
                if vulns:
                    for vuln in vulns:
                        vuln_count += 1
                        print(f"        [!] VULNERABILITY FOUND!")
                        print(f"            Service: {vuln['service']}")
                        print(f"            Description: {vuln['description']}")
                        print(f"            Severity: {vuln['severity']}")
                        if vuln.get('cve'):
                            print(f"            CVE: {vuln['cve']}")
                        print()
        
        print()
    else:
        print("[-] No open ports found")
    
    print("-" * 60)
    if args.vuln_check:
        print(f"[*] Scan complete - {vuln_count} vulnerability(s) found")
    else:
        print("[*] Scan complete")
        print("[*] Use --vuln-check to scan for vulnerabilities")


if __name__ == '__main__':
    # Check for root privileges (required for raw sockets)
    if os.geteuid() != 0:
        print("[-] Error: This script must run as root!")
        print("[-] Raw socket access requires root privileges.")
        print("[-] Run with: sudo python3 main.py ...")
        sys.exit(1)
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)
