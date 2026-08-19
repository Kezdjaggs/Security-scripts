#!/usr/bin/env python3
"""
Network Reconnaissance Tool
Author: Kehinde Jaggs | Certified Ethical Hacker (CEH)
Description: Automated network scanning and reporting tool for penetration testing
Disclaimer: For authorized testing and educational purposes only
"""

import subprocess
import sys
import os
import datetime
import json
import re

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    """Display tool banner"""
    banner = f"""
{Colors.BLUE}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🔐 Network Reconnaissance Tool - CEH Edition 🔐         ║
║                                                              ║
║     Author: Kehinde Jaggs                                    ║
║     Certified Ethical Hacker (CEH)                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}
    """
    print(banner)

def validate_target(target):
    """Validate the target input"""
    # Simple validation - check if it looks like an IP or domain
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if re.match(ip_pattern, target) or re.match(domain_pattern, target):
        return True
    return False

def run_nmap_scan(target, scan_type="quick"):
    """
    Run Nmap scan on the target
    scan_type: "quick" (top 100 ports) or "full" (all ports)
    """
    print(f"{Colors.YELLOW}[+] Starting scan on target: {target}{Colors.RESET}")
    
    if scan_type == "quick":
        nmap_cmd = ['nmap', '-sV', '-T4', '-F', target]
        print(f"{Colors.BLUE}[+] Quick scan: Top 100 ports{Colors.RESET}")
    else:
        nmap_cmd = ['nmap', '-sV', '-T4', '-p-', target]
        print(f"{Colors.BLUE}[+] Full scan: All 65535 ports (this may take a while){Colors.RESET}")
    
    try:
        result = subprocess.run(
            nmap_cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[+] Scan completed successfully!{Colors.RESET}")
            return result.stdout
        else:
            print(f"{Colors.RED}[-] Scan failed with error:{Colors.RESET}")
            print(result.stderr)
            return None
            
    except subprocess.TimeoutExpired:
        print(f"{Colors.RED}[-] Scan timed out after 10 minutes{Colors.RESET}")
        return None
    except FileNotFoundError:
        print(f"{Colors.RED}[-] Nmap not found! Please install Nmap first.{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Install with: sudo apt-get install nmap (Linux){Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Or: brew install nmap (Mac){Colors.RESET}")
        return None

def parse_nmap_output(output):
    """Parse Nmap output to extract useful information"""
    if not output:
        return {}
    
    results = {
        "open_ports": [],
        "services": [],
        "os_detection": None
    }
    
    lines = output.split('\n')
    for line in lines:
        # Look for open ports
        if '/tcp' in line and 'open' in line:
            parts = line.split()
            if len(parts) >= 3:
                port_info = {
                    "port": parts[0],
                    "service": parts[2]
                }
                results["open_ports"].append(port_info)
                results["services"].append(parts[2])
        
        # Look for OS detection
        if 'OS details' in line:
            results["os_detection"] = line.replace('OS details:', '').strip()
    
    return results

def generate_report(target, scan_output, parsed_results, scan_type):
    """Generate a professional report"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = f"""
{'='*60}
🔐 NETWORK RECONNAISSANCE REPORT
{'='*60}

📋 Scan Information:
    Target: {target}
    Scan Type: {scan_type.upper()}
    Date/Time: {timestamp}
    Scanner: Kehinde Jaggs (CEH)

📊 Scan Results:
    Total Open Ports Found: {len(parsed_results.get('open_ports', []))}
    
    Open Ports & Services:
"""
    
    if parsed_results.get('open_ports'):
        for port in parsed_results['open_ports']:
            report += f"    - {port['port']} : {port['service']}\n"
    else:
        report += "    No open ports found or scan returned no results.\n"
    
    if parsed_results.get('os_detection'):
        report += f"""
🔍 OS Detection:
    {parsed_results['os_detection']}
"""
    
    report += f"""
📝 Raw Scan Output:
{'-'*60}
{scan_output if scan_output else 'No output captured'}
{'-'*60}

⚠️  DISCLAIMER:
    This scan was conducted for authorized testing purposes only.
    Unauthorized scanning is illegal and unethical.

✅ Report Generated By:
    Kehinde Jaggs
    Certified Ethical Hacker (CEH)
    GitHub: github.com/Kezdjaggs

{'='*60}
"""
    return report

def save_report(target, report):
    """Save report to a file"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{target}_{timestamp}.txt"
    
    # Clean filename for invalid characters
    filename = filename.replace('/', '_').replace(':', '_')
    
    try:
        with open(filename, 'w') as f:
            f.write(report)
        print(f"{Colors.GREEN}[+] Report saved to: {filename}{Colors.RESET}")
        return filename
    except Exception as e:
        print(f"{Colors.RED}[-] Error saving report: {e}{Colors.RESET}")
        return None

def main():
    """Main function"""
    print_banner()
    
    # Check if target was provided as command line argument
    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}Usage: python3 network_recon.py <target> [quick|full]{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python3 network_recon.py 192.168.1.1 quick{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python3 network_recon.py google.com full{Colors.RESET}")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Validate target
    if not validate_target(target):
        print(f"{Colors.RED}[-] Invalid target format: {target}{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Please enter a valid IP address or domain name{Colors.RESET}")
        sys.exit(1)
    
    # Determine scan type
    scan_type = "quick"
    if len(sys.argv) > 2 and sys.argv[2].lower() == "full":
        scan_type = "full"
    
    print(f"{Colors.BOLD}🎯 Target: {target}{Colors.RESET}")
    print(f"{Colors.BOLD}📊 Scan Type: {scan_type.upper()}{Colors.RESET}")
    
    # Confirm before scanning
    print(f"{Colors.YELLOW}\n[!] WARNING: Ensure you have permission to scan this target!{Colors.RESET}")
    confirm = input(f"{Colors.YELLOW}[?] Proceed with scan? (y/n): {Colors.RESET}")
    
    if confirm.lower() != 'y':
        print(f"{Colors.RED}[-] Scan aborted by user{Colors.RESET}")
        sys.exit(0)
    
    # Run the scan
    scan_output = run_nmap_scan(target, scan_type)
    
    if scan_output:
        # Parse the results
        parsed_results = parse_nmap_output(scan_output)
        
        # Generate report
        report = generate_report(target, scan_output, parsed_results, scan_type)
        
        # Print report to screen
        print(report)
        
        # Save report to file
        save_report(target, report)
        
        print(f"{Colors.GREEN}{Colors.BOLD}✅ Scan completed successfully!{Colors.RESET}")
    else:
        print(f"{Colors.RED}❌ Scan failed. Please check your network connection and target.{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
