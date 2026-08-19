#!/usr/bin/env python3
"""
Web Vulnerability Scanner
Author: Kehinde Jaggs | Certified Ethical Hacker (CEH)
Description: Basic web vulnerability scanner for penetration testing
Disclaimer: For authorized testing and educational purposes only
"""

import requests
import sys
import datetime
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    """Display tool banner"""
    banner = f"""
{Colors.PURPLE}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🌐 Web Vulnerability Scanner - CEH Edition 🌐           ║
║                                                              ║
║     Author: Kehinde Jaggs                                    ║
║     Certified Ethical Hacker (CEH)                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}
    """
    print(banner)

class WebVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.results = {}
        
    def check_robots_txt(self):
        """Check for robots.txt file"""
        print(f"{Colors.BLUE}[+] Checking robots.txt...{Colors.RESET}")
        try:
            response = self.session.get(f"{self.target_url}/robots.txt", timeout=5)
            if response.status_code == 200:
                print(f"{Colors.YELLOW}[!] robots.txt found!{Colors.RESET}")
                self.vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'description': 'robots.txt file exposes directory structure',
                    'details': response.text[:200] + '...' if len(response.text) > 200 else response.text,
                    'severity': 'Low'
                })
                return response.text
            else:
                print(f"{Colors.GREEN}[✓] robots.txt not found (good){Colors.RESET}")
                return None
        except:
            return None
    
    def check_sensitive_directories(self):
        """Check for sensitive directories"""
        print(f"{Colors.BLUE}[+] Checking for sensitive directories...{Colors.RESET}")
        
        directories = [
            'admin', 'login', 'wp-admin', 'administrator',
            'backup', 'backups', 'temp', 'tmp', 'logs',
            'config', 'conf', 'include', 'includes',
            'phpmyadmin', 'mysql', 'db', 'database',
            '.git', '.svn', '.env', '.aws'
        ]
        
        found_dirs = []
        for directory in directories:
            try:
                response = self.session.get(f"{self.target_url}/{directory}/", timeout=3)
                if response.status_code == 200:
                    print(f"{Colors.RED}[!] Found: /{directory}/ (HTTP 200){Colors.RESET}")
                    found_dirs.append(directory)
                    self.vulnerabilities.append({
                        'type': 'Sensitive Directory Exposure',
                        'description': f'Directory /{directory}/ is accessible',
                        'details': f'URL: {self.target_url}/{directory}/',
                        'severity': 'Medium'
                    })
                elif response.status_code == 403:
                    print(f"{Colors.YELLOW}[!] Found: /{directory}/ (HTTP 403 - Forbidden){Colors.RESET}")
                elif response.status_code == 401:
                    print(f"{Colors.YELLOW}[!] Found: /{directory}/ (HTTP 401 - Authentication Required){Colors.RESET}")
            except:
                pass
        
        if not found_dirs:
            print(f"{Colors.GREEN}[✓] No sensitive directories found{Colors.RESET}")
        
        return found_dirs

    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        print(f"{Colors.BLUE}[+] Testing for SQL injection...{Colors.RESET}")
        
        payloads = [
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1',
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
        ]
        
        # Find parameters in URLs (simple approach)
        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        if query_params:
            print(f"{Colors.YELLOW}[!] Found parameters: {list(query_params.keys())}{Colors.RESET}")
            
            for param in query_params.keys():
                for payload in payloads:
                    try:
                        # Create test URL
                        test_params = query_params.copy()
                        test_params[param] = [payload]
                        test_url = urllib.parse.urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urllib.parse.urlencode(test_params, doseq=True),
                            parsed.fragment
                        ))
                        
                        response = self.session.get(test_url, timeout=5)
                        
                        # Check for common SQL error patterns
                        sql_errors = [
                            'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
                            'you have an error in your SQL', 'Unclosed quotation mark',
                            'Microsoft OLE DB', 'SQL Server', 'syntax error'
                        ]
                        
                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                print(f"{Colors.RED}[!] SQL Injection possible in parameter: {param}{Colors.RESET}")
                                self.vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'description': f'Parameter {param} is vulnerable to SQL injection',
                                    'details': f'Payload: {payload}',
                                    'severity': 'Critical'
                                })
                                break
                    except:
                        pass
        else:
            print(f"{Colors.YELLOW}[!] No parameters found for SQL injection testing{Colors.RESET}")

    def test_xss(self):
        """Test for Cross-Site Scripting (XSS) vulnerabilities"""
        print(f"{Colors.BLUE}[+] Testing for XSS vulnerabilities...{Colors.RESET}")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "onmouseover=alert('XSS')",
            "';alert('XSS');//",
            "<svg onload=alert('XSS')>",
        ]
        
        # Find parameters in URLs
        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        if query_params:
            for param in query_params.keys():
                for payload in payloads:
                    try:
                        test_params = query_params.copy()
                        test_params[param] = [payload]
                        test_url = urllib.parse.urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urllib.parse.urlencode(test_params, doseq=True),
                            parsed.fragment
                        ))
                        
                        response = self.session.get(test_url, timeout=5)
                        
                        # Check if payload is reflected in response
                        if payload in response.text:
                            print(f"{Colors.RED}[!] XSS possible in parameter: {param}{Colors.RESET}")
                            self.vulnerabilities.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'description': f'Parameter {param} is vulnerable to XSS',
                                'details': f'Payload: {payload}',
                                'severity': 'High'
                            })
                            break
                    except:
                        pass
        else:
            print(f"{Colors.YELLOW}[!] No parameters found for XSS testing{Colors.RESET}")

    def check_security_headers(self):
        """Check security headers"""
        print(f"{Colors.BLUE}[+] Checking security headers...{Colors.RESET}")
        
        try:
            response = self.session.get(self.target_url, timeout=5)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS header missing',
                'X-Content-Type-Options': 'X-Content-Type-Options header missing',
                'X-Frame-Options': 'X-Frame-Options header missing',
                'X-XSS-Protection': 'X-XSS-Protection header missing',
                'Content-Security-Policy': 'Content-Security-Policy header missing',
                'Referrer-Policy': 'Referrer-Policy header missing'
            }
            
            missing_headers = []
            for header, message in security_headers.items():
                if header not in headers:
                    print(f"{Colors.YELLOW}[!] {message}{Colors.RESET}")
                    missing_headers.append(header)
                    self.vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'description': message,
                        'details': f'Header: {header}',
                        'severity': 'Medium'
                    })
            
            if not missing_headers:
                print(f"{Colors.GREEN}[✓] All security headers are present!{Colors.RESET}")
                
        except:
            print(f"{Colors.RED}[-] Could not retrieve headers{Colors.RESET}")

    def scan(self):
        """Run all scans"""
        print(f"{Colors.BOLD}\n🔍 Scanning target: {self.target_url}{Colors.RESET}\n")
        
        # Run all checks
        self.check_robots_txt()
        print()
        self.check_sensitive_directories()
        print()
        self.test_sql_injection()
        print()
        self.test_xss()
        print()
        self.check_security_headers()
        
        return self.vulnerabilities

    def generate_report(self):
        """Generate vulnerability report"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        severity_count = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            if severity in severity_count:
                severity_count[severity] += 1
        
        report = f"""
{'='*60}
🌐 WEB VULNERABILITY SCAN REPORT
{'='*60}

📋 Scan Information:
    Target: {self.target_url}
    Date/Time: {timestamp}
    Scanner: Kehinde Jaggs (CEH)

📈 Summary:
    Total Vulnerabilities Found: {len(self.vulnerabilities)}
    
    Severity Breakdown:
        Critical: {severity_count['Critical']}
        High: {severity_count['High']}
        Medium: {severity_count['Medium']}
        Low: {severity_count['Low']}

🔍 Detailed Findings:
"""
        
        if self.vulnerabilities:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report += f"""
    {i}. {vuln['type']} ({vuln['severity']})
       Description: {vuln['description']}
       Details: {vuln['details']}
"""
        else:
            report += f"""
    ✅ No vulnerabilities found!
    The target appears to be well-configured.
"""
        
        report += f"""
{'='*60}
⚠️  RECOMMENDATIONS:
    1. Fix all Critical and High severity issues immediately
    2. Review Medium severity issues in the next sprint
    3. Regular security scanning is recommended
    4. Consider implementing additional security controls

📝 Report Generated By:
    Kehinde Jaggs
    Certified Ethical Hacker (CEH)
    GitHub: github.com/Kezdjaggs

{'='*60}
"""
        return report

def main():
    """Main function"""
    print_banner()
    
    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}Usage: python3 web_vuln_scanner.py <target_url>{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python3 web_vuln_scanner.py https://example.com{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python3 web_vuln_scanner.py https://example.com?id=1{Colors.RESET}")
        print(f"\n{Colors.BLUE}Note: This is for EDUCATIONAL purposes only!{Colors.RESET}")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Validate URL
    if not target.startswith(('http://', 'https://')):
        print(f"{Colors.RED}[-] Invalid URL format. Include http:// or https://{Colors.RESET}")
        sys.exit(1)
    
    # Confirm before scanning
    print(f"{Colors.YELLOW}[!] WARNING: Ensure you have permission to scan this target!{Colors.RESET}")
    confirm = input(f"{Colors.YELLOW}[?] Proceed with scan? (y/n): {Colors.RESET}")
    
    if confirm.lower() != 'y':
        print(f"{Colors.RED}[-] Scan aborted by user{Colors.RESET}")
        sys.exit(0)
    
    # Run scan
    scanner = WebVulnerabilityScanner(target)
    vulnerabilities = scanner.scan()
    
    # Generate report
    report = scanner.generate_report()
    print(report)
    
    # Save report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"web_vuln_report_{timestamp}.txt"
    with open(report_file, 'w') as f:
        f.write(report)
    print(f"{Colors.GREEN}[+] Report saved to: {report_file}{Colors.RESET}")

if __name__ == "__main__":
    main()
