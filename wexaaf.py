#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║                    WexAAF v1.0                                ║
║            AI Powered Web Penetration Testing Tool            ║
║                   Ethical Security Only                       ║
╚═══════════════════════════════════════════════════════════════╝

⚠️  IMPORTANT LEGAL DISCLAIMER ⚠️
=====================================
WexAAF is created SOLELY for educational and ethical security testing purposes.

By using this tool, you agree to:
✓ Only test websites you OWN or have EXPLICIT WRITTEN permission to test
✓ Never use WexAAF for malicious purposes or unauthorized access
✓ Always comply with local, state, and federal laws
✓ Test on your own server first before any deployment
✓ Use this tool responsibly and ethically

⚠️  DISCLAIMER: ⚠️
The developers and contributors of WexAAF are NOT responsible for:
- Any misuse of this tool
- Any damage caused to systems
- Any legal consequences arising from misuse
- Any unauthorized access or data breaches

TRY IT ON YOUR OWN SERVER AND WE ARE NOT RESPONSIBLE FOR WRONG USE!
WE WILL MAKE THIS TOOL ONLY ETHICAL AND EDUCATIONAL PURPOSED.

For authorized security testing, always obtain proper authorization first.

===============================================================
            Ready for Ethical Security Testing
===============================================================
"""

import sys
import os
import argparse
import time
from modules.http_handler import HTTPHandler
from modules.waf_detector import WAFDetector
from modules.sql_injector import SQLInjector
from modules.xss_scanner import XSSScanner
from modules.url_bruteforce import URLBruteforcer
from modules.ai_analyzer import AIAnalyzer
from modules.data_dumper import DataDumper
from modules.utils import Colors, print_banner, print_disclaimer, save_results

class WexAAF:
    def __init__(self, target_url):
        """
        Initialize WexAAF with target URL
        
        Args:
            target_url (str): Target website URL for security testing
        """
        self.target_url = target_url
        self.results = {
            'target': target_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'scan_results': {}
        }
        
        # Initialize modules
        self.http_handler = HTTPHandler(target_url)
        self.waf_detector = WAFDetector(self.http_handler)
        self.sql_injector = SQLInjector(self.http_handler)
        self.xss_scanner = XSSScanner(self.http_handler)
        self.url_bruteforcer = URLBruteforcer(self.http_handler)
        self.ai_analyzer = AIAnalyzer()
        self.data_dumper = DataDumper(self.http_handler)
        
        print(f"\n{Colors.BRIGHT_CYAN}[*] Target initialized: {target_url}{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}[*] Modules loaded successfully{Colors.RESET}\n")
    
    def run_security_scan(self, options):
        """
        Run comprehensive security scan based on options
        
        Args:
            options (dict): Scan options and flags
        """
        print(f"{Colors.BRIGHT_YELLOW}═══════════════════════════════════════════════════════════════{Colors.RESET}")
        print(f"{Colors.BRIGHT_GREEN}          🛡️  Starting WexAAF Security Scan  🛡️                   {Colors.RESET}")
        print(f"{Colors.BRIGHT_YELLOW}═══════════════════════════════════════════════════════════════{Colors.RESET}\n")
        
        # 1. Basic Website Analysis
        if options.get('basic', True):
            self._run_basic_analysis()
        
        # 2. WAF Detection
        if options.get('waf', True):
            self._run_waf_detection()
        
        # 3. SQL Injection Check
        if options.get('sql', True):
            self._run_sql_injection_test()
        
        # 4. XSS Vulnerability Scan
        if options.get('xss', True):
            self._run_xss_scan()
        
        # 5. URL Bruteforce
        if options.get('brute', True):
            self._run_url_bruteforce()
        
        # 6. AI Analysis
        if options.get('ai', True):
            self._run_ai_analysis()
        
        # Save results
        if options.get('output', True):
            self._save_scan_results()
        
        print(f"\n{Colors.BRIGHT_YELLOW}═══════════════════════════════════════════════════════════════{Colors.RESET}")
        print(f"{Colors.BRIGHT_GREEN}          🎉 Scan Completed Successfully! 🎉                         {Colors.RESET}")
        print(f"{Colors.BRIGHT_YELLOW}═══════════════════════════════════════════════════════════════{Colors.RESET}\n")
        
        # Final disclaimer reminder
        print(f"{Colors.BRIGHT_RED}{'='*70}{Colors.RESET}")
        print(f"{Colors.BRIGHT_RED}REMEMBER: This tool is for EDUCATIONAL PURPOSES ONLY!{Colors.RESET}")
        print(f"{Colors.BRIGHT_RED}TRY IT ON YOUR OWN SERVER - WE ARE NOT RESPONSIBLE FOR MISUSE{Colors.RESET}")
        print(f"{Colors.BRIGHT_RED}{'='*70}{Colors.RESET}\n")
    
    def _run_basic_analysis(self):
        """Run basic website security analysis"""
        print(f"\n{Colors.BRIGHT_CYAN}[+] Running Basic Security Analysis...{Colors.RESET}")
        print(f"{Colors.CYAN}{'─'*70}{Colors.RESET}")
        
        try:
            # Get server information
            server_info = self.http_handler.get_server_info()
            self.results['scan_results']['basic_analysis'] = server_info
            
            print(f"{Colors.GREEN}[✓] Server: {server_info.get('server', 'Unknown')}{Colors.RESET}")
            print(f"{Colors.GREEN}[✓] Status Code: {server_info.get('status_code', 'Unknown')}{Colors.RESET}")
            print(f"{Colors.GREEN}[✓] Response Time: {server_info.get('response_time', 'Unknown')}s{Colors.RESET}")
            print(f"{Colors.GREEN}[✓] Content-Length: {server_info.get('content_length', 'Unknown')} bytes{Colors.RESET}")
            
            # Check security headers
            security_headers = self.http_handler.check_security_headers()
            self.results['scan_results']['security_headers'] = security_headers
            
            print(f"\n{Colors.YELLOW}[i] Security Headers Analysis:{Colors.RESET}")
            for header, present in security_headers.items():
                status = Colors.GREEN + "[✓]" if present else Colors.RED + "[✗]"
                print(f"{status} {header}: {Colors.CYAN}{present if present else 'Missing'}{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[✗] Error in basic analysis: {str(e)}{Colors.RESET}")
            self.results['scan_results']['basic_analysis'] = {'error': str(e)}
    
    def _run_waf_detection(self):
        """Run WAF detection and bypass analysis"""
        print(f"\n{Colors.BRIGHT_CYAN}[+] Running WAF Detection...{Colors.RESET}")
        print(f"{Colors.CYAN}{'─'*70}{Colors.RESET}")
        
        try:
            waf_result = self.waf_detector.detect_waf()
            self.results['scan_results']['waf_detection'] = waf_result
            
            if waf_result['detected']:
                print(f"{Colors.RED}[!] WAF Detected: {Colors.YELLOW}{waf_result['waf_name']}{Colors.RESET}")
                print(f"{Colors.CYAN}    Signature matched: {waf_result['signature']}{Colors.RESET}")
                
                # Check bypass techniques
                print(f"\n{Colors.YELLOW}[i] Testing WAF Bypass Techniques...{Colors.RESET}")
                bypass_results = self.waf_detector.check_bypass_techniques()
                self.results['scan_results']['waf_bypass'] = bypass_results
                
                for technique, success in bypass_results.items():
                    status = Colors.GREEN + "[✓]" if success else Colors.RED + "[✗]"
                    print(f"{status} {technique}: {Colors.CYAN}{'Potentially bypassable' if success else 'Blocked'}{Colors.RESET}")
            else:
                print(f"{Colors.GREEN}[✓] No WAF detected{Colors.RESET}")
                self.results['scan_results']['waf_bypass'] = {}
                
        except Exception as e:
            print(f"{Colors.RED}[✗] Error in WAF detection: {str(e)}{Colors.RESET}")
            self.results['scan_results']['waf_detection'] = {'error': str(e)}
    
    def _run_sql_injection_test(self):
        """Run SQL injection vulnerability checks"""
        print(f"\n{Colors.BRIGHT_CYAN}[+] Running SQL Injection Tests...{Colors.RESET}")
        print(f"{Colors.CYAN}{'─'*70}{Colors.RESET}")
        
        try:
            # Find injectable parameters
            print(f"{Colors.YELLOW}[i] Finding injectable parameters...{Colors.RESET}")
            injectable_params = self.sql_injector.find_injectable_params()
            self.results['scan_results']['sql_injection'] = injectable_params
            
            if injectable_params['vulnerable_params']:
                print(f"{Colors.RED}[!] Vulnerable Parameters Found:{Colors.RESET}")
                for param in injectable_params['vulnerable_params']:
                    print(f"{Colors.RED}    - {param}{Colors.RESET}")
                
                # Column detection
                print(f"\n{Colors.YELLOW}[i] Detecting number of columns...{Colors.RESET}")
                columns = self.sql_injector.find_columns(injectable_params['vulnerable_params'])
                self.results['scan_results']['columns'] = columns
                
                if columns['column_count']:
                    print(f"{Colors.GREEN}[✓] Columns detected: {Colors.YELLOW}{columns['column_count']}{Colors.RESET}")
                    print(f"{Colors.GREEN}[✓] Method used: {columns['method']}{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[~] Could not determine column count{Colors.RESET}")
                
                # Database enumeration
                print(f"\n{Colors.YELLOW}[i] Attempting database enumeration...{Colors.RESET}")
                db_info = self.sql_injector.find_database_info(injectable_params['vulnerable_params'], columns.get('column_count', 0))
                self.results['scan_results']['database_info'] = db_info
                
                if db_info.get('database_name'):
                    print(f"{Colors.GREEN}[✓] Database found: {Colors.YELLOW}{db_info['database_name']}{Colors.RESET}")
                    print(f"{Colors.GREEN}[✓] Database version: {Colors.YELLOW}{db_info.get('version', 'Unknown')}{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[~] Could not enumerate database{Colors.RESET}")
                
            else:
                print(f"{Colors.GREEN}[✓] No SQL injection vulnerabilities detected{Colors.RESET}")
                self.results['scan_results']['columns'] = {}
                self.results['scan_results']['database_info'] = {}
                
        except Exception as e:
            print(f"{Colors.RED}[✗] Error in SQL injection test: {str(e)}{Colors.RESET}")
            self.results['scan_results']['sql_injection'] = {'error': str(e)}
    
    def _run_xss_scan(self):
        """Run XSS vulnerability scanner"""
        print(f"\n{Colors.BRIGHT_CYAN}[+] Running XSS Vulnerability Scan...{Colors.RESET}")
        print(f"{Colors.CYAN}{'─'*70}{Colors.RESET}")
        
        try:
            xss_results = self.xss_scanner.scan_xss()
            self.results['scan_results']['xss_scan'] = xss_results
            
            if xss_results['vulnerabilities']:
                print(f"{Colors.RED}[!] XSS Vulnerabilities Found:{Colors.RESET}")
                for vuln in xss_results['vulnerabilities']:
                    print(f"{Colors.RED}    - Type: {vuln['type']}{Colors.RESET}")
                    print(f"{Colors.CYAN}      Payload: {vuln['payload'][:50]}...{Colors.RESET}")
                    print(f"{Colors.CYAN}      Location: {vuln.get('location', 'Unknown')}{Colors.RESET}")
            else:
                print(f"{Colors.GREEN}[✓] No XSS vulnerabilities detected{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.RED}[✗] Error in XSS scan: {str(e)}{Colors.RESET}")
            self.results['scan_results']['xss_scan'] = {'error': str(e)}
    
    def _run_url_bruteforce(self):
        """Run URL bruteforce for hidden paths"""
        print(f"\n{Colors.BRIGHT_CYAN}[+] Running URL Bruteforce...{Colors.RESET}")
        print(f"{Colors.CYAN}{'─'*70}{Colors.RESET}")
        
        try:
            print(f"{Colors.YELLOW}[i] Discovering hidden paths and permuted URLs...{Colors.RESET}")
            url_results = self.url_bruteforcer.discover_urls()
            self.results['scan_results']['url_discovery'] = url_results
            
            if url_results['found_urls']:
                print(f"{Colors.GREEN}[✓] Found {Colors.YELLOW}{len(url_results['found_urls'])}{Colors.GREEN} URLs:{Colors.RESET}")
                for url in url_results['found_urls'][:20]:  # Show first 20
                    print(f"{Colors.CYAN}    - {url}{Colors.RESET}")
                if len(url_results['found_urls']) > 20:
                    print(f"{Colors.CYAN}    ... and {len(url_results['found_urls']) - 20} more{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[~] No additional URLs found{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.RED}[✗] Error in URL bruteforce: {str(e)}{Colors.RESET}")
            self.results['scan_results']['url_discovery'] = {'error': str(e)}
    
    def _run_ai_analysis(self):
        """Run AI-powered vulnerability analysis"""
        print(f"\n{Colors.BRIGHT_CYAN}[+] Running AI-Powered Analysis...{Colors.RESET}")
        print(f"{Colors.CYAN}{'─'*70}{Colors.RESET}")
        
        try:
            ai_results = self.ai_analyzer.analyze_vulnerabilities(self.results)
            self.results['scan_results']['ai_analysis'] = ai_results
            
            print(f"{Colors.GREEN}[✓] AI Analysis Complete{Colors.RESET}")
            print(f"{Colors.CYAN}    Overall Risk Level: {Colors.YELLOW}{ai_results['overall_risk']}{Colors.RESET}")
            print(f"{Colors.CYAN}    Vulnerability Count: {Colors.YELLOW}{ai_results['vulnerability_count']}{Colors.RESET}")
            
            print(f"\n{Colors.YELLOW}[i] AI Recommendations:{Colors.RESET}")
            for i, recommendation in enumerate(ai_results['recommendations'], 1):
                print(f"{Colors.CYAN}    {i}. {recommendation}{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.RED}[✗] Error in AI analysis: {str(e)}{Colors.RESET}")
            self.results['scan_results']['ai_analysis'] = {'error': str(e)}
    
    def _save_scan_results(self):
        """Save scan results to file"""
        try:
            if not os.path.exists('output'):
                os.makedirs('output')
            
            filename = f"output/scan_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            save_results(self.results, filename)
            print(f"\n{Colors.GREEN}[✓] Results saved to: {Colors.YELLOW}{filename}{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[✗] Error saving results: {str(e)}{Colors.RESET}")


def main():
    """Main entry point for WexAAF"""
    # Print banner and disclaimer
    print_banner()
    print_disclaimer()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='WexAAF - AI Powered Web Penetration Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python wexaaf.py -u https://example.com                 # Full scan
  python wexaaf.py -u https://example.com --sql-only      # SQL injection only
  python wexaaf.py -u https://example.com --no-waf        # Skip WAF detection
  python wexaaf.py -u https://example.com --no-output     # Skip saving results

For more information, visit: https://github.com/wexaaf
        '''
    )
    
    parser.add_argument('-u', '--url', required=True, 
                       help='Target URL for security testing')
    parser.add_argument('--basic', action='store_true', default=True,
                       help='Run basic security analysis (default: true)')
    parser.add_argument('--waf', action='store_true', default=True,
                       help='Run WAF detection (default: true)')
    parser.add_argument('--sql', action='store_true', default=True,
                       help='Run SQL injection tests (default: true)')
    parser.add_argument('--xss', action='store_true', default=True,
                       help='Run XSS vulnerability scan (default: true)')
    parser.add_argument('--brute', action='store_true', default=True,
                       help='Run URL bruteforce (default: true)')
    parser.add_argument('--ai', action='store_true', default=True,
                       help='Run AI analysis (default: true)')
    parser.add_argument('--sql-only', action='store_true',
                       help='Run only SQL injection tests')
    parser.add_argument('--xss-only', action='store_true',
                       help='Run only XSS vulnerability scan')
    parser.add_argument('--no-waf', action='store_true',
                       help='Skip WAF detection')
    parser.add_argument('--no-output', action='store_true',
                       help='Skip saving results to file')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Colors.RED}[✗] Error: URL must start with http:// or https://{Colors.RESET}")
        sys.exit(1)
    
    # Build options dictionary
    options = {
        'basic': args.basic,
        'waf': args.waf and not args.no_waf,
        'sql': args.sql,
        'xss': args.xss,
        'brute': args.brute,
        'ai': args.ai,
        'output': not args.no_output
    }
    
    # Handle exclusive modes
    if args.sql_only:
        options = {'sql': True, 'output': not args.no_output}
    elif args.xss_only:
        options = {'xss': True, 'output': not args.no_output}
    
    # Confirm with user
    print(f"{Colors.YELLOW}[!] This tool is for EDUCATIONAL PURPOSES ONLY!{Colors.RESET}")
    print(f"{Colors.Y}    You must own or have permission to test: {args.url}{Colors.RESET}")
    print(f"{Colors.YELLOW}[?] Do you want to proceed? (yes/no): {Colors.RESET}", end='')
    
    try:
        confirm = input().lower()
        if confirm not in ['yes', 'y']:
            print(f"{Colors.YELLOW}[i] Scan aborted by user.{Colors.RESET}")
            sys.exit(0)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[i] Scan aborted by user.{Colors.RESET}")
        sys.exit(0)
    
    # Initialize and run WexAAF
    try:
        wexaaf = WexAAF(args.url)
        wexaaf.run_security_scan(options)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[i] Scan interrupted by user.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[✗] Fatal error: {str(e)}{Colors.RESET}")
        sys.exit(1)


if __name__ == '__main__':
    main()