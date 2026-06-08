"""
Utility Functions for WexAAF
"""

import os
import json
import time
from datetime import datetime


class Colors:
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_PURPLE = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    PURPLE = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BG_GREEN = '\033[42m'
    BG_RED = '\033[41m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'


def print_banner():
    """Print WexAAF banner"""
    banner = f"""
{Colors.BRIGHT_CYAN}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║                    {Colors.BRIGHT_WHITE}WexAAF v1.0{Colors.BRIGHT_CYAN}                                ║
║            {Colors.BRIGHT_WHITE}AI Powered Web Penetration Testing Tool{Colors.BRIGHT_CYAN}            ║
║                   {Colors.BRIGHT_GREEN}Ethical Security Only{Colors.BRIGHT_CYAN}                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
    print(banner)


def print_disclaimer():
    """Print legal disclaimer"""
    disclaimer = f"""
{Colors.BRIGHT_RED}╔═══════════════════════════════════════════════════════════════════╗
║                      ⚠️  LEGAL DISCLAIMER ⚠️                     ║
╚═══════════════════════════════════════════════════════════════════╝{Colors.RED}

WexAAF is created SOLELY for educational and ethical security testing 
purposes. By using this tool, you agree to:

{Colors.GREEN}✓{Colors.RED} Only test websites you OWN or have EXPLICIT WRITTEN permission to test
{Colors.GREEN}✓{Colors.RED} Never use WexAAF for malicious purposes or unauthorized access
{Colors.GREEN}✓{Colors.RED} Always comply with local, state, and federal laws
{Colors.GREEN}✓{Colors.RED} Test on your own server first before any deployment
{Colors.GREEN}✓{Colors.RED} Use this tool responsibly and ethically

{Colors.BRIGHT_RED}DISCLAIMER:{Colors.RESET}
{Colors.WHITE}The developers and contributors of WexAAF are NOT responsible for:{Colors.RED}
{Colors.WHITE}• Any misuse of this tool{Colors.RED}
{Colors.WHITE}• Any damage caused to systems{Colors.RED}
{Colors.WHITE}• Any legal consequences arising from misuse{Colors.RED}
{Colors.WHITE}• Any unauthorized access or data breaches

{Colors.BRIGHT_YELLOW}
TRY IT ON YOUR OWN SERVER AND WE ARE NOT RESPONSIBLE FOR WRONG USE!
WE WILL MAKE THIS TOOL ONLY ETHICAL AND EDUCATIONAL PURPOSED.

For authorized security testing, always obtain proper authorization first.
{Colors.RESET}
"""
    print(disclaimer)
    time.sleep(2)


def save_results(results, filename):
    """
    Save scan results to file
    
    Args:
        results (dict): Scan results dictionary
        filename (str): Output filename
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("WexAAF Security Scan Report\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Target URL: {results.get('target', 'Unknown')}\n")
            f.write(f"Scan Time: {results.get('timestamp', 'Unknown')}\n")
            f.write("=" * 80 + "\n\n")
            
            # Write all scan results
            for section, data in results.get('scan_results', {}).items():
                f.write(f"\n[{section.upper()}]\n")
                f.write("-" * 80 + "\n")
                
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, list):
                            if value:
                                f.write(f"{key}:\n")
                                for item in value:
                                    f.write(f"  - {item}\n")
                        else:
                            f.write(f"{key}: {value}\n")
                elif isinstance(data, list):
                    if data:
                        for item in data:
                            f.write(f"  - {item}\n")
                else:
                    f.write(f"{data}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
            
        return True
    except Exception as e:
        print(f"{Colors.RED}[✗] Error saving results: {str(e)}{Colors.RESET}")
        return False


def format_timestamp():
    """Get formatted current timestamp"""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def validate_url(url):
    """
    Validate URL format
    
    Args:
        url (str): URL to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    if not url:
        return False
    
    if not url.startswith(('http://', 'https://')):
        return False
    
    # Check for basic domain format
    if '//' not in url or '.' not in url.split('//')[-1]:
        return False
    
    return True


def get_random_user_agent():
    """Get a random user agent string"""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
    ]
    return user_agents[int(time.time()) % len(user_agents)]


def sanitize_output(text):
    """
    Sanitize output to prevent injection in reports
    
    Args:
        text (str): Text to sanitize
    
    Returns:
        str: Sanitized text
    """
    if not isinstance(text, str):
        return str(text)
    
    # Remove potentially dangerous characters
    dangerous_chars = ['\x00', '\r', '\n', '\t']
    for char in dangerous_chars:
        text = text.replace(char, ' ')
    
    return text.strip()


def calculate_risk_score(vulnerabilities):
    """
    Calculate overall risk score based on found vulnerabilities
    
    Args:
        vulnerabilities (dict): Dictionary of found vulnerabilities
    
    Returns:
        str: Risk level (Low, Medium, High, Critical)
    """
    if not vulnerabilities:
        return "Low"
    
    score = 0
    
    # SQLInjection = Critical
    if vulnerabilities.get('sql_injection', {}).get('vulnerable_params'):
        score += 40
    
    # XSS = High
    if vulnerabilities.get('xss_scan', {}).get('vulnerabilities'):
        score += 30
    
    # WAF detected = Medium
    if vulnerabilities.get('waf_detection', {}).get('detected'):
        score += 10
    
    # Missing security headers = Medium
    security_headers = vulnerabilities.get('security_headers', {})
    if isinstance(security_headers, dict):
        missing_headers = sum(1 for v in security_headers.values() if not v)
        score += min(missing_headers * 5, 20)
    
    if score >= 70:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 30:
        return "Medium"
    else:
        return "Low"