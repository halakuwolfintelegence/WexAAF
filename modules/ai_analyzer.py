"""
AI Analyzer Module for WexAAF
Provides AI-powered vulnerability analysis and recommendations
"""

import re
from .utils import Colors, calculate_risk_score


class AIAnalyzer:
    """
    AI-Powered Security Analyzer class
    """
    
    # Vulnerability severity scoring
    SEVERITY_SCORES = {
        'Critical': 10,
        'High': 7,
        'Medium': 4,
        'Low': 1
    }
    
    # Vulnerability patterns for AI analysis
    VULNERABILITY_PATTERNS = {
        'SQL Injection': {
            'indicators': ['sql_injection', 'UNION SELECT', 'AND/OR', 'SLEEP', 'BENCHMARK'],
            'severity': 'Critical',
            'impact': 'Data breach, data manipulation, unauthorized access',
            'remediation': 'Use parameterized queries, input validation, ORM frameworks'
        },
        'XSS': {
            'indicators': ['xss_scan', '<script>', 'onerror', 'onload', 'javascript:'],
            'severity': 'High',
            'impact': 'Session hijacking, data theft, phishing',
            'remediation': 'Output encoding, CSP, input sanitization, HttpOnly cookies'
        },
        'WAF': {
            'indicators': ['waf_detection', 'cloudflare', 'fortinet', 'akamai'],
            'severity': 'Medium',
            'impact': 'Filter evasion required, potential blocking',
            'remediation': 'Implement proper WAF rules, regular updates'
        },
        'Missing Security Headers': {
            'indicators': ['security_headers', 'X-Frame-Options', 'CSP'],
            'severity': 'Medium',
            'impact': 'Clickjacking, XSS vulnerabilities, data leakage',
            'remediation': 'Implement all security headers, use CSP'
        },
        'Information Disclosure': {
            'indicators': ['server_info', 'powered_by', 'technology'],
            'severity': 'Low',
            'impact': 'Passive reconnaissance, targeted attacks',
            'remediation': 'Hide server versions, minimal error messages'
        },
        'Backup/Config Files': {
            'indicators': ['backup', 'config', '.env', 'database.sql'],
            'severity': 'Critical',
            'impact': 'Credential exposure, source code disclosure',
            'remediation': 'Remove backup files, use version control properly'
        }
    }
    
    def __init__(self):
        """Initialize AI Analyzer"""
        self.analysis_history = []
        
    def analyze_vulnerabilities(self, scan_results):
        """
        Analyze vulnerabilities and provide AI-powered insights
        
        Args:
            scan_results (dict): Complete scan results
        
        Returns:
            dict: AI analysis results
        """
        print(f"{Colors.CYAN}[i] Running AI vulnerability analysis...{Colors.RESET}")
        
        analysis = {
            'overall_risk': 'Low',
            'vulnerability_count': 0,
            'risk_score': 0,
            'detected_vulnerabilities': [],
            'recommendations': [],
            'priority_fixes': [],
            'security_score': 100,
            'attack_surface': self._calculate_attack_surface(scan_results)
        }
        
        # Analyze each scan section
        all_results = scan_results.get('scan_results', {})
        
        # SQL Injection Analysis
        if 'sql_injection' in all_results:
            vuln = self._analyze_sql_injection(all_results['sql_injection'])
            if vuln:
                analysis['detected_vulnerabilities'].append(vuln)
        
        # XSS Analysis
        if 'xss_scan' in all_results:
            vuln = self._analyze_xss(all_results['xss_scan'])
            if vuln:
                analysis['detected_vulnerabilities'].append(vuln)
        
        # WAF Analysis
        if 'waf_detection' in all_results:
            vuln = self._analyze_waf(all_results['waf_detection'])
            if vuln:
                analysis['detected_vulnerabilities'].append(vuln)
        
        # Security Headers Analysis
        if 'security_headers' in all_results:
            vuln = self._analyze_security_headers(all_results['security_headers'])
            if vuln:
                analysis['detected_vulnerabilities'].append(vuln)
        
        # URL Discovery Analysis
        if 'url_discovery' in all_results:
            vuln = self._analyze_url_discovery(all_results['url_discovery'])
            if vuln:
                analysis['detected_vulnerabilities'].append(vuln)
        
        # Basic Information Disclosure
        if 'basic_analysis' in all_results:
            vuln = self._analyze_info_disclosure(all_results['basic_analysis'])
            if vuln:
                analysis['detected_vulnerabilities'].append(vuln)
        
        # Calculate metrics
        analysis['vulnerability_count'] = len(analysis['detected_vulnerabilities'])
        analysis['risk_score'] = self._calculate_risk_score(analysis['detected_vulnerabilities'])
        analysis['overall_risk'] = self._determine_risk_level(analysis['risk_score'])
        analysis['security_score'] = max(0, 100 - analysis['risk_score'])
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis['detected_vulnerabilities'])
        
        # Identify priority fixes
        analysis['priority_fixes'] = self._prioritize_fixes(analysis['detected_vulnerabilities'])
        
        # Store analysis in history
        self.analysis_history.append(analysis)
        
        return analysis
    
    def _analyze_sql_injection(self, sql_results):
        """Analyze SQL injection vulnerabilities"""
        vuln_params = sql_results.get('vulnerable_params', [])
        
        if not vuln_params:
            return None
        
        severity = 'Critical' if vuln_params else 'Low'
        
        return {
            'type': 'SQL Injection',
            'severity': severity,
            'affected_params': vuln_params,
            'database_type': sql_results.get('database_type', 'Unknown'),
            'count': len(vuln_params),
            'description': 'SQL injection vulnerabilities detected in URL parameters',
            'impact': 'Critical - Can lead to data breach, data manipulation, and complete database compromise',
            'remediation': [
                'Use parameterized queries or prepared statements',
                'Implement input validation and sanitization',
                'Use ORM frameworks with built-in SQL injection protection',
                'Apply principle of least privilege for database accounts',
                'Implement Web Application Firewall (WAF)'
            ]
        }
    
    def _analyze_xss(self, xss_results):
        """Analyze XSS vulnerabilities"""
        vulnerabilities = xss_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return None
        
        # Determine severity based on type and count
        severity = 'High'
        for vuln in vulnerabilities:
            if vuln.get('alert_triggered'):
                severity = 'Critical'
                break
        
        return {
            'type': 'Cross-Site Scripting (XSS)',
            'severity': severity,
            'count': len(vulnerabilities),
            'types': list(set(v.get('type', 'Unknown') for v in vulnerabilities)),
            'methods': list(set(v.get('method', 'Unknown') for v in vulnerabilities)),
            'description': f'{len(vulnerabilities)} XSS vulnerability(ies) detected',
            'impact': f'{severity} - Can lead to session hijacking, credential theft, and phishing attacks',
            'remediation': [
                'Implement proper output encoding (HTML, JavaScript, URL)',
                'Use Content Security Policy (CSP)',
                'Validate and sanitize all user inputs',
                'Set HttpOnly and Secure flags on cookies',
                'Use frameworks with built-in XSS protection',
                'Implement X-XSS-Protection header'
            ]
        }
    
    def _analyze_waf(self, waf_results):
        """Analyze WAF status"""
        detected = waf_results.get('detected', False)
        
        if not detected:
            return {
                'type': 'Missing WAF Protection',
                'severity': 'Medium',
                'description': 'No Web Application Firewall detected',
                'impact': 'Medium - Increased vulnerability to common attacks',
                'remediation': [
                    'Implement a Web Application Firewall',
                    'Configure WAF rules for your application',
                    'Regularly update WAF signatures',
                    'Monitor WAF logs for suspicious activity'
                ]
            }
        
        return {
            'type': 'WAF Detected',
            'severity': 'Low',
            'waf_name': waf_results.get('waf_name', 'Unknown'),
            'description': f'WAF detected: {waf_results.get("waf_name", "Unknown")}',
            'impact': 'Low - WAF provides some protection but bypass techniques may still work',
            'remediation': [
                'Ensure WAF is properly configured',
                'Regularly test WAF bypass scenarios',
                'Keep WAF signatures updated',
                'Complement WAF with secure coding practices'
            ]
        }
    
    def _analyze_security_headers(self, headers):
        """Analyze security headers"""
        missing_headers = [h for h, present in headers.items() if not present]
        
        if not missing_headers or len(missing_headers) < 2:
            return None
        
        return {
            'type': 'Missing Security Headers',
            'severity': 'Medium',
            'missing_headers': missing_headers,
            'count': len(missing_headers),
            'description': f'{len(missing_headers)} security header(s) are missing',
            'impact': 'Medium - Increased vulnerability to clickjacking, XSS, and other attacks',
            'remediation': [
                'Implement X-Frame-Options header',
                'Set X-Content-Type-Options: nosniff',
                'Configure X-XSS-Protection',
                'Implement Content Security Policy (CSP)',
                'Set Strict-Transport-Security (HTTPS)',
                'Configure Referrer-Policy',
                'Add Permissions-Policy header'
            ]
        }
    
    def _analyze_url_discovery(self, url_results):
        """Analyze discovered URLs and paths"""
        found_urls = url_results.get('found_urls', [])
        
        if not found_urls:
            return None
        
        # Check for sensitive paths
        sensitive_patterns = ['admin', 'backup', 'config', 'sql', 'env', 'git']
        sensitive_urls = [url for url in found_urls 
                         if any(pattern in url.lower() for pattern in sensitive_patterns)]
        
        severity = 'Critical' if len(sensitive_urls) > 0 else 'Low'
        
        return {
            'type': 'Exposed Sensitive Paths',
            'severity': severity,
            'total_urls': len(found_urls),
            'sensitive_urls': len(sensitive_urls),
            'description': f'{len(found_urls)} URLs discovered, {len(sensitive_urls)} appear sensitive',
            'impact': f'{severity} - Sensitive paths may expose critical information',
            'remediation': [
                'Restrict access to administrative paths',
                'Remove backup and configuration files',
                'Disable directory listing',
                'Implement proper authentication',
                'Use robots.txt and sitemap.xml carefully',
                'Monitor 404 errors for reconnaissance attempts'
            ]
        }
    
    def _analyze_info_disclosure(self, basic_analysis):
        """Analyze information disclosure"""
        server = basic_analysis.get('server', 'Unknown')
        tech_stack = basic_analysis.get('technology', [])
        
        if server == 'Unknown' and not tech_stack:
            return None
        
        vulns = []
        
        if server != 'Unknown' and 'nginx' not in server.lower():
            vulns.append('Server header disclosure')
        
        if basic_analysis.get('powered_by') and basic_analysis['powered_by'] != 'Not specified':
            vulns.append('X-Powered-By disclosure')
        
        if tech_stack and 'Unknown' not in tech_stack:
            vulns.append('Technology stack disclosure')
        
        if not vulns:
            return None
        
        return {
            'type': 'Information Disclosure',
            'severity': 'Low',
            'disclosures': vulns,
            'server': server,
            'technologies': tech_stack,
            'description': 'Server and technology information disclosed',
            'impact': 'Low - Aids passive reconnaissance and targeted attacks',
            'remediation': [
                'Hide server version information',
                'Remove X-Powered-By header',
                'Use generic error messages',
                'Minimize HTTP headers exposure',
                'Implement proper error handling'
            ]
        }
    
    def _calculate_attack_surface(self, scan_results):
        """Calculate attack surface score"""
        score = 0
        
        # SQL injection adds to attack surface
        if 'sql_injection' in scan_results.get('scan_results', {}):
            if scan_results['scan_results']['sql_injection'].get('vulnerable_params'):
                score += 30
        
        # XSS adds to attack surface
        if 'xss_scan' in scan_results.get('scan_results', {}):
            if scan_results['scan_results']['xss_scan'].get('vulnerabilities'):
                score += 25
        
        # Missing headers
        if 'security_headers' in scan_results.get('scan_results', {}):
            missing = sum(1 for v in scan_results['scan_results']['security_headers'].values() if not v)
            score += min(missing * 3, 15)
        
        # Found URLs
        if 'url_discovery' in scan_results.get('scan_results', {}):
            found = len(scan_results['scan_results']['url_discovery'].get('found_urls', []))
            score += min(found, 10)
        
        return min(score, 100)  # Cap at 100
    
    def _calculate_risk_score(self, vulnerabilities):
        """Calculate overall risk score from vulnerabilities"""
        total_score = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            base_score = self.SEVERITY_SCORES.get(severity, 1)
            
            # Multiply by count if applicable
            count = vuln.get('count', 1)
            total_score += base_score * min(count, 5)  # Cap multiplier at 5
        
        return min(total_score, 100)  # Cap at 100
    
    def _determine_risk_level(self, score):
        """Determine risk level from score"""
        if score >= 70:
            return 'Critical'
        elif score >= 50:
            return 'High'
        elif score >= 30:
            return 'Medium'
        else:
            return 'Low'
    
    def _generate_recommendations(self, vulnerabilities):
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Add general recommendations
        general_recs = [
            'Implement a comprehensive security policy',
            'Conduct regular security audits and penetration testing',
            'Keep all software and dependencies updated',
            'Implement proper logging and monitoring',
            'Use HTTPS for all communications',
            'Implement rate limiting',
            'Regular backup and disaster recovery procedures',
            'Train development team on secure coding practices'
        ]
        
        recommendations.extend(general_recs)
        
        # Add specific recommendations based on vulnerabilities
        for vuln in vulnerabilities:
            if 'remediation' in vuln:
                recommendations.extend(vuln['remediation'])
        
        # Remove duplicates and prioritize
        unique_recs = list(set(recommendations))
        
        # Sort by priority (Critical vulnerabilities' remediations first)
        critical_keywords = ['parameterized', 'output encoding', 'CSP', 'X-Frame-Options']
        prioritized_recs = []
        other_recs = []
        
        for rec in unique_recs:
            if any(keyword.lower() in rec.lower() for keyword in critical_keywords):
                prioritized_recs.append(rec)
            else:
                other_recs.append(rec)
        
        return prioritized_recs[:10] + other_recs[:10]
    
    def _prioritize_fixes(self, vulnerabilities):
        """Prioritize vulnerabilities for fixing"""
        prioritized = []
        
        # Sort by severity
        severity_order = ['Critical', 'High', 'Medium', 'Low']
        
        sorted_vulns = sorted(vulnerabilities, 
                           key=lambda x: severity_order.index(x.get('severity', 'Low')))
        
        for vuln in sorted_vulns:
            prioritized.append({
                'vulnerability': vuln.get('type', 'Unknown'),
                'severity': vuln.get('severity', 'Low'),
                'priority': self._calculate_priority(vuln),
                'details': vuln.get('description', ''),
                'fix_suggestions': vuln.get('remediation', [])[:3]
            })
        
        return prioritized
    
    def _calculate_priority(self, vulnerability):
        """Calculate priority level for a vulnerability"""
        severity = vulnerability.get('severity', 'Low')
        count = vulnerability.get('count', 1)
        
        if severity == 'Critical':
            return 1  # Highest priority
        elif severity == 'High':
            return 2
        elif severity == 'Medium':
            return 3
        else:
            return 4
    
    def generate_summary_report(self, analysis):
        """
        Generate a human-readable summary report
        
        Args:
            analysis (dict): AI analysis results
        
        Returns:
            str: Formatted summary report
        """
        report = f"""
{'='*70}
AI-POWERED SECURITY ANALYSIS SUMMARY
{'='*70}

OVERALL RISK LEVEL: {Colors.BRIGHT_RED if analysis['overall_risk'] == 'Critical' else Colors.YELLOW if analysis['overall_risk'] in ['High', 'Medium'] else Colors.GREEN}{analysis['overall_risk']}{Colors.RESET}
SECURITY SCORE: {analysis['security_score']}/100
ATTACK SURFACE: {analysis['attack_surface']}/100

VULNERABILITIES FOUND: {analysis['vulnerability_count']}

{Colors.BRIGHT_YELLOW}CRITICAL ISSUES (Fix Immediately){Colors.RESET}
{'-'*70}
"""
        # Add critical and high severity vulnerabilities
        for vuln in analysis['detected_vulnerabilities']:
            if vuln.get('severity') in ['Critical', 'High']:
                report += f"\n{Colors.BRIGHT_RED}[!] {vuln['type']}{Colors.RESET}\n"
                report += f"    Severity: {vuln['severity']}\n"
                report += f"    Impact: {vuln.get('impact', 'Unknown')}\n"
                report += f"    Details: {vuln.get('description', 'Unknown')}\n"
        
        report += f"\n{Colors.YELLOW}RECOMMENDATIONS{Colors.RESET}\n"
        report += f"{'-'*70}\n"
        
        for i, rec in enumerate(analysis['recommendations'][:15], 1):
            report += f"{i}. {rec}\n"
        
        report += f"\n{Colors.BRIGHT_YELLOW}PRIORITY FIXES{Colors.RESET}\n"
        report += f"{'-'*70}\n"
        
        for i, fix in enumerate(analysis['priority_fixes'][:10], 1):
            report += f"\n{Colors.CYAN}[{i}] {fix['vulnerability']} (Priority {fix['priority']}){Colors.RESET}\n"
            for suggestion in fix['fix_suggestions']:
                report += f"    - {suggestion}\n"
        
        report += f"\n{'='*70}\n"
        
        return report
    
    def get_trend_analysis(self):
        """
        Analyze trends across multiple scans
        
        Returns:
            dict: Trend analysis results
        """
        if len(self.analysis_history) < 2:
            return {
                'message': 'Need at least 2 scans for trend analysis',
                'trends': {}
            }
        
        latest = self.analysis_history[-1]
        previous = self.analysis_history[-2]
        
        trends = {
            'risk_score_change': latest['risk_score'] - previous['risk_score'],
            'vuln_count_change': latest['vulnerability_count'] - previous['vulnerability_count'],
            'security_score_change': latest['security_score'] - previous['security_score'],
            'new_vulnerabilities': [],
            'fixed_vulnerabilities': []
        }
        
        # Compare vulnerabilities
        latest_vuln_types = set(v['type'] for v in latest['detected_vulnerabilities'])
        previous_vuln_types = set(v['type'] for v in previous['detected_vulnerabilities'])
        
        trends['new_vulnerabilities'] = list(latest_vuln_types - previous_vuln_types)
        trends['fixed_vulnerabilities'] = list(previous_vuln_types - latest_vuln_types)
        
        return trends