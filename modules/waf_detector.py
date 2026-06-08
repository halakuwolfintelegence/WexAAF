"""
WAF Detector Module for WexAAF
Detects Web Application Firewalls and tests bypass techniques
"""

import re
from .utils import Colors


class WAFDetector:
    """
    WAF Detection and Bypass Testing class
    """
    
    # WAF signatures database
    WAF_SIGNATURES = {
        'Cloudflare': [
            'cf-ray',
            'cloudflare',
            '__cfduid',
            'cf_clearance',
            'captcha',
            'challenge platform'
        ],
        'Fortinet': [
            'fortigate',
            'fortiweb',
            'firewall',
            'fortinet'
        ],
        'Akamai': [
            'akamai',
            'akamaighost',
            'akamai-origin'
        ],
        'F5 BIG-IP ASM': [
            'f5',
            'big-ip',
            'ts='
        ],
        'Barracuda': [
            'barracuda',
            'barracudanetworks'
        ],
        'ModSecurity': [
            'mod_security',
            'modsecurity',
            'mod_security: access denied',
            'not acceptable'
        ],
        'AWS WAF': [
            'aws-waf',
            'amazon',
            'aws'
        ],
        'Imperva': [
            'imperva',
            'incapsula',
            'visid_incap'
        ],
        'Sucuri': [
            'sucuri',
            'cloudproxy'
        ],
        'Wordfence': [
            'wordfence',
            'wf_logID'
        ],
        'Airlock': [
            'airlock',
            'alphalight'
        ],
        'Citrix NetScaler': [
            'citrix',
            'netscaler',
            'ns_af'
        ],
        'Radware': [
            'radware',
            'appwall'
        ],
        'Microsoft Azure': [
            'azure',
            'microsoft-antimalware'
        ],
        'Google Cloud Armor': [
            'gcp',
            'google cloud armor',
            'gcloud'
        ]
    }
    
    # Test payloads for WAF detection
    TEST_PAYLOADS = [
        '<script>alert(1)</script>',
        '1 UNION SELECT 1--',
        '../etc/passwd',
        'OR 1=1',
        '${jndi:ldap://}',
        '<svg onload=alert(1)>'
    ]
    
    def __init__(self, http_handler):
        """
        Initialize WAF Detector
        
        Args:
            http_handler: HTTPHandler instance
        """
        self.http_handler = http_handler
        self.detected_waf = None
        self.waf_signatures = self.WAF_SIGNATURES
    
    def detect_waf(self):
        """
        Detect WAF based on response analysis
        
        Returns:
            dict: WAF detection results
        """
        print(f"{Colors.CYAN}[i] Analyzing WAF signatures...{Colors.RESET}")
        
        # Step 1: Check headers and response content for WAF signatures
        header_result = self._check_headers()
        if header_result['detected']:
            self.detected_waf = header_result['waf_name']
            return header_result
        
        # Step 2: Test with suspicious payloads
        print(f"{Colors.CYAN}[i] Testing with suspicious payloads...{Colors.RESET}")
        payload_result = self._test_payloads()
        if payload_result['detected']:
            self.detected_waf = payload_result['waf_name']
            return payload_result
        
        # No WAF detected
        return {
            'detected': False,
            'waf_name': None,
            'signature': None,
            'type': None
        }
    
    def _check_headers(self):
        """
        Check HTTP headers and cookies for WAF signatures
        
        Returns:
            dict: WAF detection result from header analysis
        """
        response = self.http_handler.get()
        
        if not response['success']:
            return {
                'detected': False,
                'waf_name': None,
                'signature': None,
                'type': None
            }
        
        # Get all response headers and cookies as lowercase string
        headers_str = ' '.join([f'{k} {v}' for k, v in response['headers'].items()]).lower()
        cookies_str = ' '.join([f'{k} {v}' for k, v in response['cookies'].items()]).lower()
        content_str = response['content'].lower()
        
        combined_str = headers_str + ' ' + cookies_str + ' ' + content_str
        
        # Check against each WAF signature
        for waf_name, signatures in self.waf_signatures.items():
            for signature in signatures:
                if signature.lower() in combined_str:
                    print(f"{Colors.YELLOW}[!] WAF signature matched: {waf_name} ({signature}){Colors.RESET}")
                    return {
                        'detected': True,
                        'waf_name': waf_name,
                        'signature': signature,
                        'type': 'Header/Cookie/Content Analysis'
                    }
        
        return {
            'detected': False,
            'waf_name': None,
            'signature': None,
            'type': None
        }
    
    def _test_payloads(self):
        """
        Test with suspicious payloads to trigger WAF
        
        Returns:
            dict: WAF detection result from payload testing
        """
        # Get normal response first
        normal_response = self.http_handler.get()
        
        if not normal_response['success']:
            return {
                'detected': False,
                'waf_name': None,
                'signature': None,
                'type': None
            }
        
        normal_status = normal_response['status_code']
        normal_content_length = normal_content_length
        
        # Test each payload
        for payload in self.TEST_PAYLOADS:
            test_url = self.http_handler.target_url
            
            # Add payload as parameter if URL has parameters
            if '?' in test_url:
                test_url += f'&test={payload}'
            else:
                test_url += f'?test={payload}'
            
            test_response = self.http_handler.get(test_url)
            
            if not test_response['success']:
                continue
            
            # Check for WAF indicators
            waf_indicators = self._check_waf_indicators(test_response, normal_response)
            
            if waf_indicators['blocked']:
                return {
                    'detected': True,
                    'waf_name': waf_indicators['waf_name'] or 'Generic WAF',
                    'signature': payload,
                    'type': 'Payload Testing'
                }
        
        return {
            'detected': False,
            'waf_name': None,
            'signature': None,
            'type': None
        }
    
    def _check_waf_indicators(self, test_response, normal_response):
        """
        Check if response indicates WAF blocking
        
        Args:
            test_response (dict): Response with test payload
            normal_response (dict): Normal response
        
        Returns:
            dict: WAF indicator analysis
        """
        indicators = {
            'blocked': False,
            'waf_name': None,
            'reasons': []
        }
        
        test_status = test_response.get('status_code')
        normal_status = normal_response.get('status_code')
        test_content = test_response.get('content', '').lower()
        
        # Check for status code changes (403, 406, etc.)
        if test_status in [403, 406, 401, 503]:
            indicators['blocked'] = True
            indicators['reasons'].append(f'Status code changed to {test_status}')
        
        # Check for WAF-specific responses
        waf_keywords = [
            'block', 'forbidden', 'access denied', 'not acceptable',
            'security', 'firewall', 'waf', 'protection',
            'cloudflare', 'akamai', 'incapsula', 'sucuri'
        ]
        
        for keyword in waf_keywords:
            if keyword in test_content:
                indicators['blocked'] = True
                indicators['reasons'].append(f'Keyword found: {keyword}')
                
                # Try to identify specific WAF
                for waf_name in self.waf_signatures.keys():
                    if waf_name.lower() in test_content:
                        indicators['waf_name'] = waf_name
                        break
                break
        
        # Check for drastic content change
        test_length = test_response.get('content_length', 0)
        normal_length = normal_response.get('content_length', 0)
        
        if test_length < normal_length * 0.5:  # Response became much shorter
            indicators['blocked'] = True
            indicators['reasons'].append('Content length drastically reduced')
        
        return indicators
    
    def check_bypass_techniques(self):
        """
        Test various WAF bypass techniques
        
        Returns:
            dict: Bypass technique results
        """
        if not self.detected_waf:
            return {
                'error': 'No WAF detected',
                'techniques': {}
            }
        
        print(f"{Colors.CYAN}[i] Testing bypass techniques for {self.detected_waf}...{Colors.RESET}")
        
        bypass_methods = {
            'URL Encoding': self._test_url_encoding,
            'Double Encoding': self._test_double_encoding,
            'Comment Injection': self._test_comment_injection,
            'Case Variation': self._test_case_variation,
            'Whitespace Variation': self._test_whitespace_variation,
            'Null Byte Injection': self._test_null_byte,
            'Line Break Injection': self._test_line_break,
            'Random Noise': self._test_random_noise
        }
        
        results = {}
        
        for method_name, method_func in bypass_methods.items():
            try:
                result = method_func()
                results[method_name] = result['bypass_successful']
                
                if result['bypass_successful']:
                    print(f"{Colors.GREEN}[✓] {method_name}: Potentially bypassable{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[✗] {method_name}: Blocked{Colors.RESET}")
                    
            except Exception as e:
                results[method_name] = False
                print(f"{Colors.RED}[✗] {method_name}: Error - {str(e)}{Colors.RESET}")
        
        return results
    
    def _test_url_encoding(self):
        """Test URL encoding bypass"""
        payload = "1%20UNION%20SELECT%201--"
        
        if '?' in self.http_handler.target_url:
            test_url = self.http_handler.target_url + f'&test={payload}'
        else:
            test_url = self.http_handler.target_url + f'?test={payload}'
        
        response = self.http_handler.get(test_url)
        
        return {
            'bypass_successful': response['success'] and response['status_code'] == 200
        }
    
    def _test_double_encoding(self):
        """Test double URL encoding bypass"""
        payload = "1%2520UNION%2520SELECT%25201--"
        
        if '?' in self.http_handler.target_url:
            test_url = self.http_handler.target_url + f'&test={payload}'
        else:
            test_url = self.http_handler.target_url + f'?test={payload}'
        
        response = self.http_handler.get(test_url)
        
        return {
            'bypass_successful': response['success'] and response['status_code'] == 200
        }
    
    def _test_comment_injection(self):
        """Test comment injection bypass"""
        payload = "1/**/UNION/**/SELECT/**/1--"
        
        if '?' in self.http_handler.target_url:
            test_url = self.http_handler.target_url + f'&test={payload}'
        else:
            test_url = self.http_handler.target_url + f'?test={payload}'
        
        response = self.http_handler.get(test_url)
        
        return {
            'bypass_successful': response['success'] and response['status_code'] == 200
        }
    
    def _test_case_variation(self):
        """Test case variation bypass"""
        payload = "1 uNiOn SeLeCt 1--"
        
        if '?' in self.http_handler.target_url:
            test_url = self.http_handler.target_url + f'&test={payload}'
        else:
            test_url = self.http_handler.target_url + f'?test={payload}'
        
        response = self.http_handler.get(test_url)
        
        return {
            'bypass_successful': response['success'] and response['status_code'] == 200
        }
    
    def _test_whitespace_variation(self):
        """Test whitespace variation bypass"""
        payload = "1%09UNION%09SELECT%091--"
        
        if '?' in self.http_handler.target_url:
            test_url = self.http_handler.target_url + f'&test={payload}'
        else:
            test_url = self.http_handler.target_url + f'?test={payload}'
        
        response = self.http_handler.get(test_url)
        
        return {
            'bypass_successful': response['success'] and response['status_code'] == 200
        }
    
    def _test_null_byte(self):
        """Test null byte injection bypass"""
        payload = "1%00UNION%00SELECT%001--"
        
        if '?' in self.http_handler.target_url:
            test_url = self.http_handler.target_url + f'&test={payload}'
        else:
            test_url = self.http_handler.target_url + f'?test={payload}'
        
        response = self.http_handler.get(test_url)
        
        return {
            'bypass_successful': response['success'] and response['status_code'] == 200
        }
    
    def _test_line_break(self):
        """Test line break injection bypass"""
        payload = "1%0aUNION%0aSELECT%0a1--"
        
        if '?' in self.http_handler.target_url:
            test_url = self.http_handler.target_url + f'&test={payload}'
        else:
            test_url = self.http_handler.target_url + f'?test={payload}'
        
        response = self.http_handler.get(test_url)
        
        return {
            'bypass_successful': response['success'] and response['status_code'] == 200
        }
    
    def _test_random_noise(self):
        """Test random noise injection bypass"""
        payload = "1/*!00000UNION*/SELECT/*!00000*/1--"
        
        if '?' in self.http_handler.target_url:
            test_url = self.http_handler.target_url + f'&test={payload}'
        else:
            test_url = self.http_handler.target_url + f'?test={payload}'
        
        response = self.http_handler.get(test_url)
        
        return {
            'bypass_successful': response['success'] and response['status_code'] == 200
        }