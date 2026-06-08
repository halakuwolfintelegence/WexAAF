"""
HTTP Handler Module for WexAAF
Handles all HTTP requests and response analysis
"""

import requests
import urllib3
import time
from .utils import Colors, get_random_user_agent

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPHandler:
    """
    HTTP Handler class for managing requests to target websites
    """
    
    def __init__(self, target_url):
        """
        Initialize HTTP Handler
        
        Args:
            target_url (str): Target website URL
        """
        self.target_url = target_url
        self.session = requests.Session()
        
        # Configure session
        self.session.headers.update({
            'User-Agent': get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Configure request settings
        self.verify_ssl = False  # For testing purposes
        self.timeout = 10
        self.max_retries = 3
        
    def get(self, url=None, params=None, headers=None, timeout=None, follow_redirects=True):
        """
        Perform GET request
        
        Args:
            url (str): URL to request (default: self.target_url)
            params (dict): Query parameters
            headers (dict): Additional headers
            timeout (int): Request timeout
            follow_redirects (bool): Follow redirects
        
        Returns:
            dict: Response information
        """
        target = url or self.target_url
        
        try:
            start_time = time.time()
            response = self.session.get(
                target,
                params=params,
                headers=headers,
                verify=self.verify_ssl,
                timeout=timeout or self.timeout,
                allow_redirects=follow_redirects
            )
            end_time = time.time()
            
            return {
                'status_code': response.status_code,
                'url': response.url,
                'headers': dict(response.headers),
                'content': response.text,
                'content_length': len(response.content),
                'response_time': round(end_time - start_time, 3),
                'history': [r.url for r in response.history],
                'cookies': dict(response.cookies),
                'elapsed': response.elapsed.total_seconds(),
                'success': True
            }
            
        except requests.exceptions.Timeout:
            return {
                'error': 'Request timeout',
                'success': False
            }
        except requests.exceptions.TooManyRedirects:
            return {
                'error': 'Too many redirects',
                'success': False
            }
        except requests.exceptions.SSLError:
            return {
                'error': 'SSL error',
                'success': False
            }
        except requests.exceptions.ConnectionError as e:
            return {
                'error': f'Connection error: {str(e)}',
                'success': False
            }
        except Exception as e:
            return {
                'error': f'Unexpected error: {str(e)}',
                'success': False
            }
    
    def post(self, url=None, data=None, json_data=None, params=None, headers=None):
        """
        Perform POST request
        
        Args:
            url (str): URL to request
            data (dict): Form data
            json_data (dict): JSON data
            params (dict): Query parameters
            headers (dict): Additional headers
        
        Returns:
            dict: Response information
        """
        target = url or self.target_url
        
        try:
            start_time = time.time()
            response = self.session.post(
                target,
                data=data,
                json=json_data,
                params=params,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            end_time = time.time()
            
            return {
                'status_code': response.status_code,
                'url': response.url,
                'headers': dict(response.headers),
                'content': response.text,
                'content_length': len(response.content),
                'response_time': round(end_time - start_time, 3),
                'success': True
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'success': False
            }
    
    def get_server_info(self):
        """
        Get basic server information
        
        Returns:
            dict: Server information
        """
        response = self.get()
        
        if not response['success']:
            return {
                'error': response.get('error', 'Unknown error'),
                'server': 'Unknown',
                'status_code': 'Unknown',
                'response_time': 'Unknown',
                'content_length': 'Unknown'
            }
        
        return {
            'server': response['headers'].get('Server', 'Unknown'),
            'status_code': response['status_code'],
            'response_time': response['response_time'],
            'content_length': response['content_length'],
            'powered_by': response['headers'].get('X-Powered-By', 'Not specified'),
            'technology': self._detect_technology(response['content'], response['headers'])
        }
    
    def _detect_technology(self, content, headers):
        """
        Detect web technologies from response
        
        Args:
            content (str): Response content
            headers (dict): Response headers
        
        Returns:
            list: Detected technologies
        """
        technologies = []
        
        # Check headers
        if 'x-powered-by' in [h.lower() for h in headers.keys()]:
            tech = headers.get('X-Powered-By', '').lower()
            if 'php' in tech:
                technologies.append('PHP')
            elif 'asp.net' in tech:
                technologies.append('ASP.NET')
            elif 'express' in tech:
                technologies.append('Node.js/Express')
        
        # Check cookies
        cookies_str = ' '.join(headers.get('Set-Cookie', '').lower())
        if 'phpsessid' in cookies_str:
            technologies.append('PHP')
        elif 'jsessionid' in cookies_str:
            technologies.append('Java')
        elif 'aspsessionid' in cookies_str:
            technologies.append('ASP.NET')
        
        # Check content for patterns
        content_lower = content.lower()
        
        # Frameworks
        if 'wp-content' in content_lower or 'wordpress' in content_lower:
            technologies.append('WordPress')
        if 'joomla' in content_lower:
            technologies.append('Joomla')
        if 'drupal' in content_lower:
            technologies.append('Drupal')
        if 'laravel' in content_lower:
            technologies.append('Laravel')
        
        # JavaScript frameworks
        if 'react' in content_lower or 'createelement("react")' in content_lower:
            technologies.append('React')
        if 'vue' in content_lower:
            technologies.append('Vue.js')
        if 'angular' in content_lower:
            technologies.append('Angular')
        
        return technologies if technologies else ['Unknown']
    
    def check_security_headers(self):
        """
        Check for presence of security headers
        
        Returns:
            dict: Security headers status
        """
        response = self.get()
        
        if not response['success']:
            return {
                'error': 'Could not retrieve headers',
                'success': False
            }
        
        headers = response['headers']
        
        security_headers = {
            'X-Frame-Options': False,
            'X-Content-Type-Options': False,
            'X-XSS-Protection': False,
            'Strict-Transport-Security': False,
            'Content-Security-Policy': False,
            'Referrer-Policy': False,
            'Permissions-Policy': False,
            'X-Permitted-Cross-Domain-Policies': False
        }
        
        # Check each header
        for header in security_headers.keys():
            if any(h.lower() == header.lower() for h in headers.keys()):
                security_headers[header] = True
        
        security_headers['success'] = True
        return security_headers
    
    def extract_forms(self, url=None):
        """
        Extract all forms from a page
        
        Args:
            url (str): URL to extract forms from
        
        Returns:
            list: List of form dictionaries
        """
        response = self.get(url)
        
        if not response['success']:
            return []
        
        # Simple form extraction using regex
        import re
        
        content = response['content']
        forms = []
        
        # Find all forms
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        matches = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for match in matches:
            action, method, form_content = match
            
            # Extract input fields
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']?([^"\']*)["\']?[^>]*/?>'
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            form = {
                'action': action,
                'method': method.lower(),
                'inputs': [{'name': name, 'type': input_type} for name, input_type in inputs]
            }
            
            forms.append(form)
        
        return forms
    
    def extract_links(self, url=None):
        """
        Extract all links from a page
        
        Args:
            url (str): URL to extract links from
        
        Returns:
            list: List of link URLs
        """
        response = self.get(url)
        
        if not response['success']:
            return []
        
        # Simple link extraction using regex
        import re
        
        content = response['content']
        link_pattern = r'href=["\']([^"\']+)["\']'
        links = re.findall(link_pattern, content)
        
        # Filter and clean links
        clean_links = []
        for link in links:
            # Skip javascript, mailto, and anchor links
            if link.startswith(('javascript:', 'mailto:', '#', 'tel:')):
                continue
            
            # Convert relative URLs to absolute
            if link.startswith('/'):
                base_url = self.target_url.split('/')[0] + '//' + self.target_url.split('/')[2]
                link = base_url + link
            elif not link.startswith(('http://', 'https://')):
                base_url = self.target_url.rsplit('/', 1)[0]
                link = base_url + '/' + link
            
            clean_links.append(link)
        
        return list(set(clean_links))  # Remove duplicates
    
    def extract_parameters(self, url=None):
        """
        Extract GET parameters from URL
        
        Args:
            url (str): URL to extract parameters from
        
        Returns:
            list: List of parameter names
        """
        target = url or self.target_url
        
        if '?' not in target:
            return []
        
        query_string = target.split('?')[1]
        parameters = []
        
        for param_pair in query_string.split('&'):
            if '=' in param_pair:
                param_name = param_pair.split('=')[0]
                parameters.append(param_name)
        
        return parameters
    
    def close(self):
        """Close the HTTP session"""
        self.session.close()