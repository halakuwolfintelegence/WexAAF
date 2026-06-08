"""
URL Bruteforce Module for WexAAF
Discovers hidden paths and permuted URLs
"""

import re
from .utils import Colors


class URLBruteforcer:
    """
    URL Discovery and Bruteforce class
    """
    
    # Common directory and file names
    COMMON_DIRECTORIES = [
        'admin', 'administrator', 'wp-admin', 'cpanel', 'dashboard',
        'login', 'signin', 'account', 'user', 'auth', 'authentication',
        'api', 'v1', 'v2', 'rest', 'graphql', 'webhook',
        'config', 'configuration', 'settings', 'setup', 'install',
        'backup', 'backups', 'db', 'database', 'sql', 'dump',
        'test', 'testing', 'dev', 'staging', 'demo', 'temp',
        'uploads', 'upload', 'files', 'images', 'img', 'assets',
        'includes', 'include', 'lib', 'libraries', 'vendor',
        'private', 'protected', 'secret', 'hidden',
        'logs', 'log', 'error', 'errors',
        'docs', 'documentation', 'help', 'support',
        'static', 'public', 'www', 'htdocs',
        'scripts', 'js', 'css', 'style',
        'admin.php', 'login.php', 'config.php', 'index.php',
        'admin.html', 'login.html', 'dashboard.html',
        'robots.txt', 'sitemap.xml', '.htaccess', '.git'
    ]
    
    COMMON_EXTENSIONS = [
        '', '.php', '.html', '.htm', '.asp', '.aspx', '.jsp',
        '.json', '.xml', '.txt', '.log', '.sql', '.bak', '.old',
        '.tar', '.zip', '.rar', '.gz', '.conf', '.cfg'
    ]
    
    # Parameter fuzzing list
    PARAMETER_NAMES = [
        'id', 'page', 'user', 'username', 'name', 'email',
        'search', 'query', 'q', 'term', 'keyword', 'filter',
        'cat', 'category', 'type', 'sort', 'order', 'limit',
        'offset', 'start', 'count', 'num', 'number',
        'action', 'do', 'method', 'cmd', 'command',
        'file', 'filename', 'path', 'dir', 'directory',
        'url', 'link', 'ref', 'source', 'redirect',
        'lang', 'language', 'locale', 'region',
        'format', 'output', 'callback', 'jsonp',
        'token', 'session', 'key', 'secret', 'auth',
        'debug', 'test', 'demo', 'mode', 'type',
        'view', 'show', 'display', 'list', 'detail',
        'create', 'add', 'edit', 'update', 'delete',
        'status', 'state', 'active', 'enabled'
    ]
    
    def __init__(self, http_handler):
        """
        Initialize URL Bruteforcer
        
        Args:
            http_handler: HTTPHandler instance
        """
        self.http_handler = http_handler
        
    def discover_urls(self):
        """
        Discover URLs through various methods
        
        Returns:
            dict: URL discovery results
        """
        print(f"{Colors.CYAN}[i] Starting URL discovery...{Colors.RESET}")
        
        found_urls = []
        tested_urls = []
        
        # Method 1: Directory bruteforce
        print(f"{Colors.CYAN}[i] Performing directory bruteforce...{Colors.RESET}")
        dir_results = self._bruteforce_directories()
        found_urls.extend(dir_results['found'])
        tested_urls.extend(dir_results['tested'])
        
        # Method 2: Extract links from page
        print(f"{Colors.CYAN}[i] Extracting links from page...{Colors.RESET}")
        link_results = self._extract_page_links()
        found_urls.extend(link_results['found'])
        tested_urls.extend(link_results['tested'])
        
        # Method 3: Parameter fuzzing
        print(f"{Colors.CYAN}[i] Performing parameter fuzzing...{Colors.RESET}")
        param_results = self._fuzz_parameters()
        found_urls.extend(param_results['found'])
        tested_urls.extend(param_results['tested'])
        
        # Method 4: Common backup and config files
        print(f"{Colors.CYAN}[i] Checking for backup and config files...{Colors.RESET}")
        backup_results = self._check_backup_files()
        found_urls.extend(backup_results['found'])
        tested_urls.extend(backup_results['tested'])
        
        # Remove duplicates
        found_urls = list(set(found_urls))
        tested_urls = list(set(tested_urls))
        
        print(f"{Colors.GREEN}[✓] Found {len(found_urls)} unique URLs after testing {len(tested_urls)} URLs{Colors.RESET}")
        
        return {
            'found_urls': found_urls,
            'total_tested': len(tested_urls),
            'success_rate': round(len(found_urls) / len(tested_urls) * 100, 2) if tested_urls else 0
        }
    
    def _bruteforce_directories(self):
        """
        Bruteforce common directories
        
        Returns:
            dict: Directory bruteforce results
        """
        found = []
        tested = []
        base_url = self.http_handler.target_url.rstrip('/')
        
        # Limit the number of requests for performance
        max_tests = 100
        test_count = 0
        
        for directory in self.COMMON_DIRECTORIES:
            if test_count >= max_tests:
                break
                
            for extension in self.COMMON_EXTENSIONS[:5]:  # Limit extensions
                test_url = f"{base_url}/{directory}{extension}"
                tested.append(test_url)
                
                response = self.http_handler.get(test_url)
                test_count += 1
                
                if response['success'] and response['status_code'] != 404:
                    found.append(test_url)
                    print(f"{Colors.GREEN}[+] Found: {test_url} ({response['status_code']}){Colors.RESET}")
        
        return {'found': found, 'tested': tested}
    
    def _extract_page_links(self):
        """
        Extract links from the main page
        
        Returns:
            dict: Link extraction results
        """
        found = []
        tested = []
        
        try:
            links = self.http_handler.extract_links()
            tested.extend(links)
            
            # Test each link
            for link in links:
                # Only test links from same domain
                if self._same_domain(link, self.http_handler.target_url):
                    response = self.http_handler.get(link)
                    if response['success']:
                        found.append(link)
        
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error extracting links: {str(e)}{Colors.RESET}")
        
        return {'found': found, 'tested': tested}
    
    def _fuzz_parameters(self):
        """
        Fuzz URL parameters
        
        Returns:
            dict: Parameter fuzzing results
        """
        found = []
        tested = []
        base_url = self.http_handler.target_url
        
        # Test adding new parameters to URL
        max_params = 20  # Limit for performance
        
        for param in self.PARAMETER_NAMES[:max_params]:
            test_url = f"{base_url}?{param}=test"
            tested.append(test_url)
            
            response = self.http_handler.get(test_url)
            
            # Look for different responses (might indicate valid parameter)
            if response['success'] and response['status_code'] == 200:
                found.append(test_url)
        
        return {'found': found, 'tested': tested}
    
    def _check_backup_files(self):
        """
        Check for common backup and configuration files
        
        Returns:
            dict: Backup file check results
        """
        found = []
        tested = []
        base_url = self.http_handler.target_url.rstrip('/')
        
        backup_files = [
            'backup.zip', 'backup.tar.gz', 'backup.sql',
            'database.sql', 'db.sql', 'dump.sql',
            'config.php.bak', 'config.php~', 'config.php.old',
            'wp-config.php.bak', 'wp-config.php~',
            '.git/config', '.env', '.env.bak',
            'web.config.bak', 'web.config~',
            'settings.py', 'settings.json.bak',
            'debug.log', 'error.log', 'access.log'
        ]
        
        for backup_file in backup_files:
            test_url = f"{base_url}/{backup_file}"
            tested.append(test_url)
            
            response = self.http_handler.get(test_url)
            
            if response['success'] and response['status_code'] != 404:
                found.append(test_url)
                print(f"{Colors.YELLOW}[!] Backup/config found: {test_url} ({response['status_code']}){Colors.RESET}")
        
        return {'found': found, 'tested': tested}
    
    def _same_domain(self, url1, url2):
        """
        Check if two URLs are from the same domain
        
        Args:
            url1 (str): First URL
            url2 (str): Second URL
        
        Returns:
            bool: True if same domain
        """
        try:
            import urllib.parse
            domain1 = urllib.parse.urlparse(url1).netloc
            domain2 = urllib.parse.urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False
    
    def generate_permuted_urls(self, base_url):
        """
        Generate permuted URLs based on patterns
        
        Args:
            base_url (str): Base URL
        
        Returns:
            list: Permuted URLs
        """
        permuted = []
        parsed = self._parse_url(base_url)
        
        if not parsed:
            return permuted
        
        path_components = parsed['path'].strip('/').split('/')
        
        # Generate combinations
        from itertools import permutations, combinations
        
        # Permutations of path components
        if len(path_components) > 2:
            for perm in permutations(path_components, min(len(path_components), 3)):
                permuted.append(f"{parsed['scheme']}://{parsed['netloc']}/{'/'.join(perm)}")
        
        # Add common suffixes
        common_suffixes = ['/', '.php', '.html', '.json', '/api', '/v1', '/v2']
        for suffix in common_suffixes:
            permuted.append(base_url.rstrip('/') + suffix)
        
        # Add common prefixes
        common_prefixes = ['admin/', 'api/', 'v1/', 'v2/', 'dev/', 'test/']
        for prefix in common_prefixes:
            permuted.append(base_url.rstrip('/') + '/' + prefix)
        
        return list(set(permuted))
    
    def _parse_url(self, url):
        """
        Parse URL into components
        
        Args:
            url (str): URL to parse
        
        Returns:
            dict: URL components
        """
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            return {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path,
                'params': parsed.params,
                'query': parsed.query,
                'fragment': parsed.fragment
            }
        except:
            return None
    
    def discover_hidden_api(self):
        """
        Discover hidden API endpoints
        
        Returns:
            list: Found API endpoints
        """
        print(f"{Colors.CYAN}[i] Looking for hidden API endpoints...{Colors.RESET}")
        
        api_endpoints = []
        base_url = self.http_handler.target_url.rstrip('/')
        
        # Common API patterns
        api_patterns = [
            '/api/v1/users',
            '/api/v1/products',
            '/api/v1/categories',
            '/api/auth/login',
            '/api/auth/register',
            '/api/admin',
            '/api/dashboard',
            '/graphql',
            '/rest/api',
            '/wp-json/wp/v2/posts',
            '/wp-json/wp/v2/users'
        ]
        
        for pattern in api_patterns:
            test_url = base_url + pattern
            response = self.http_handler.get(test_url)
            
            if response['success']:
                if response['status_code'] in [200, 201, 400, 405]:  # API responses
                    api_endpoints.append(test_url)
                    print(f"{Colors.GREEN}[+] API endpoint found: {test_url}{Colors.RESET}")
        
        return api_endpoints
    
    def check_robots_txt(self):
        """
        Check robots.txt for hidden paths
        
        Returns:
            list: Hidden paths from robots.txt
        """
        print(f"{Colors.CYAN}[i] Checking robots.txt...{Colors.RESET}")
        
        base_url = self.http_handler.target_url.rstrip('/')
        robots_url = f"{base_url}/robots.txt"
        
        response = self.http_handler.get(robots_url)
        
        if not response['success'] or response['status_code'] == 404:
            return []
        
        content = response.get('content', '')
        hidden_paths = []
        
        # Parse robots.txt for disallowed paths
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.startswith('Disallow:'):
                path = line.replace('Disallow:', '').strip()
                if path and path != '/':
                    hidden_paths.append(path)
                    print(f"{Colors.YELLOW}[+] Disallowed path: {path}{Colors.RESET}")
        
        return hidden_paths
    
    def check_sitemap(self):
        """
        Check sitemap.xml for additional URLs
        
        Returns:
            list: URLs from sitemap
        """
        print(f"{Colors.CYAN}[i] Checking sitemap.xml...{Colors.RESET}")
        
        base_url = self.http_handler.target_url.rstrip('/')
        sitemap_url = f"{base_url}/sitemap.xml"
        
        response = self.http_handler.get(sitemap_url)
        
        if not response['success'] or response['status_code'] == 404:
            return []
        
        content = response.get('content', '')
        urls = []
        
        # Extract URLs from sitemap
        import re
        url_pattern = r'<loc>(.*?)</loc>'
        matches = re.findall(url_pattern, content)
        
        urls.extend(matches)
        
        print(f"{Colors.GREEN}[+] Found {len(urls)} URLs in sitemap{Colors.RESET}")
        
        return urls