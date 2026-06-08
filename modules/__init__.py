"""
WexAAF Modules
============

This package contains all the security testing modules for WexAAF.
"""

__version__ = '1.0.0'
__author__ = 'WexAAF Team'

from .http_handler import HTTPHandler
from .waf_detector import WAFDetector
from .sql_injector import SQLInjector
from .xss_scanner import XSSScanner
from .url_bruteforce import URLBruteforcer
from .ai_analyzer import AIAnalyzer
from .data_dumper import DataDumper
from .utils import Colors, print_banner, print_disclaimer, save_results

__all__ = [
    'HTTPHandler',
    'WAFDetector',
    'SQLInjector',
    'XSSScanner',
    'URLBruteforcer',
    'AIAnalyzer',
    'DataDumper',
    'Colors',
    'print_banner',
    'print_disclaimer',
    'save_results'
]