#!/usr/bin/env python3
"""
Test Script for WexAAF
This script demonstrates the basic functionality of WexAFP modules
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_module_imports():
    """Test if all modules can be imported successfully"""
    print("Testing module imports...")
    
    try:
        from modules import HTTPHandler, WAFDetector, SQLInjector, XSSScanner
        from modules import URLBruteforcer, AIAnalyzer, DataDumper, utils
        print("✓ All modules imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_banner():
    """Test banner display"""
    print("\n" + "="*60)
    print("Testing Banner Display")
    print("="*60)
    
    from modules.utils import print_banner, print_disclaimer
    print_banner()
    print_disclaimer()
    print("✓ Banner and disclaimer displayed")
    return True

def test_colors():
    """Test color output"""
    print("\n" + "="*60)
    print("Testing Color Output")
    print("="*60)
    
    from modules.utils import Colors
    
    print(f"{Colors.RED}RED{Colors.RESET}")
    print(f"{Colors.GREEN}GREEN{Colors.RESET}")
    print(f"{Colors.YELLOW}YELLOW{Colors.RESET}")
    print(f"{Colors.BLUE}BLUE{Colors.RESET}")
    print(f"{Colors.BRIGHT_PURPLE}PURPLE{Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}CYAN{Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}WHITE{Colors.RESET}")
    
    print("\n✓ Color output working")
    return True

def test_http_handler():
    """Test HTTP handler with a safe test URL"""
    print("\n" + "="*60)
    print("Testing HTTP Handler")
    print("="*60)
    
    from modules.http_handler import HTTPHandler
    
    # Test with example.com (safe, public site)
    print("Testing with example.com...")
    handler = HTTPHandler("https://example.com")
    
    response = handler.get()
    
    if response['success']:
        print(f"✓ GET request successful")
        print(f"  Status code: {response['status_code']}")
        print(f"  Response time: {response['response_time']}s")
        print(f"  Content length: {response['content_length']} bytes")
        return True
    else:
        print(f"✗ Request failed: {response.get('error', 'Unknown error')}")
        return False

def test_server_info():
    """Test server information extraction"""
    print("\n" + "="*60)
    print("Testing Server Information Extraction")
    print("="*60)
    
    from modules.http_handler import HTTPHandler
    
    handler = HTTPHandler("https://example.com")
    server_info = handler.get_server_info()
    
    print(f"  Server: {server_info.get('server', 'Unknown')}")
    print(f"  Status code: {server_info.get('status_code', 'Unknown')}")
    print(f"  Technology: {server_info.get('technology', 'Unknown')}")
    
    print("\n✓ Server information extraction working")
    return True

def test_waf_detection():
    """Test WAF detection"""
    print("\n" + "="*60)
    print("Testing WAF Detection")
    print("="*60)
    
    from modules.http_handler import HTTPHandler
    from modules.waf_detector import WAFDetector
    
    handler = HTTPHandler("https://example.com")
    detector = WAFDetector(handler)
    
    result = detector.detect_waf()
    
    if result['detected']:
        print(f"  WAF Detected: {result['waf_name']}")
    else:
        print("  No WAF detected")
    
    print("\n✓ WAF detection working")
    return True

def main():
    """Run all tests"""
    print("\n")
    print("="*60)
    print(" WexAAF Test Suite")
    print("="*60)
    
    tests = [
        ("Module Imports", test_module_imports),
        ("Banner Display", test_banner),
        ("Color Output", test_colors),
        ("HTTP Handler", test_http_handler),
        ("Server Info", test_server_info),
        ("WAF Detection", test_waf_detection),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ Test '{test_name}' failed with error: {e}")
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "="*60)
    print(" TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"{status}: {test_name}")
    
    print("\n" + "="*60)
    print(f" Results: {passed}/{total} tests passed")
    print("="*60)
    
    if passed == total:
        print("\n🎉 All tests passed! WexAAF is ready to use.\n")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the errors above.\n")
        return 1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)