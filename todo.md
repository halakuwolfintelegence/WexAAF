# WexAAF - AI Powered Web Penetration Testing Tool

## Project Overview
WexAAF is an ethical web security testing tool designed for educational purposes only. It performs various security checks including:
- Website security analysis
- Column detection
- WAF detection and bypass checks
- Database enumeration and data extraction
- XSS vulnerability detection
- Permuted URL discovery
- AI-powered analysis

## Task Checklist

### Phase 1: Project Structure & Setup
- [x] Create project directory structure
- [x] Create main WexAAF script
- [x] Create configuration file
- [x] Create requirements.txt for dependencies
- [x] Create README.md with disclaimer

### Phase 2: Core Modules
- [x] Create HTTP request handler module
- [x] Create WAF detector module
- [x] Create SQL injection module
- [x] Create XSS scanner module
- [x] Create URL bruteforcer module
- [x] Create AI analyzer module
- [x] Create data dumper module

### Phase 3: Main Interface
- [x] Create interactive CLI interface
- [x] Add banner and disclaimer
- [x] Implement command parser
- [x] Add color output formatting
- [x] Create result exporter

### Phase 4: Testing & Documentation
- [x] Test all modules
- [x] Create usage examples
- [x] Write comprehensive README
- [x] Finalize disclaimer
- [x] Create test suite
- [x] Verify all functionality

## Project Structure
```
wexaaf/
├── wexaaf.py              # Main entry point
├── modules/
│   ├── __init__.py
│   ├── http_handler.py    # HTTP requests
│   ├── waf_detector.py    # WAF detection
│   ├── sql_injector.py    # SQL injection checks
│   ├── xss_scanner.py     # XSS detection
│   ├── url_bruteforce.py  # URL discovery
│   ├── ai_analyzer.py     # AI-powered analysis
│   ├── data_dumper.py     # Database dumping
│   └── utils.py           # Utilities
├── config/
│   ├── settings.json      # Configuration
│   └── payloads.txt       # Payload templates
├── output/                # Results directory
├── requirements.txt       # Python dependencies
└── README.md             # Documentation
```

## Legal Disclaimer
This tool is created SOLELY for educational and ethical security testing purposes. Users must:
- Only test systems they own or have explicit permission to test
- Never use this tool for malicious purposes
- Always comply with local laws and regulations
- Test on your own server first
- The developers are NOT responsible for any misuse