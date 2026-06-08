# WexAAF - AI Powered Web Penetration Testing Tool

## ⚠️ IMPORTANT LEGAL DISCLAIMER

**WexAAF is created SOLELY for educational and ethical security testing purposes.**

By using this tool, you agree to:

✓ Only test websites you OWN or have EXPLICIT WRITTEN permission to test  
✓ Never use WexAAF for malicious purposes or unauthorized access  
✓ Always comply with local, state, and federal laws  
✓ Test on your own server first before any deployment  
✓ Use this tool responsibly and ethically  

**DISCLAIMER:**
The developers and contributors of WexAAF are NOT responsible for:
- Any misuse of this tool
- Any damage caused to systems
- Any legal consequences arising from misuse
- Any unauthorized access or data breaches

**TRY IT ON YOUR OWN SERVER AND WE ARE NOT RESPONSIBLE FOR WRONG USE!**  
**WE WILL MAKE THIS TOOL ONLY ETHICAL AND EDUCATIONAL PURPOSED.**

For authorized security testing, always obtain proper authorization first.

---

## 🎯 About WexAAF

WexAAF is a comprehensive, AI-powered web penetration testing tool designed for ethical security testing and educational purposes. It provides automated vulnerability scanning with intelligent analysis capabilities.

### Features

✅ **Website Security Analysis** - Analyze server information, security headers, and technology stack  
✅ **WAF Detection & Bypass Testing** - Detect Web Application Firewalls and test evasion techniques  
✅ **SQL Injection Detection** - Test for SQL injection vulnerabilities and enumerate database structure  
✅ **XSS Vulnerability Scanning** - Detect reflected, stored, and DOM-based XSS vulnerabilities  
✅ **URL Discovery** - Discover hidden paths, backup files, and sensitive endpoints  
✅ **AI-Powered Analysis** - Intelligent vulnerability scoring, prioritization, and recommendations  
✅ **Data Dumping** - Extract database information and enumerate tables/columns  
✅ **Column Detection** - Automatically detect number of columns for union-based injection  
✅ **Database Enumeration** - Find database names, versions, and structure  
✅ **Comprehensive Reporting** - Generate detailed security reports  

---

## 📦 Installation

### Requirements

- Python 3.7 or higher
- pip (Python package installer)

### Setup

1. Clone or download WexAAF:
```bash
git clone https://github.com/yourusername/wexaaf.git
cd wexaaf
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Verify installation:
```bash
python wexaaf.py --help
```

---

## 🚀 Usage

### Basic Usage

Run a full security scan:
```bash
python wexaaf.py -u https://example.com
```

### Command Line Options

```bash
python wexaaf.py -u <URL> [options]

Options:
  -u, --url              Target URL (required)
  --basic                Run basic security analysis (default: true)
  --waf                  Run WAF detection (default: true)
  --sql                  Run SQL injection tests (default: true)
  --xss                  Run XSS vulnerability scan (default: true)
  --brute                Run URL bruteforce (default: true)
  --ai                   Run AI analysis (default: true)
  --sql-only             Run only SQL injection tests
  --xss-only             Run only XSS vulnerability scan
  --no-waf               Skip WAF detection
  --no-output            Skip saving results to file
  -h, --help             Show help message
```

### Examples

1. **Full Security Scan:**
```bash
python wexaaf.py -u https://example.com
```

2. **SQL Injection Only:**
```bash
python wexaaf.py -u https://example.com --sql-only
```

3. **XSS Scan Only:**
```bash
python wexaaf.py -u https://example.com --xss-only
```

4. **Skip WAF Detection:**
```bash
python wexaaf.py -u https://example.com --no-waf
```

5. **Without Saving Results:**
```bash
python wexaaf.py -u https://example.com --no-output
```

---

## 📊 Output

WexAAF generates:
- **Console Output**: Real-time colored terminal output showing scan progress
- **Text Report**: Detailed security reports saved to the `output/` directory
- **Structured Results**: JSON-formatted results for further analysis

### Output Directory Structure
```
wexaaf/
├── output/
│   ├── scan_20240101_120000.txt      # Full scan report
│   ├── db_dump_20240101_120000.json  # Database dumps (if applicable)
│   └── ...
```

---

## 🔧 Modules

### HTTP Handler
- Handles all HTTP requests
- Supports GET, POST methods
- Session management
- Header/cookie analysis
- Form/link extraction

### WAF Detector
- Detects popular WAFs (Cloudflare, Fortinet, Akamai, etc.)
- Tests bypass techniques
- Signature-based detection
- Payload-based detection

### SQL Injector
- Boolean-based injection
- Error-based injection
- Union-based injection
- Time-based (blind) injection
- Column detection
- Database enumeration

### XSS Scanner
- Reflected XSS detection
- Stored XSS detection
- DOM-based XSS detection
- Multiple payload types
- Context analysis

### URL Bruteforcer
- Directory bruteforce
- Link extraction
- Parameter fuzzing
- Backup file detection
- API endpoint discovery

### AI Analyzer
- Intelligent vulnerability scoring
- Risk assessment
- Priority recommendations
- Trend analysis
- Comprehensive reporting

### Data Dumper
- Database enumeration
- Table/column discovery
- Data extraction
- Structured output

---

## 🛡️ Security Best Practices

1. **Always Get Permission** - Never test systems you don't own or have explicit permission to test
2. **Use in Isolated Environment** - Test on your own servers first
3. **Keep Updated** - Regularly update WexAAF and its dependencies
4. **Review Results** - Always manually verify findings
5. **Report Responsibly** - Follow responsible disclosure practices
6. **Educational Use** - Use only for learning and improving security

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

**Contributions should focus on:**
- Bug fixes
- New features for educational purposes
- Documentation improvements
- Security enhancements

---

## 📝 License

This project is for educational purposes only. Use responsibly.

---

## 🙏 Acknowledgments

- Security researchers and contributors
- Open source security tools community
- Educational security resources

---

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review examples use cases

---

## 🔄 Updates

### Version 1.0.0
- Initial release
- Core vulnerability scanning modules
- AI-powered analysis
- Comprehensive reporting

---

## ⚡ Performance Tips

1. **Limit Scan Scope** - Focus on specific modules for faster results
2. **Adjust Timeout** - Modify timeout settings in config/settings.json
3. **Use Selective Scans** - Use --sql-only or --xss-only for targeted testing
4. **Monitor Resources** - Keep an eye on system resources during scans

---

## 🐛 Troubleshooting

### Common Issues

1. **Connection Timeout**
   - Increase timeout in settings.json
   - Check network connectivity
   - Verify target URL is accessible

2. **SSL Certificate Errors**
   - SSL verification is disabled by default for testing
   - For production, use valid certificates

3. **Permission Errors**
   - Ensure you have write permissions for output directory
   - Run with appropriate permissions

4. **Module Import Errors**
   - Verify all dependencies are installed
   - Check Python version (3.7+ required)

---

## 📚 Learning Resources

- OWASP Testing Guide
- Web Application Security Basics
- SQL Injection Techniques
- XSS Prevention Cheat Sheet
- Ethical Hacking Best Practices

---

## 🌟 Features Highlight

### AI-Powered Analysis
WexAAF uses intelligent algorithms to:
- Calculate overall risk scores
- Prioritize vulnerability fixes
- Generate actionable recommendations
- Identify patterns and trends

### Comprehensive Scanning
- Multiple attack vectors tested
- Automated vulnerability detection
- Real-time progress updates
- Detailed finding reports

### Educational Focus
- Explanations for each finding
- Remediation recommendations
- Best practices guidance
- Security score calculation

---

**Remember: This tool is for EDUCATIONAL PURPOSES ONLY!**  
**TRY IT ON YOUR OWN SERVER - WE ARE NOT RESPONSIBLE FOR MISUSE**

---

**Made with ❤️ for the security community**