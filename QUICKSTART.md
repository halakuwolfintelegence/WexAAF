# WexAAF - Quick Start Guide

## ⚡ Get Started in 3 Minutes

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Run Tests

```bash
python test_wexaaf.py
```

You should see: **🎉 All tests passed! WexAAF is ready to use.**

### Step 3: Start Scanning

```bash
python wexaaf.py -u https://example.com
```

**⚠️ IMPORTANT**: Only test on websites you OWN or have WRITTEN PERMISSION to test!

---

## 🎯 Common Commands

### Full Security Scan
```bash
python wexaaf.py -u TARGET_URL
```

### SQL Injection Only
```bash
python wexaaf.py -u TARGET_URL --sql-only
```

### XSS Scanning Only
```bash
python wexaaf.py -u TARGET_URL --xss-only
```

### Skip WAF Detection
```bash
python wexaaf.py -u TARGET_URL --no-waf
```

---

## 📊 Understanding Output

### Terminal Output
```
[✓] Success indicator
[!] Warning/finding
[i] Information
[✗] Error
```

### Colors
- 🔴 RED - Critical/Error
- 🟢 GREEN - Safe/Success
- 🟡 YELLOW - Warning
- 🔵 BLUE - Info
- 🟣 PURPLE - Special

---

## 📁 Output Files

Results are saved to the `output/` directory:
- `scan_YYYYMMDD_HHMMSS.txt` - Full scan report

---

## ⚠️ Legal Notice

**WexAAF is for EDUCATIONAL PURPOSES ONLY!**

- ✅ Test ONLY on systems you own or have explicit permission
- ✅ Use responsibly and ethically
- ❌ NEVER use for malicious purposes
- ❌ We are NOT responsible for misuse

**TRY IT ON YOUR OWN SERVER!**

---

## 📚 More Help

- Full documentation: **README.md**
- Examples: **EXAMPLES.md**
- Project info: **PROJECT_SUMMARY.md**
- Help command: `python wexaaf.py --help`

---

## 🧪 Testing Your Own Server

For learning, set up a vulnerable test environment:

### Using Docker (Recommended)
```bash
# Run DVWA (Damn Vulnerable Web App)
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

Then scan: `python wexaaf.py -u http://localhost/vulnerabilities/sqli/?id=1`

### Using XAMPP/WAMP
1. Download DVWA
2. Place in htdocs/www
3. Access at `http://localhost/dvwa`
4. Test with WexAAF

---

## 💡 Tips

1. **Start Small** - Test on your own vulnerable lab first
2. **Read Documentation** - Check README.md for details
3. **Understand Findings** - Research each vulnerability found
4. **Learn Remediation** - Focus on how to fix issues
5. **Stay Legal** - Always get permission before testing

---

## 🐛 Troubleshooting

### Import Errors
```bash
pip install -r requirements.txt --upgrade
```

### Connection Timeout
Edit `config/settings.json`:
```json
{
  "settings": {
    "timeout": 30
  }
}
```

### Permission Denied
```bash
chmod +x wexaaf.py
```

---

## 🎓 Learning Path

1. **Week 1**: Basic scanning - Understand tool output
2. **Week 2**: SQL injection - Study SQL injection techniques
3. **Week 3**: XSS - Learn XSS prevention
4. **Week 4**: WAF - Study WAF bypass techniques
5. **Week 5**: Practice - Test on your own vulnerable servers
6. **Week 6**: Deep dive - Read source code, understand implementation

---

## 🌟 Key Features

- ✅ SQL Injection Testing
- ✅ XSS Vulnerability Scanning
- ✅ WAF Detection & Bypass
- ✅ URL Discovery
- ✅ Column Detection
- ✅ Database Enumeration
- ✅ AI-Powered Analysis
- ✅ Comprehensive Reporting

---

## 🚀 Ready to Start?

```bash
# 1. Install
pip install -r requirements.txt

# 2. Test
python test_wexaaf.py

# 3. Scan (YOUR OWN SERVER ONLY!)
python wexaaf.py -u YOUR_TARGET_URL
```

---

**Remember: Ethical Hacking Only! 🛡️**

*For detailed information, see README.md*