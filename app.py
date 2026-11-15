import os
from flask import Flask, request, render_template_string
import requests
from urllib.parse import urljoin

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Server'] = 'SecureScanner/2.0'
    return response

def run_advanced_scan(target):
    results = []
    if not target.startswith('http'):
        target = 'https://' + target
        
    results.append(f"[*] Starting Deep Audit on: {target}")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecureScanner/2.0"}
    
    try:
        response = requests.get(target, headers=headers, timeout=10)
        results.append(f"[+] Target is online. Status: {response.status_code}")
        
        # 1. Security Headers
        results.append("--- Security Headers ---")
        sec_headers = ['Strict-Transport-Security', 'X-Frame-Options', 'Content-Security-Policy']
        for h in sec_headers:
            if h not in response.headers:
                results.append(f"[-] MISSING: {h}")
            else:
                results.append(f"[+] SECURE: {h} is present.")
                
        # 2. Exposed Files
        results.append("--- Exposed Files ---")
        files = ['.env', '.git/config', 'config.php', 'database.sql', 'backup.zip']
        for f in files:
            f_url = urljoin(target, f)
            try:
                res = requests.get(f_url, headers=headers, timeout=5)
                if res.status_code == 200:
                    content = res.text.lower()
                    if f == '.env' and ('db_password' in content): results.append(f"[!!!] CRITICAL: Exposed .env at {f_url}")
                    elif f == 'database.sql' and ('insert into' in content): results.append(f"[!!!] CRITICAL: Exposed SQL at {f_url}")
                    else: results.append(f"[+] Safe: {f}")
            except: pass
            
        # 3. DIRECTORY TRAVERSAL CHECK (Path Traversal)
        # We test if we can read the /etc/passwd file (Linux) or win.ini (Windows)
        results.append("--- Directory Traversal Test ---")
        payloads = ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "..\\..\\..\\..\\windows\\win.ini"]
        traversal_found = False
        
        for payload in payloads:
            test_url = urljoin(target, f"?file={payload}")
            try:
                res = requests.get(test_url, headers=headers, timeout=5)
                # If we see "root:x:" or "[extensions]" in the response, we can read system files!
                if "root:x:" in res.text or "[extensions]" in res.text:
                    results.append(f"[!!!] CRITICAL: Directory Traversal found via {test_url}")
                    traversal_found = True
            except: pass
            
        if not traversal_found:
            results.append("[+] SECURE: No obvious Directory Traversal found.")

        # 4. SQL INJECTION CHECK (Error-Based)
        # We append a single quote to the URL to force a database error
        results.append("--- SQL Injection Test ---")
        sqli_payloads = ["'", "\"", "' OR '1'='1"]
        sql_found = False
        
        for payload in sqli_payloads:
            test_url = urljoin(target, f"?id={payload}")
            try:
                res = requests.get(test_url, headers=headers, timeout=5)
                # Database errors usually contain these keywords
                error_keywords = ["SQL syntax", "mysql_fetch", "ORA-01756", "SQLite/JDBCDriver", "PostgreSQL query failed"]
                for keyword in error_keywords:
                    if keyword.lower() in res.text.lower():
                        results.append(f"[!!!] CRITICAL: SQL Injection found via {test_url}")
                        sql_found = True
                        break
            except: pass
            
        if not sql_found:
            results.append("[+] SECURE: No obvious SQL errors detected.")
                
    except Exception as e:
        results.append(f"[-] Error scanning target: {e}")

    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    target = ""
    
    if request.method == 'POST':
        target = request.form.get('url')
        if target:
            results = run_advanced_scan(target)

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Deep Vulnerability Scanner</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; padding: 20px; background: #f4f7f6; color: #333; }
            h2 { color: #004085; }
            input[type="text"] { width: 70%; max-width: 400px; padding: 12px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px; }
            button { padding: 12px 24px; background: #004085; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
            .results-container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border: 1px solid #ddd; margin-top: 20px; }
            ul { list-style-type: none; padding: 0; }
            li { padding: 8px 0; border-bottom: 1px solid #eee; font-family: monospace; font-size: 14px; }
            .critical { color: #d9534f; font-weight: bold; }
            .safe { color: #5cb85c; }
            .info { color: #5bc0de; }
        </style>
    </head>
    <body>
        <h2>🛡️ Deep Vulnerability Scanner</h2>
        <form method="POST">
            <input type="text" name="url" placeholder="Enter target URL" value="{{ target }}" required>
            <button type="submit">Start Deep Scan</button>
        </form>
        
        {% if results %}
        <div class="results-container">
            <h3>Scan Results for: {{ target }}</h3>
            <ul>
            {% for res in results %}
                {% if "[!!!]" in res or "[-]" in res %}<li class="critical">{{ res }}</li>
                {% elif "[+]" in res %}<li class="safe">{{ res }}</li>
                {% else %}<li class="info">{{ res }}</li>{% endif %}
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
