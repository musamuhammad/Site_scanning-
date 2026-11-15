import os
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
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Server'] = 'SecureScanner/1.0'
    return response

# ==========================================
# 🔍 ADVANCED SCANNER ENGINE
# ==========================================
def run_advanced_scan(target):
    results = []
    if not target.startswith('http'):
        target = 'https://' + target
        
    results.append(f"[*] Starting Advanced Audit on: {target}")
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecureScanner/1.0"}
    
    try:
        # 1. Basic Connection & Server Info
        response = requests.get(target, headers=headers, timeout=10, verify=True)
        results.append(f"[+] Target is online. Status: {response.status_code}")
        
        server_header = response.headers.get('Server', 'Hidden')
        results.append(f"[*] Server Signature: {server_header}")
        if server_header in ['Apache', 'nginx', 'IIS', 'Unknown']:
            results.append(f"[!] INFO LEAK: Server is broadcasting its software version ({server_header})")
        
        # 2. Security Headers Check
        results.append("--- Security Headers ---")
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
                
        # 3. Advanced Exposed Files (Content-Based Validation)
        results.append("--- Exposed Files & Open Directories ---")
        files_to_check = {
            '.env': 'Environment variables (Passwords)',
            '.git/config': 'Git repository config',
            'config.php': 'PHP Config file',
            'database.sql': 'Raw SQL database dump',
            'backup.zip': 'Compressed site backup',
            'admin/': 'Admin panel directory',
            'backup/': 'Backup directory'
        }
        
        for f, description in files_to_check.items():
            f_url = urljoin(target, f)
            try:
                res = requests.get(f_url, headers=headers, timeout=5, verify=True)
                is_vulnerable = False
                
                # Professional Check: Verify the actual content
                if res.status_code == 200:
                    content = res.text.lower()
                    
                    # 1. .env files must contain environment variables
                    if f == '.env' and ('app_key=' in content or 'db_password=' in content or 'db_host=' in content):
                        is_vulnerable = True
                    
                    # 2. SQL files must contain SQL syntax
                    elif f == 'database.sql' and ('insert into' in content or 'create table' in content):
                        is_vulnerable = True
                    
                    # 3. Open directories must show an "Index of /" page
                    elif f.endswith('/') and ('index of /' in content):
                        is_vulnerable = True
                        
                    # 4. Real files (zip, php, config) should NOT be standard HTML pages
                    elif f in ['config.php', 'backup.zip', '.git/config']:
                        if '<html' not in content and '<!doctype html' not in content and len(content) > 10:
                            is_vulnerable = True

                if is_vulnerable:
                    results.append(f"[!!!] CRITICAL: Exposed {description} at {f_url}")
                else:
                    results.append(f"[+] Safe: {f} (Custom 404 or Protected)")
                    
            except requests.exceptions.Timeout:
                results.append(f"[!] Timeout checking: {f}")
            except Exception:
                results.append(f"[!] Error checking: {f}")
                
    except requests.exceptions.SSLError:
        results.append("[-] SSL Error: The target has an invalid or expired SSL certificate.")
    except Exception as e:
        results.append(f"[-] Error scanning target: {e}")

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
            results = run_advanced_scan(target)

    # The HTML UI with inline CSS for a professional look
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Scanner</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 20px; background: #f4f7f6; color: #333; }
            h2 { color: #004085; }
            .form-container { margin-bottom: 20px; }
            input[type="text"] { width: 70%; max-width: 400px; padding: 12px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px; }
            button { padding: 12px 24px; background: #004085; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
            button:hover { background: #002752; }
            .results-container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border: 1px solid #ddd; margin-top: 20px; }
            ul { list-style-type: none; padding: 0; }
            li { padding: 8px 0; border-bottom: 1px solid #eee; font-family: monospace; font-size: 14px; }
            li:last-child { border-bottom: none; }
            .critical { color: #d9534f; font-weight: bold; }
            .warning { color: #f0ad4e; font-weight: bold; }
            .safe { color: #5cb85c; }
            .info { color: #5bc0de; }
        </style>
    </head>
    <body>
        <h2>☁️ Advanced Cloud Vulnerability Scanner</h2>
        <div class="form-container">
            <form method="POST">
                <input type="text" name="url" placeholder="Enter target URL (e.g., https://example.com)" value="{{ target }}" required>
                <button type="submit">Scan Now</button>
            </form>
        </div>
        
        {% if results %}
        <div class="results-container">
            <h3>Scan Results for: {{ target }}</h3>
            <ul>
            {% for res in results %}
                {% if "[!!!]" in res or "[-]" in res %}
                    <li class="critical">{{ res }}</li>
                {% elif "[!]" in res %}
                    <li class="warning">{{ res }}</li>
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
