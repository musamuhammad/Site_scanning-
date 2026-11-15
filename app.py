import os
from flask import Flask, request, render_template_string
import requests
from urllib.parse import urljoin

app = Flask(__name__)

# --- ADVANCED SCANNER LOGIC ---
def run_advanced_scan(target):
    results = []
    if not target.startswith('http'):
        target = 'https://' + target
        
    results.append(f"[*] Starting Advanced Audit on: {target}")
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    try:
        # 1. Basic Connection Test
        response = requests.get(target, headers=headers, timeout=10)
        results.append(f"[+] Target is online. Status: {response.status_code}")
        
        # 2. Advanced Server Info Leak
        server_header = response.headers.get('Server', 'Unknown')
        results.append(f"[*] Server Signature: {server_header}")
        if "Apache" in server_header or "nginx" in server_header or "IIS" in server_header:
            results.append(f"[!] INFO LEAK: Server is broadcasting its software version ({server_header})")
        
        # 3. Security Headers Check
        results.append("--- Security Headers ---")
        sec_headers = ['Strict-Transport-Security', 'X-Frame-Options', 'Content-Security-Policy']
        for h in sec_headers:
            if h not in response.headers:
                results.append(f"[-] MISSING: {h}")
            else:
                results.append(f"[+] SECURE: {h} is present.")
                
        # 4. Advanced Exposed Files & Directories Check
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
                res = requests.get(f_url, headers=headers, timeout=5)
                
                # If it's a directory, it usually ends with a slash and returns 200
                if res.status_code == 200:
                    # Check if it's an open directory (contains "Index of /")
                    if "Index of /" in res.text:
                        results.append(f"[!!!] CRITICAL: OPEN DIRECTORY found at {f_url}")
                    # Check if it's a real file (not a custom 404 page)
                    elif "404" not in res.text and "Not Found" not in res.text and len(res.text) > 0:
                        results.append(f"[!!!] CRITICAL: Exposed {description} at {f_url}")
                    else:
                        results.append(f"[+] Safe: {f}")
                else:
                    results.append(f"[+] Safe: {f} (Status: {res.status_code})")
            except:
                results.append(f"[!] Timeout checking: {f}")
                
    except Exception as e:
        results.append(f"[-] Error scanning target: {e}")

    return results

# --- WEB INTERFACE ---
@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    target = ""
    
    if request.method == 'POST':
        target = request.form.get('url')
        results = run_advanced_scan(target)

    # The HTML UI
    html = """
    <html><body style="font-family: Arial; padding: 20px; background: #f4f7f6;">
    <h2>☁️ Advanced Cloud Vulnerability Scanner</h2>
    <form method="POST">
        <input type="text" name="url" placeholder="Enter target URL" style="width: 300px; padding: 10px;" value="{{ target }}" required>
        <button type="submit" style="padding: 10px 20px; background: #004085; color: white; border: none; border-radius: 4px;">Scan Now</button>
    </form>
    <br>
    <div style="background: white; padding: 20px; border-radius: 5px; border: 1px solid #ccc;">
    """
    
    if results:
        html += "<h3>Scan Results:</h3><ul>"
        for res in results:
            if "[!!!]" in res or "[-]" in res or "[!]" in res:
                html += f"<li style='color: red; font-weight: bold;'>{res}</li>"
            else:
                html += f"<li style='color: green;'>{res}</li>"
        html += "</ul>"
        
    html += "</div></body></html>"
    return render_template_string(html, results=results, target=target)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
