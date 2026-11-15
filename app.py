import os
from flask import Flask, request, render_template_string
import requests
from urllib.parse import urljoin

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def scan_website():
    results = []
    target = ""
    
    if request.method == 'POST':
        target = request.form.get('url')
        if not target.startswith('http'):
            target = 'https://' + target
            
        results.append(f"[*] Starting Audit on: {target}")
        
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            response = requests.get(target, headers=headers, timeout=10)
            results.append(f"[+] Target is online. Status: {response.status_code}")
            
            # Check Security Headers
            results.append("--- Security Headers ---")
            sec_headers = ['Strict-Transport-Security', 'X-Frame-Options', 'Content-Security-Policy']
            for h in sec_headers:
                if h not in response.headers:
                    results.append(f"[-] MISSING: {h}")
                else:
                    results.append(f"[+] SECURE: {h} is present.")
                    
            # Check Sensitive Files
            results.append("--- Sensitive Files ---")
            files = ['.env', '.git/config', 'config.php']
            for f in files:
                f_url = urljoin(target, f)
                try:
                    res = requests.get(f_url, timeout=5)
                    if res.status_code == 200 and "404" not in res.text:
                        results.append(f"[!!!] CRITICAL: Exposed file found: {f_url}")
                    else:
                        results.append(f"[+] Safe: {f}")
                except:
                    results.append(f"[!] Timeout checking: {f}")
                    
        except Exception as e:
            results.append(f"[-] Error scanning target: {e}")

    # The HTML Interface
    html = """
    <html><body style="font-family: Arial; padding: 20px; background: #f4f7f6;">
    <h2>☁️ Cloud Web Vulnerability Scanner</h2>
    <form method="POST">
        <input type="text" name="url" placeholder="Enter target URL" style="width: 300px; padding: 10px;" required>
        <button type="submit" style="padding: 10px 20px; background: #004085; color: white;">Scan Now</button>
    </form>
    <br>
    <div style="background: white; padding: 20px; border-radius: 5px; border: 1px solid #ccc;">
    """
    
    if results:
        html += "<h3>Scan Results:</h3><ul>"
        for res in results:
            if "[!!!]" in res or "[-]" in res:
                html += f"<li style='color: red; font-weight: bold;'>{res}</li>"
            else:
                html += f"<li style='color: green;'>{res}</li>"
        html += "</ul>"
        
    html += "</div></body></html>"
    return html

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
