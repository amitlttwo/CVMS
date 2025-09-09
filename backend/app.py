from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import subprocess
import requests
import shodan_search
import subdomain_utils
import scanner
import threading
import os
import json
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__, static_folder='static')
CORS(app)

# Store scan results in memory (in production, use a database)
scan_results = {}
executor = ThreadPoolExecutor(max_workers=5)

@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)

@app.route('/api/enumerate', methods=['POST'])
def enumerate_subdomains():
    data = request.get_json()
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    # Generate a unique ID for this scan
    scan_id = domain.replace('.', '_') + '_' + str(int(time.time()))
    scan_results[scan_id] = {'status': 'processing', 'subdomains': [], 'progress': 0}
    
    # Start the scan in a separate thread to avoid blocking
    thread = threading.Thread(target=run_scan, args=(domain, scan_id))
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'status': 'processing'})

def run_scan(domain, scan_id):
    try:
        # Phase 1: Passive enumeration (fast)
        scan_results[scan_id]['progress'] = 10
        scan_results[scan_id]['status'] = 'passive_enumeration'
        
        passive_subdomains = []
        
        # Use subfinder (if installed)
        subfinder_domains = subdomain_utils.get_subfinder_subdomains(domain)
        passive_subdomains.extend(subfinder_domains)
        
        # Use crt.sh
        crtsh_domains = subdomain_utils.get_crtsh_subdomains(domain)
        passive_subdomains.extend(crtsh_domains)
        
        # Use Shodan
        shodan_domains = subdomain_utils.get_shodan_subdomains(domain)
        passive_subdomains.extend(shodan_domains)
        
        # Use additional sources
        additional_domains = subdomain_utils.get_additional_sources(domain)
        passive_subdomains.extend(additional_domains)
        
        # Remove duplicates and invalid domains
        valid_domains = []
        for d in passive_subdomains:
            if d.endswith(domain) and d != domain and '*' not in d:
                valid_domains.append(d.lower())
        
        # Remove duplicates
        valid_domains = list(set(valid_domains))
        
        scan_results[scan_id]['progress'] = 40
        scan_results[scan_id]['status'] = 'active_enumeration'
        
        # Phase 2: Active enumeration (bruteforce)
        if len(valid_domains) < 50:  # Only bruteforce if we didn't find many
            try:
                # Run ultra fast async scan
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                bruteforce_results = loop.run_until_complete(scanner.ultra_scan_domain(domain))
                loop.close()
                
                # Merge results
                bruteforce_subs = [item['subdomain'] for item in bruteforce_results]
                valid_domains = list(set(valid_domains + bruteforce_subs))
            except Exception as e:
                print(f"Bruteforce scan error: {e}")
        
        scan_results[scan_id]['progress'] = 70
        scan_results[scan_id]['status'] = 'verification'
        
        # Phase 3: Verification and detail collection
        detailed_subdomains = subdomain_utils.get_subdomain_details_batch(valid_domains)
        
        # Update scan results
        scan_results[scan_id] = {
            'status': 'completed', 
            'subdomains': detailed_subdomains,
            'count': len(detailed_subdomains),
            'progress': 100
        }
    
    except Exception as e:
        scan_results[scan_id] = {
            'status': 'error',
            'error': str(e)
        }

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/api/export/<scan_id>/<format_type>', methods=['GET'])
def export_results(scan_id, format_type):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    if scan_results[scan_id]['status'] != 'completed':
        return jsonify({'error': 'Scan not completed yet'}), 400
    
    subdomains = scan_results[scan_id]['subdomains']
    
    if format_type == 'json':
        return jsonify({
            'domain': scan_id.split('_')[0],
            'subdomains': subdomains,
            'count': len(subdomains),
            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    elif format_type == 'txt':
        output = f"# Subdomain Enumeration Results\n"
        output += f"# Domain: {scan_id.split('_')[0]}\n"
        output += f"# Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        output += f"# Total subdomains: {len(subdomains)}\n\n"
        
        for sub in subdomains:
            output += f"{sub['subdomain']}\n"
            if sub['ip']:
                output += f"  IP: {sub['ip']}\n"
            if sub['http_status']:
                output += f"  HTTP: {sub['http_status']}\n"
            if sub['https_status']:
                output += f"  HTTPS: {sub['https_status']}\n"
            if sub['server']:
                output += f"  Server: {sub['server']}\n"
            if sub['cloudflare']:
                output += f"  Cloudflare: {sub['cloudflare']}\n"
            output += "\n"
        
        return output, 200, {'Content-Type': 'text/plain', 
                            'Content-Disposition': f'attachment; filename=subdomains_{scan_id.split("_")[0]}.txt'}
    
    else:
        return jsonify({'error': 'Invalid format type'}), 400

if __name__ == '__main__':
    # Create static directory if it doesn't exist
    if not os.path.exists('static'):
        os.makedirs('static')
    
    # Create wordlists directory if it doesn't exist
    wordlist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlists')
    if not os.path.exists(wordlist_dir):
        os.makedirs(wordlist_dir)
    
    app.run(debug=True, host='0.0.0.0', port=5051, threaded=True)
