import subprocess
import requests
import socket
import dns.resolver
import tldextract
import re
import time
import asyncio
import aiohttp
import aiodns
from urllib.parse import urlparse
from scanner import ultra_scan_domain
from shodan_search import search_subdomains
from config import *

def get_subfinder_subdomains(domain):
    subdomains = []
    try:
        subfinder_result = subprocess.run(
            ['subfinder', '-d', domain, '-silent', '-timeout', '5'],
            capture_output=True, text=True, timeout=120
        )
        if subfinder_result.returncode == 0:
            subdomains = subfinder_result.stdout.splitlines()
    except Exception as e:
        print(f"Subfinder error: {e}")
    return subdomains

def get_crtsh_subdomains(domain):
    subdomains = []
    try:
        crtsh_url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(crtsh_url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for item in data:
                name = item['name_value']
                if '\n' in name:
                    for subdomain in name.split('\n'):
                        if domain in subdomain and '*' not in subdomain:
                            subdomains.append(subdomain.strip())
                else:
                    if domain in name and '*' not in name:
                        subdomains.append(name.strip())
    except Exception as e:
        print(f"CRT.sh error: {e}")
    return subdomains

def get_shodan_subdomains(domain):
    return search_subdomains(domain)

def get_additional_sources(domain):
    subdomains = []
    # Additional passive sources
    sources = [
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    ]
    
    for source in sources:
        try:
            response = requests.get(source, timeout=10)
            if response.status_code == 200:
                # Simple pattern matching for subdomains
                found = re.findall(r'([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain) + r')', response.text)
                subdomains.extend(found)
        except:
            continue
    
    return list(set(subdomains))

async def get_subdomain_details_async(subdomain):
    """Get detailed information for a subdomain using async methods"""
    try:
        # DNS resolution
        resolver = aiodns.DNSResolver()
        try:
            result = await resolver.query(subdomain, 'A')
            ip = result[0].host if result else None
        except:
            ip = None
        
        # HTTP checking
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            http_status, https_status, server, cloudflare = None, None, '', False
            
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    async with session.get(url, ssl=False, allow_redirects=True) as response:
                        if protocol == 'https':
                            https_status = response.status
                        else:
                            http_status = response.status
                        
                        server = response.headers.get('server', '')
                        cloudflare = 'cf-ray' in response.headers
                        break  # Prefer HTTPS
                except:
                    continue
        
        return {
            'subdomain': subdomain,
            'ip': ip,
            'http_status': http_status,
            'https_status': https_status,
            'server': server,
            'cloudflare': 'Enabled' if cloudflare else 'Disabled',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    except:
        return {
            'subdomain': subdomain,
            'ip': None,
            'http_status': None,
            'https_status': None,
            'server': '',
            'cloudflare': 'Unknown',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }

def get_subdomain_details_batch(subdomains):
    """Get details for multiple subdomains efficiently"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    async def process_batch():
        tasks = [get_subdomain_details_async(sub) for sub in subdomains]
        return await asyncio.gather(*tasks)
    
    results = loop.run_until_complete(process_batch())
    loop.close()
    return results

def resolve_dns(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None
