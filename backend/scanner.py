import asyncio
import aiohttp
import aiodns
import socket
import httpx
from tqdm import tqdm
import re
import time
from config import *

class UltraFastScanner:
    def __init__(self, domain):
        self.domain = domain
        self.resolver = aiodns.DNSResolver()
        self.found_subdomains = set()
        self.session = None
        self.semaphore = asyncio.Semaphore(MAX_THREADS)
        
    async def init_session(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT))
        
    async def close_session(self):
        if self.session:
            await self.session.close()
            
    async def resolve_dns_async(self, subdomain):
        try:
            async with self.semaphore:
                result = await self.resolver.query(subdomain, 'A')
                return subdomain, result[0].host if result else None
        except:
            return subdomain, None
            
    async def check_http_async(self, url):
        try:
            async with self.session.get(url, ssl=False, allow_redirects=True) as response:
                return {
                    'status': response.status,
                    'headers': dict(response.headers),
                    'server': response.headers.get('server', ''),
                    'cloudflare': 'cf-ray' in response.headers
                }
        except:
            return None
            
    async def mass_dns_resolve(self, subdomains):
        """Resolve multiple subdomains concurrently"""
        tasks = [self.resolve_dns_async(f"{sub}.{self.domain}") for sub in subdomains]
        results = await asyncio.gather(*tasks)
        return {sub: ip for sub, ip in results if ip}
        
    async def mass_http_check(self, subdomains):
        """Check HTTP/HTTPS for multiple subdomains concurrently"""
        results = {}
        for protocol in ['http', 'https']:
            tasks = []
            for sub in subdomains:
                url = f"{protocol}://{sub}.{self.domain}"
                tasks.append(self.check_http_async(url))
                
            http_results = await asyncio.gather(*tasks)
            for sub, result in zip(subdomains, http_results):
                if sub not in results:
                    results[sub] = {}
                results[sub][protocol] = result
        return results

def load_wordlist():
    """Load subdomain wordlist"""
    wordlist = []
    try:
        with open(SUBDOMAIN_WORDLIST, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        # Fallback to common subdomains
        wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'secure', 
            'news', 'ns1', 'ns2', 'ns3', 'ns4', 'test', 'docs', 'api', 'admin',
            'blog', 'cloud', 'dev', 'development', 'forum', 'help', 'image', 'img',
            'login', 'm', 'mobile', 'my', 'new', 'old', 'owa', 'portal', 'proxy',
            'shop', 'ssl', 'support', 'web', 'webdisk', 'webadmin', 'autodiscover',
            'email', 'webmail', 'dashboard', 'api', 'vpn', 'ftp', 'shop', 'blog',
            'news', 'forum', 'wiki', 'download', 'uploads', 'cdn', 'static', 'assets',
            'media', 'files', 'images', 'img', 'js', 'css', 'cdn', 'cache', 'storage',
            'app', 'apps', 'application', 'demo', 'stage', 'staging', 'prod', 'production',
            'test', 'testing', 'dev', 'development', 'beta', 'alpha', 'live', 'status',
            'monitor', 'monitoring', 'stats', 'statistics', 'analytics', 'metrics',
            'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'mongodb', 'elastic',
            'search', 'query', 'api', 'rest', 'graphql', 'soap', 'xml', 'json', 'rpc',
            'auth', 'authentication', 'login', 'signin', 'signup', 'register', 'account',
            'user', 'users', 'profile', 'profiles', 'admin', 'administrator', 'root',
            'system', 'sys', 'server', 'servers', 'service', 'services', 'backend',
            'frontend', 'client', 'clients', 'customer', 'customers', 'partner', 'partners'
        ]
    return wordlist

async def ultra_scan_domain(domain):
    """Main scanning function"""
    scanner = UltraFastScanner(domain)
    await scanner.init_session()
    
    # Load wordlist
    subdomains = load_wordlist()
    
    # Step 1: Mass DNS resolution
    print(f"Resolving {len(subdomains)} subdomains...")
    dns_results = await scanner.mass_dns_resolve(subdomains)
    
    # Step 2: HTTP checking for resolved subdomains
    resolved_subs = list(dns_results.keys())
    print(f"Checking HTTP for {len(resolved_subs)} resolved subdomains...")
    http_results = await scanner.mass_http_check(resolved_subs)
    
    # Prepare final results
    results = []
    for sub in resolved_subs:
        full_domain = f"{sub}.{domain}"
        http_data = http_results.get(sub, {})
        
        results.append({
            'subdomain': full_domain,
            'ip': dns_results[sub],
            'http_status': http_data.get('http', {}).get('status'),
            'https_status': http_data.get('https', {}).get('status'),
            'server': http_data.get('https', {}).get('server') or http_data.get('http', {}).get('server'),
            'cloudflare': 'Enabled' if http_data.get('https', {}).get('cloudflare') or http_data.get('http', {}).get('cloudflare') else 'Disabled',
            'title': '',  # Will be extracted later
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    await scanner.close_session()
    return results
