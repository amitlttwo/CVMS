# Configuration settings
import os

# API Keys
SHODAN_API_KEY = "eX6jFqSUP3gSKA2DEGzhiTDlYYNxc1i6"

# Performance settings
MAX_THREADS = 50
MAX_PROCESSES = 10
HTTP_TIMEOUT = 5
DNS_TIMEOUT = 3

# Wordlist paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDLIST_DIR = os.path.join(BASE_DIR, 'wordlists')
SUBDOMAIN_WORDLIST = os.path.join(WORDLIST_DIR, 'subdomains.txt')

# Scan options
ENABLE_BRUTEFORCE = True
ENABLE_PASSIVE = True
ENABLE_ACTIVE = True
ENABLE_HTTP_SCAN = True

# Output options
OUTPUT_DIR = os.path.join(BASE_DIR, 'results')
