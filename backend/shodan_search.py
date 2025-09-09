import shodan
from config import SHODAN_API_KEY

def search_subdomains(domain):
    api = shodan.Shodan(SHODAN_API_KEY)
    subdomains = []
    
    try:
        # Search Shodan with multiple queries
        queries = [
            f"hostname:{domain}",
            f"ssl:{domain}",
        ]
        
        for query in queries:
            try:
                results = api.search(query)
                for result in results['matches']:
                    if 'hostnames' in result:
                        for hostname in result['hostnames']:
                            if hostname.endswith(domain) and '*' not in hostname:
                                subdomains.append(hostname)
            except Exception as e:
                print(f"Shodan query error for {query}: {e}")
                continue
    
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
    except Exception as e:
        print(f"Unexpected error in Shodan search: {e}")
    
    return list(set(subdomains))
