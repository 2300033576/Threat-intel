import requests
import base64
from flask import Flask, jsonify, request

app = Flask(__name__)

# Replace these with your actual API keys
VIRUS_TOTAL_API_KEY = "1fb6b07defc69c4e94418a5caf094c1d2e2af956af68e921d4e6b98795dfe9fb"
ABUSE_CH_API_KEY = "d552bcc7216a945958ddbc2c24cedf4b5fff06a38e839978"

# Helper function to query VirusTotal API
def get_virustotal_data(ioc):
    # Clean the IOC if it has a port (IP:Port)
    if ':' in ioc and ioc.count('.') == 3:
        ioc = ioc.split(':')[0]  # Only keep the IP, discard the port
    
    # Check the type of IOC (MD5, SHA1, SHA256, IP, domain, or URL)
    if ioc.endswith(('md5', 'sha1', 'sha256')):
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    elif ioc.count('.') == 3:  # Check if it looks like an IP address (simple check)
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc.startswith(('http://', 'https://')):  # Check if it's a URL
        # Encode URL to base64 as VirusTotal requires base64 for URLs
        encoded_url = base64.urlsafe_b64encode(ioc.encode('utf-8')).decode('utf-8').strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    elif '.' in ioc:  # Likely a domain
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    else:
        return {"error": "Invalid IOC format."}
    
    headers = {
        "x-apikey": VIRUS_TOTAL_API_KEY
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        return extract_virustotal_info(data)
    else:
        return {"error": "Unable to fetch data from VirusTotal."}


# Function to extract specific fields from the VirusTotal JSON response
def extract_virustotal_info(data):
    domain_info = data.get('data', {})
    result = {}

    # Extract the required information
    result["id"] = domain_info.get("id", "N/A")
    result["type"] = domain_info.get("type", "N/A")
    result["registrar"] = domain_info.get("attributes", {}).get("registrar", "N/A")
    result["creation_date"] = domain_info.get("attributes", {}).get("creation_date", "N/A")
    result["expiration_date"] = domain_info.get("attributes", {}).get("expiration_date", "N/A")
    
    last_analysis = domain_info.get("attributes", {}).get("last_analysis_stats", {})
    result["last_analysis_stats"] = last_analysis
    
    result["reputation"] = domain_info.get("attributes", {}).get("reputation", "N/A")
    
    categories = domain_info.get("attributes", {}).get("categories", {})
    result["categories"] = categories
    
    popularity_ranks = domain_info.get("attributes", {}).get("popularity_ranks", {})
    result["popularity_ranks"] = popularity_ranks
    
    last_dns_records = domain_info.get("attributes", {}).get("last_dns_records", [])
    result["last_dns_records"] = last_dns_records
    
    last_https_certificate = domain_info.get("attributes", {}).get("last_https_certificate", {})
    result["last_https_certificate"] = last_https_certificate
    
    whois = domain_info.get("attributes", {}).get("whois", "N/A")
    result["whois"] = whois

    return result

# Helper function to query Abuse.ch API for a specific IOC
def get_abuse_ch_data(ioc):
    url = "https://threatfox-api.abuse.ch/api/v1/"
    
    headers = {
        "Auth-Key": ABUSE_CH_API_KEY
    }
    
    payload = {
        "query": "search_ioc",  # Use search query for a specific IOC
        "ioc": ioc  # The IOC we want to search for
    }
    
    response = requests.post(url, json=payload, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": "Unable to fetch data from Abuse.ch."}