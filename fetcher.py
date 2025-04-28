import requests
from pymongo import MongoClient
from datetime import datetime

# Replace these with your MongoDB Atlas credentials
MONGO_URI = "mongodb+srv://admin:admin@threat-intel.mcmzs2n.mongodb.net/?retryWrites=true&w=majority&appName=Threat-intel"

def fetch_and_store():
    # MongoDB Atlas Connection
    client = MongoClient(MONGO_URI)
    db = client["threat_intel_db"]
    collection = db["threats"]

    # ThreatFox Feed (Abuse.ch) - JSON
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "Auth-Key": 'd552bcc7216a945958ddbc2c24cedf4b5fff06a38e839978'  # Your Auth Key
    }
    payload = {
        "query": "get_iocs", 
        "days": 1  # Fetch data from the last 1 day
    }
    
    response = requests.post(url, json=payload, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        
        # Check if successful
        if data.get("query_status") == "ok":
            for threat in data.get("data", []):
                doc = {
                    "ioc": threat.get("ioc"),
                    "threat_type": threat.get("threat_type"),
                    "malware_family": threat.get("malware_family"),
                    "first_seen": threat.get("first_seen"),
                    "confidence_level": threat.get("confidence_level"),
                    "timestamp": datetime.now()
                }
                collection.insert_one(doc)
            print(f"Inserted {len(data.get('data', []))} threats into MongoDB!")
        else:
            print("Failed to fetch data:", data.get("query_status"))
    else:
        print("Error connecting to ThreatFox API")

if __name__ == "__main__":
    fetch_and_store()
