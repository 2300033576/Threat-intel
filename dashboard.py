from flask import Flask, render_template
import requests

app = Flask(__name__)

# Fetch the latest CVEs from the CIRCL CVE Search API
def fetch_latest_cves():
    url = "https://cve.circl.lu/api/last/6"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()  # Return the JSON data
    else:
        return None