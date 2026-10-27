# Threat-intel

A small threat intelligence web app I built with Flask as a DevSecOps project. It pulls recent IOCs from ThreatFox, shows the latest CVEs, and lets you look up an IP, domain, URL or hash on VirusTotal. There's also a GitHub Actions pipeline that builds the Docker image and scans it with Trivy.

## What it does

- **Threat feeds** – fetches IOCs from the last 24 hours using the ThreatFox (abuse.ch) API and saves them to MongoDB Atlas
- **CVE dashboard** – shows the latest CVEs from the CIRCL CVE API
- **IOC lookup** – checks an IOC against VirusTotal and shows reputation, detection counts, categories, DNS records and WHOIS info
- **CI pipeline** – on every push to main, the Docker image is built and scanned for high and critical vulnerabilities

## Built with

Python, Flask, MongoDB Atlas, VirusTotal API, ThreatFox API, CIRCL CVE API, Docker, GitHub Actions, Trivy

## Files

```
app.py              main Flask app and routes
fetcher.py          gets IOCs from ThreatFox and stores them in MongoDB
threat_analysis.py  VirusTotal and abuse.ch lookups
dashboard.py        gets latest CVEs from CIRCL
templates/          HTML pages
Dockerfile
.github/workflows/main.yml
```

## Running it locally

You'll need a MongoDB Atlas cluster, a VirusTotal API key and a ThreatFox auth key.

```bash
git clone https://github.com/2300033576/Threat-intel.git
cd Threat-intel
pip install -r requirements.txt
```

Set your keys as environment variables:

```bash
export MONGO_URI="your_mongodb_uri"
export VIRUSTOTAL_API_KEY="your_key"
export ABUSE_CH_API_KEY="your_key"
```

Then run:

```bash
python app.py
```

and open http://127.0.0.1:5000

To load threat data, either click fetch in the app (`/fetch`) or run `python fetcher.py`.

## Running with Docker

```bash
docker build -t threat-intel .
docker run -p 5000:5000 -e MONGO_URI="..." -e VIRUSTOTAL_API_KEY="..." -e ABUSE_CH_API_KEY="..." threat-intel
```

## Pages

- `/index` – home
- `/dashboard` – latest CVEs
- `/feeds` – stored threats
- `/fetch` – pull new threats from ThreatFox
- `/threat_analysis` – IOC lookup

## Pipeline

The workflow builds the image and runs Trivy against it. Right now it only reports vulnerabilities and doesn't fail the build.

## Things I want to add

- fail the build on critical vulnerabilities
- add Bandit for code scanning
- remove duplicate IOCs in the database
- charts on the dashboard
