from flask import Flask, render_template, redirect, url_for, request, jsonify
from pymongo import MongoClient, errors
from datetime import datetime
from threat_analysis import get_virustotal_data

app = Flask(__name__)

# MongoDB Connection String (MongoDB Atlas)
client = MongoClient("mongodb+srv://admin:admin@threat-intel.mcmzs2n.mongodb.net/?retryWrites=true&w=majority&appName=Threat-intel")
db = client["threat_intel_db"]
collection = db["threats"]  

# Home redirects to index
@app.route('/')
def home():
    return redirect(url_for('index'))

# Dashboard page
@app.route('/dashboard')
def dashboard():
    import dashboard 
    from dashboard import fetch_latest_cves
    cve_data = fetch_latest_cves()
    print(cve_data)  # Debug print

    if cve_data:
        return render_template('dashboard.html', cves=cve_data)
    else:
        return "Failed to fetch CVEs from the API."

# Threat Feeds page
@app.route('/feeds')
def feeds():
    try:
        # Fetch latest threats from MongoDB
        threats = list(collection.find().sort("timestamp", -1))  # Sort by latest timestamp
        return render_template('feed.html', threats=threats)
    except errors.ConnectionFailure:
        return "MongoDB connection failed!", 500
    except Exception as e:
        return f"An error occurred: {e}", 500

# Fetch new threats
@app.route('/fetch')
def fetch():
    try:
        import fetcher  # Import your fetcher to fetch the latest threats
        fetcher.fetch_and_store()  # Run the fetch function
        return redirect(url_for('feeds'))
    except Exception as e:
        return f"An error occurred while fetching: {e}", 500

# Threat Analysis Page
@app.route('/threat_analysis', methods=['GET', 'POST'])
def threat_analysis_page():
    if request.method == 'GET':
        return render_template('threat_analysis.html', virustotal_data=None, error=None)

    if request.method == 'POST':
        ioc = request.form.get('ioc')

        if not ioc:
            return render_template('threat_analysis.html', error="No IOC provided.", virustotal_data=None)

        virustotal_data = get_virustotal_data(ioc)

        if 'error' not in virustotal_data:
            return render_template('threat_analysis.html', virustotal_data=virustotal_data, error=None)

        return render_template('threat_analysis.html', virustotal_data=None, error=virustotal_data.get("error"))

# Datetime formatting filter
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, int):
        return datetime.fromtimestamp(value).strftime(format)
    return value

# Index page
@app.route('/index')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=False)
