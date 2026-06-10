from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import joblib
import numpy as np
import requests
import json
import csv
import io
from datetime import datetime
from feature_extractor import extract_safe_features, get_redirect_info, get_threat_intelligence
import os
from supabase import create_client, Client

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ---------- Supabase Setup ----------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY environment variables must be set.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------- Supabase DB Helpers ----------
def trim_old_scans():
    """Keep only the most recent 100 scans, delete the rest."""
    response = (
        supabase.table("scans")
        .select("id")
        .order("timestamp", desc=True)
        .limit(1)
        .offset(100)
        .execute()
    )
    if response.data:
        cutoff_id = response.data[0]["id"]
        supabase.table("scans").delete().lte("id", cutoff_id).execute()

def save_scan(url, ml_pred, ml_conf, urlhaus_bad, verdict, redirect_count, proba, threat_info):
    """Insert a scan record into Supabase."""
    data = {
        "url": url,
        "timestamp": datetime.now().isoformat() + "Z",
        "ml_prediction": int(ml_pred),
        "ml_confidence": ml_conf,
        "urlhaus_malicious": bool(urlhaus_bad),
        "final_verdict": verdict,
        "redirect_count": redirect_count,
        "probabilities": json.dumps(proba),
        "threat_intelligence": json.dumps(threat_info)
    }
    response = supabase.table("scans").insert(data).execute()
    trim_old_scans()
    return response

def fetch_scans(limit=100):
    """Fetch recent scans from Supabase."""
    response = (
        supabase.table("scans")
        .select("*")
        .order("timestamp", desc=True)
        .limit(limit)
        .execute()
    )
    return response.data

def fetch_stats():
    """Fetch verdict distribution counts from Supabase."""
    response = supabase.table("scans").select("*").execute()
    rows = response.data
    stats = {}
    for row in rows:
        verdict = row["final_verdict"]
        stats[verdict] = stats.get(verdict, 0) + 1
    return stats

def fetch_all_for_export():
    """Fetch all scans for CSV export."""
    response = (
        supabase.table("scans")
        .select("*")
        .order("timestamp", desc=True)
        .execute()
    )
    return response.data

# ---------- Load Model ----------
try:
    model = joblib.load('phishguard_model_final.pkl')
    scaler = joblib.load('scaler_final.pkl')
    feature_names = joblib.load('feature_columns_final.pkl')
    print("Model loaded successfully")
except Exception as e:
    print(f"Error loading model: {e}")
    model = scaler = feature_names = None

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"

def query_urlhaus(url):
    try:
        r = requests.post(URLHAUS_API, data={'url': url}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return data.get('query_status') == 'ok'
    except:
        pass
    return False

# ---------- API Endpoints ----------
@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({'error': 'Model not loaded'}), 500

    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing url'}), 400

    url = data['url']
    features = extract_safe_features(url)

    try:
        redirect_count, self_redirect = get_redirect_info(url)
        features['NoOfURLRedirect'] = redirect_count
        features['NoOfSelfRedirect'] = self_redirect
    except:
        redirect_count = 0
        features['NoOfURLRedirect'] = 0
        features['NoOfSelfRedirect'] = 0

    # Run threat intelligence checks
    threat_info = get_threat_intelligence(url)

    try:
        feature_vector = [features[name] for name in feature_names]
    except KeyError as e:
        return jsonify({'error': f'Missing feature: {e}'}), 500

    X = np.array(feature_vector).reshape(1, -1)
    X_scaled = scaler.transform(X)
    pred = model.predict(X_scaled)[0]
    proba = model.predict_proba(X_scaled)[0].tolist()
    confidence = max(proba)

    urlhaus_bad = query_urlhaus(url)
    ml_is_phishing = (pred == 0)

    # Include threat intel signals in final verdict
    threat_flags = (
        threat_info.get('is_typosquatting', 0) or
        threat_info.get('is_newly_registered', 0) or
        threat_info.get('has_homoglyph', 0) or
        threat_info.get('has_punycode', 0) or
        not threat_info.get('dns_resolves', 1)
    )

    final = "phishing" if (urlhaus_bad or ml_is_phishing or threat_flags) else "legitimate"

    # Save to Supabase
    save_scan(url, pred, confidence, urlhaus_bad, final, redirect_count, proba, threat_info)

    return jsonify({
        'url': url,
        'ml_prediction': int(pred),
        'ml_confidence': confidence,
        'urlhaus_malicious': urlhaus_bad,
        'final_verdict': final,
        'probabilities': {'phishing': proba[0], 'legitimate': proba[1]},
        'redirect_count': redirect_count,
        'threat_intelligence': {
            # Obfuscation
            'decoded_url': threat_info.get('decoded_url'),
            'has_hex_encoding': bool(threat_info.get('has_hex_encoding')),
            'has_homoglyph': bool(threat_info.get('has_homoglyph')),
            'has_punycode': bool(threat_info.get('has_punycode')),
            'encoding_layers': threat_info.get('encoding_layers'),
            # DNS
            'dns_resolves': bool(threat_info.get('dns_resolves')),
            'has_mx_record': bool(threat_info.get('has_mx_record')),
            'ip_address': threat_info.get('ip_address'),
            # WHOIS
            'domain_age_days': threat_info.get('domain_age_days'),
            'is_newly_registered': bool(threat_info.get('is_newly_registered')),
            'expires_soon': bool(threat_info.get('expires_soon')),
            # Typosquatting
            'is_typosquatting': bool(threat_info.get('is_typosquatting')),
            'typosquatting_target': threat_info.get('typosquatting_target'),
            'typosquatting_score': threat_info.get('typosquatting_score'),
        }
    })

@app.route('/history', methods=['GET'])
def get_history():
    """Return all scans as JSON."""
    limit = request.args.get('limit', default=100, type=int)
    rows = fetch_scans(limit)
    scans = []
    for row in rows:
        scans.append({
            'id': row['id'],
            'url': row['url'],
            'timestamp': row['timestamp'],
            'ml_prediction': row['ml_prediction'],
            'ml_confidence': row['ml_confidence'],
            'urlhaus_malicious': row['urlhaus_malicious'],
            'final_verdict': row['final_verdict'],
            'redirect_count': row['redirect_count'],
            'probabilities': json.loads(row['probabilities']),
            'threat_intelligence': json.loads(row.get('threat_intelligence') or '{}')
        })
    return jsonify(scans)

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get risk distribution counts."""
    stats = fetch_stats()
    return jsonify(stats)

@app.route('/export', methods=['GET'])
def export_csv():
    """Export all scans as CSV."""
    rows = fetch_all_for_export()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['URL', 'Timestamp', 'Verdict', 'Confidence', 'URLhaus Malicious',
                     'Domain Age (days)', 'Is Typosquatting', 'Typosquatting Target',
                     'DNS Resolves', 'Has Homoglyph', 'Is Newly Registered'])
    for row in rows:
        ti = json.loads(row.get('threat_intelligence') or '{}')
        writer.writerow([
            row['url'],
            row['timestamp'],
            row['final_verdict'],
            row['ml_confidence'],
            row['urlhaus_malicious'],
            ti.get('domain_age_days', ''),
            ti.get('is_typosquatting', ''),
            ti.get('typosquatting_target', ''),
            ti.get('dns_resolves', ''),
            ti.get('has_homoglyph', ''),
            ti.get('is_newly_registered', ''),
        ])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='phishguard_report.csv'
    )

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)
