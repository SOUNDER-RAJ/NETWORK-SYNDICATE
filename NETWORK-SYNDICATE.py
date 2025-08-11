# Install required packages
!pip install scapy==2.5.0 cryptography==38.0.4 pandas==2.0.3 numpy==1.25.2 matplotlib==3.7.2 seaborn==0.12.2 -q
!pip install fpdf==1.7.2 scikit-learn==1.3.0 nest_asyncio==1.5.8 dpkt==1.9.8 pyclamd==0.4.0 -q
!pip install yara-python==4.5.1 requests==2.31.0 tensorflow==2.15.0 geocoder==1.38.1 qrcode==7.4.2 -q
!pip install xgboost==2.0.3 lightgbm==4.3.0 tshark==0.7.2 pypsd==0.2.1 pyod==1.1.3 -q
!apt-get update -q && apt-get install -y clamav tshark nikto -q && freshclam -q

# All imports (moved before usage to avoid NameError)
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import scapy  # Import scapy explicitly to access __version__
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, ICMP, ARP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from collections import Counter, defaultdict
from fpdf import FPDF
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.decomposition import PCA
import socket
from google.colab import files
import nest_asyncio
import dpkt
import hashlib
import re
import pyclamd
import yara
import requests
import time
import subprocess
import math
import tensorflow as tf
from tensorflow.keras import layers
import geocoder
import qrcode
from multiprocessing import Pool
import threading
import xgboost as xgb
import lightgbm as lgb
import binascii
import struct
import io
from datetime import datetime, timedelta
from joblib import Parallel, delayed
import cryptography  # Import cryptography explicitly for version check

# Verify critical library versions (now after imports)
print(f"Scapy version: {scapy.__version__}")
print(f"Cryptography version: {cryptography.__version__}")

# Check if pyod is available
try:
    from pyod.models.ecod import ECOD
    PYOD_AVAILABLE = True
except ImportError:
    PYOD_AVAILABLE = False
    print("Note: pyod library not available. Using alternative anomaly detection methods.")

nest_asyncio.apply()

# Caches for efficiency
ip_cache = {}
dns_cache = {}
geo_cache = {}
threat_intel_cache = {}
session_cache = {}

class SnortAlert:
    def __init__(self, sid, message, classification, priority, timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
                 ttl=None, payload=None, pkt_id=None, pkt_len=None, tos=None, flags=None, tcp_options=None,
                 confidence=0.0, entropy=0.0, anomaly_score=0.0, threat_level="Low", packet_hash=None):
        self.sid = sid
        self.message = message
        self.classification = classification
        self.priority = priority
        self.timestamp = pd.to_datetime(timestamp, unit='s')
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.ttl = ttl
        self.payload = payload
        self.pkt_id = pkt_id
        self.pkt_len = pkt_len
        self.tos = tos
        self.flags = flags
        self.tcp_options = tcp_options
        self.confidence = confidence
        self.entropy = entropy
        self.anomaly_score = anomaly_score
        self.threat_level = threat_level
        self.packet_hash = packet_hash

MALWARE_SIGNATURES = {
    "Mirai": ["GET / HTTP/1.1", "User-Agent: Mirai", b"\x00\x01"],
    "Zeus": ["POST /gate.php", "C&C handshake", b"\xFF\xEE"],
    "WannaCry": ["SMBv1", "445", b"\xFE\xED"],
    "Emotet": ["powershell", "I apologize", b"\xDE\xAD"],
    "Qbot": ["random_file_name", "anti-analysis", b"\xBE\xEF"],
    "Conficker": ["445/tcp", "rpc", b"\xCA\xFE"],
    "NotPetya": ["PsExec", "EternalBlue", b"\xBA\xBE"],
    "Generic Executable": [b"\x4D\x5A"],
    "SQL Slammer": ["1434/udp", "buffer overflow"],
    "Code Red": ["GET /default.ida", "NNNNNNNN"],
    "Nimda": [".exe", "admin.dll"],
    "SQL Injection": ["' OR 1=1", "SELECT * FROM"],
    "TrickBot": ["banking", "inject", b"\xAB\xCD"],
    "Ramnit": ["worm", "445", b"\xEF\xBE"],
}

YARA_RULES = """
rule MiraiBotnet { strings: $a = "Mirai" nocase $b = "GET / HTTP/1.1" $c = {00 01} condition: any of them }
rule WannaCry { strings: $a = "SMBv1" nocase $b = "445" $c = {FE ED} condition: any of them }
rule Zeus { strings: $a = "POST /gate.php" $b = "Zeus" $c = {FF EE} condition: any of them }
rule Emotet { strings: $a = "powershell" $b = "Emotet" $c = {DE AD} condition: any of them }
rule Qbot { strings: $a = "random_file_name" $b = "Qbot" $c = {BE EF} condition: any of them }
rule Conficker { strings: $a = "445/tcp" $b = "rpc" $c = {CA FE} condition: any of them }
rule NotPetya { strings: $a = "PsExec" $b = "NotPetya" $c = {BA BE} condition: any of them }
rule TrickBot { strings: $a = "banking" $b = "inject" $c = {AB CD} condition: any of them }
rule Ramnit { strings: $a = "worm" $b = "445" $c = {EF BE} condition: any of them }
rule GenericExecutable { strings: $a = {4D 5A} condition: $a }
"""

def upload_pcap():
    uploaded = files.upload()
    for filename in uploaded.keys():
        return filename

def resolve_ip(ip):
    if ip in ip_cache:
        return ip_cache[ip]
    try:
        result = socket.gethostbyaddr(ip)[0]
    except:
        result = "Unknown"
    ip_cache[ip] = result
    return result

def geoip_lookup(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        g = geocoder.ip(ip)
        result = f"{g.city}, {g.country}, Lat:{g.lat}, Lon:{g.lng}" if g.ok else "Unknown"
    except:
        result = "Unknown"
    geo_cache[ip] = result
    return result

def extract_features(pcap_file):
    packets = rdpcap(pcap_file)
    data = []
    payloads = []
    arp_count = 0
    alerts = []
    sid_counter = 1000001
    tcp_states = defaultdict(lambda: {'syn': 0, 'syn_ack': 0, 'fin': 0, 'rst': 0})
    flow_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'start_time': None, 'end_time': None})
    timings = []
    ip_pairs = Counter()

    for i, pkt in enumerate(packets):
        timestamp = float(pkt.time)
        if i > 0:
            timings.append(timestamp - float(packets[i-1].time))

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            length = len(pkt)
            protocol = pkt[IP].proto if pkt.haslayer(IP) else "Unknown"
            src_port = dst_port = flags = ttl = tos = tcp_options = None
            payload = pkt[IP].payload if pkt.haslayer(IP) and hasattr(pkt[IP], 'payload') else None
            pkt_id = pkt[IP].id if pkt.haslayer(IP) and hasattr(pkt[IP], 'id') else None
            ip_pairs[(src_ip, dst_ip)] += 1

            if pkt.haslayer(TCP):
                protocol = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = str(pkt[TCP].flags)
                ttl = pkt[IP].ttl
                tos = pkt[IP].tos
                tcp_options = pkt[TCP].options if pkt[TCP].options else "None"
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                if 'S' in flags and not 'A' in flags:
                    tcp_states[flow_key]['syn'] += 1
                    message = "ET SCAN Potential SSH Scan" if dst_port == 22 else "TCP SYN Scan"
                    alerts.append(SnortAlert(sid_counter, message, "Attempted Recon", 2, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, ttl, bytes(payload) if payload else None, pkt_id, length, tos, flags, tcp_options))
                    sid_counter += 1
                if 'SA' in flags:
                    tcp_states[flow_key]['syn_ack'] += 1
                if 'F' in flags:
                    tcp_states[flow_key]['fin'] += 1
                if 'R' in flags:
                    tcp_states[flow_key]['rst'] += 1
                if dst_port == 445 and payload and b"SMB" in bytes(payload):
                    alerts.append(SnortAlert(sid_counter, "WannaCry SMB Exploit", "Malware", 1, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, ttl, bytes(payload), pkt_id, length, tos, flags, tcp_options))
                    sid_counter += 1
            elif pkt.haslayer(UDP):
                protocol = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                ttl = pkt[IP].ttl
                tos = pkt[IP].tos
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
                ttl = pkt[IP].ttl
                tos = pkt[IP].tos
                flow_key = (src_ip, dst_ip, None, None, protocol)
            else:
                protocol = "Other"
                flow_key = (src_ip, dst_ip, None, None, protocol)

            if flow_stats[flow_key]['start_time'] is None:
                flow_stats[flow_key]['start_time'] = timestamp
            flow_stats[flow_key]['end_time'] = timestamp
            flow_stats[flow_key]['packets'] += 1
            flow_stats[flow_key]['bytes'] += length
            data.append([timestamp, src_ip, dst_ip, protocol, length, src_port, dst_port, flags, ttl, tos, pkt_id])
            if payload:
                payloads.append(bytes(payload))

        elif pkt.haslayer(ARP):
            arp_count += 1

    df = pd.DataFrame(data, columns=["Timestamp", "Source_IP", "Destination_IP", "Protocol", "Packet_Length", "Source_Port", "Destination_Port", "Flags", "TTL", "TOS", "Packet_ID"])
    return df, packets, payloads, arp_count, alerts, tcp_states, flow_stats, timings, ip_pairs

def abuseipdb_lookup(ip, api_key="YOUR-KEY"):
    if ip in threat_intel_cache:
        return threat_intel_cache[ip]
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()['data']
            result = f"Confidence {data['abuseConfidenceScore']}%, Reports: {data['totalReports']}, Last Reported: {data.get('lastReportedAt', 'N/A')}"
            threat_intel_cache[ip] = result
            return result
        return f"Failed: Status {response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"
    time.sleep(1)

def advanced_zero_day_detection(df):
    features = df[['Packet_Length', 'TTL', 'TOS', 'Packet_ID']].fillna(0)
    scaler = RobustScaler()
    features_scaled = scaler.fit_transform(features)

    input_dim = features_scaled.shape[1]
    encoder = tf.keras.Sequential([layers.Input(shape=(input_dim,)), layers.Dense(32, activation='relu'), layers.Dense(16, activation='relu'), layers.Dense(8)])
    decoder = tf.keras.Sequential([layers.Input(shape=(8,)), layers.Dense(16, activation='relu'), layers.Dense(32, activation='relu'), layers.Dense(input_dim, activation='sigmoid')])
    inputs = layers.Input(shape=(input_dim,))
    encoded = encoder(inputs)
    z_mean = layers.Dense(8)(encoded)
    z_log_var = layers.Dense(8)(encoded)
    epsilon = tf.keras.backend.random_normal(shape=(tf.shape(z_mean)[0], 8))
    z = z_mean + tf.exp(0.5 * z_log_var) * epsilon
    outputs = decoder(z)
    vae = tf.keras.Model(inputs, outputs)
    reconstruction_loss = tf.reduce_mean(tf.reduce_sum(tf.keras.losses.binary_crossentropy(inputs, outputs), axis=-1))
    kl_loss = -0.5 * tf.reduce_mean(tf.reduce_sum(1 + z_log_var - tf.square(z_mean) - tf.exp(z_log_var), axis=-1))
    vae.add_loss(reconstruction_loss + kl_loss)
    vae.compile(optimizer='adam')
    vae.fit(features_scaled, epochs=5, batch_size=128, shuffle=True, verbose=0)
    reconstructions = vae.predict(features_scaled, verbose=0)
    mse = np.mean(np.power(features_scaled - reconstructions, 2), axis=1)
    vae_threshold = np.percentile(mse, 97)
    vae_anomalies = mse > vae_threshold

    if PYOD_AVAILABLE:
        ecod = ECOD()
        ecod_scores = ecod.fit_predict(features_scaled)
        ecod_anomalies = ecod_scores == 1
        combined_anomalies = vae_anomalies | ecod_anomalies
    else:
        combined_anomalies = vae_anomalies
        print("Using VAE only for zero-day detection")

    return combined_anomalies.sum(), df.loc[combined_anomalies, 'Source_IP'].unique().tolist(), mse

def advanced_behavioral_profiling(df):
    features = df[['Packet_Length', 'TTL', 'TOS', 'Packet_ID']].fillna(0)
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)

    dbscan = DBSCAN(eps=0.7, min_samples=5, n_jobs=-1).fit(features_scaled)
    df['DBSCAN_Cluster'] = dbscan.labels_

    kmeans = KMeans(n_clusters=5, random_state=42, n_init=10).fit(features_scaled)
    df['KMeans_Cluster'] = kmeans.labels_

    suspicious_dbscan = df[df['DBSCAN_Cluster'] == -1]['Source_IP'].unique().tolist()
    suspicious_kmeans = df.groupby('KMeans_Cluster')['Packet_Length'].mean().idxmax()
    suspicious_kmeans_ips = df[df['KMeans_Cluster'] == suspicious_kmeans]['Source_IP'].unique().tolist()

    return suspicious_dbscan, suspicious_kmeans_ips

def calculate_entropy(payload):
    if len(payload) == 0:
        return 0
    byte_counts = Counter(payload)
    entropy = -sum((count / len(payload)) * math.log2(count / len(payload)) for count in byte_counts.values())
    return entropy

def detect_anomalies(df):
    features = df[['Packet_Length', 'TTL', 'TOS', 'Packet_ID']].fillna(0)
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)

    iso_forest = IsolationForest(contamination=0.05, random_state=42, n_jobs=-1)
    df['Anomaly_Score_Iso'] = iso_forest.fit_predict(features_scaled)

    xgb_model = xgb.XGBClassifier(random_state=42, n_jobs=-1)
    xgb_model.fit(features_scaled, df['Anomaly_Score_Iso'] == -1)
    df['Anomaly_Score_XGB'] = xgb_model.predict_proba(features_scaled)[:, 1]

    return df

def analyze_packet_timing(timings):
    if not timings:
        return "No timing data", 0, 0
    mean_delay = np.mean(timings)
    std_delay = np.std(timings)
    anomalies = sum(1 for t in timings if abs(t - mean_delay) > 3 * std_delay)
    jitter = np.var(timings)
    return "Timing anomalies detected" if anomalies > 10 else "Normal timing", anomalies, jitter

def detect_attack_types(df, arp_count, alerts, tcp_states, flow_stats, ip_pairs):
    attack_types = set()
    src_ip_counts = df['Source_IP'].value_counts()
    if src_ip_counts.max() > 1500:
        attack_types.add(f"DDoS Attack (High packet count from {src_ip_counts.idxmax()}: {src_ip_counts.max()})")
    for flow, stats in flow_stats.items():
        duration = stats['end_time'] - stats['start_time']
        if duration > 0 and stats['bytes'] / duration > 5000:
            attack_types.add(f"Data Exfiltration (Flow: {flow[0]}:{flow[2]} -> {flow[1]}:{flow[3]}, {stats['bytes']/duration:.2f} B/s)")
    for (src, dst), count in ip_pairs.most_common(5):
        if count > 1000:
            attack_types.add(f"High Traffic Pair: {src} -> {dst} ({count} packets)")
    for alert in alerts:
        attack_types.add(f"{alert.classification}: {alert.message}")
    return list(attack_types) if attack_types else ["No specific attack detected"]

def hash_payloads(payloads):
    return [(hashlib.md5(p).hexdigest(), hashlib.sha256(p).hexdigest(), hashlib.sha1(p).hexdigest()) for p in payloads[:15]]

def virustotal_lookup(hashes, api_key="YOUR-KEY"):
    if not api_key or api_key == "No KEY Available":
        return ["VirusTotal lookup skipped (no API key provided)"]
    url = "https://www.virustotal.com/api/v3/files/"
    headers = {"x-apikey": api_key}
    results = []
    for md5, sha256, sha1 in hashes[:5]:
        response = requests.get(url + sha256, headers=headers)
        if response.status_code == 200:
            data = response.json()
            positives = data['data']['attributes']['last_analysis_stats']['malicious']
            if positives > 0:
                results.append(f"Hash {sha256}: Malicious ({positives} engines)")
        time.sleep(15)
    return results if results else ["No malicious hashes found"]

def otx_lookup(ip, api_key="YOUR-KEY"):
    if ip in threat_intel_cache:
        return threat_intel_cache[ip]
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            pulse_count = len(data.get('pulse_info', {}).get('pulses', []))
            reputation = data.get('reputation', 0)
            result = f"Pulses: {pulse_count}, Reputation: {reputation}"
            threat_intel_cache[ip] = result
            return result
        return f"Failed: Status {response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"
    time.sleep(1)

def clamav_scan_worker(payload_data):
    i, payload = payload_data
    temp_file = f"temp_payload_{i}.bin"
    with open(temp_file, "wb") as f:
        f.write(payload)
    result = subprocess.run(['clamscan', '--no-summary', temp_file], capture_output=True, text=True)
    os.remove(temp_file)
    return f"ClamAV detected malware in payload {i}: {result.stdout.splitlines()[0]}" if "Infected files: 1" in result.stdout else None

def clamav_scan(payloads):
    with Pool(4) as pool:
        results = pool.map(clamav_scan_worker, [(i, p) for i, p in enumerate(payloads[:15])])
    return [r for r in results if r] or ["No malware detected by ClamAV"]

def yara_scan(payloads):
    with open("temp_yara_rules.yar", "w") as f:
        f.write(YARA_RULES)
    rules = yara.compile(filepath="temp_yara_rules.yar")

    detection_counts = Counter()
    payload_details = defaultdict(list)

    for i, payload in enumerate(payloads[:15]):
        temp_file = f"temp_payload_{i}.bin"
        with open(temp_file, "wb") as f:
            f.write(payload)

        matches = rules.match(temp_file)
        os.remove(temp_file)

        for match in matches:
            detection_counts[match.rule] += 1
            payload_details[match.rule].append(i)

    os.remove("temp_yara_rules.yar")

    results = []
    for rule, count in detection_counts.most_common():
        examples = payload_details[rule][:3]
        examples_str = ", ".join(f"payload {n}" for n in examples)
        if count > 3:
            examples_str += f" (+{count-3} more)"
        results.append(f"{rule}: {count} ({examples_str})")
    return results if results else ["No YARA matches found"]

def detect_malware(payloads):
    malware_detected = []
    for i, payload in enumerate(payloads):
        payload_str = str(payload)
        payload_bytes = bytes(payload)
        entropy = calculate_entropy(payload_bytes)
        for name, signatures in MALWARE_SIGNATURES.items():
            for sig in signatures:
                if isinstance(sig, str) and sig in payload_str:
                    malware_detected.append((name, f"Signature: {sig}", entropy, i))
                elif isinstance(sig, bytes) and sig in payload_bytes:
                    malware_detected.append((name, "Binary Signature", entropy, i))
    return Counter([(m[0], m[1]) for m in malware_detected]).most_common()

def extract_dns_queries(packets):
    dns_queries = []
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            if pkt.haslayer(IP):
                dns_queries.append((query, pkt[IP].src, pkt[IP].dst))
    return Counter([(q[0], q[1], q[2]) for q in dns_queries]).most_common(15)

def application_layer_decoding(packets):
    http_requests = []
    smtp_data = []
    ftp_commands = []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            if b"GET" in payload or b"POST" in payload:
                http_requests.append(payload.decode('utf-8', errors='ignore').split('\r\n')[0])
        elif pkt.haslayer(TCP) and pkt[TCP].dport == 25 and pkt.haslayer(Raw):
            smtp_data.append(bytes(pkt[Raw]).decode('utf-8', errors='ignore')[:100])
        elif pkt.haslayer(TCP) and pkt[TCP].dport == 21 and pkt.haslayer(Raw):
            ftp_commands.append(bytes(pkt[Raw]).decode('utf-8', errors='ignore')[:50])
    return http_requests[:10], smtp_data[:10], ftp_commands[:10]

def encrypted_traffic_analysis(df, payloads):
    tls_df = df[(df['Protocol'] == 'TCP') & ((df['Destination_Port'].isin([443, 8443])) | (df['Source_Port'].isin([443, 8443])))]
    if tls_df.empty:
        return "No TLS traffic detected", 0, 0.0
    avg_size = tls_df['Packet_Length'].mean()
    anomaly_count = len(tls_df[tls_df['Anomaly_Score_Iso'] == -1])
    tls_payloads = [payloads[i] for i in tls_df.index if i < len(payloads)]
    if tls_payloads:
        concatenated_payload = b''.join(tls_payloads[:10])
        entropy_avg = calculate_entropy(concatenated_payload)
    else:
        entropy_avg = 0.0
    return ("Suspicious TLS traffic detected" if anomaly_count > 10 or avg_size > 1500 else "Normal TLS traffic"), anomaly_count, entropy_avg

def ml_threat_scoring(df, alerts, entropy_info):
    if not alerts or len(df) < 10:
        return alerts

    features = df[['Packet_Length', 'TTL', 'TOS', 'Packet_ID', 'Anomaly_Score_XGB']].fillna(0)
    scaler = StandardScaler()
    X = scaler.fit_transform(features)

    alert_ips = set(a.src_ip for a in alerts)
    y = np.array([1 if ip in alert_ips else 0 for ip in df['Source_IP']])

    pos_weight = (len(y) - sum(y)) / max(sum(y), 1)

    rf = RandomForestClassifier(n_estimators=50, max_depth=8, min_samples_split=10, n_jobs=-1, random_state=42)
    xgb_model = xgb.XGBClassifier(max_depth=4, scale_pos_weight=pos_weight, n_estimators=50, learning_rate=0.1, n_jobs=-1, random_state=42, eval_metric='logloss')
    lgb_model = lgb.LGBMClassifier(n_estimators=50, max_depth=4, min_child_samples=10, min_child_weight=0.001, num_leaves=10, learning_rate=0.1, n_jobs=-1, random_state=42)

    from sklearn.model_selection import train_test_split
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
    rf.fit(X_train, y_train)
    xgb_model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)
    lgb_model.fit(X_train, y_train, eval_set=[(X_val, y_val)], callbacks=[lgb.early_stopping(stopping_rounds=10, verbose=False)])

    rf_scores = rf.predict_proba(X)[:, 1]
    xgb_scores = xgb_model.predict_proba(X)[:, 1]
    lgb_scores = lgb_model.predict_proba(X)[:, 1]

    ensemble_scores = (0.4 * xgb_scores + 0.3 * rf_scores + 0.3 * lgb_scores)

    for i, alert in enumerate(alerts):
        idx = df[(df['Source_IP'] == alert.src_ip) & (df['Timestamp'] == alert.timestamp)].index
        if len(idx) > 0:
            score = ensemble_scores[idx[0]]
            alert.confidence = score
            alert.threat_level = "Critical" if score > 0.9 else "High" if score > 0.7 else "Medium" if score > 0.5 else "Low"
        else:
            alert.confidence = 0.3

    return alerts

def cluster_threat_correlation(alerts):
    if len(alerts) < 3:
        return "Insufficient data for clustering", 0
    ip_times = [(a.src_ip, a.timestamp.timestamp()) for a in alerts]
    df = pd.DataFrame(ip_times, columns=['IP', 'Time'])
    clustering = DBSCAN(eps=300, min_samples=3, n_jobs=-1).fit(df[['Time']])
    clusters = Counter(clustering.labels_)
    if -1 in clusters:
        del clusters[-1]
    return f"Correlated threats in {len(clusters)} clusters", len(clusters)

def generate_advanced_visuals(df):
    sns.set(style='whitegrid')
    plt.figure(figsize=(14, 7))
    sns.histplot(df['Packet_Length'], bins=100, kde=True, color='blue')
    plt.title('Packet Length Distribution')
    plt.savefig("length_distribution.png")
    plt.close()

    plt.figure(figsize=(14, 7))
    protocol_counts = df['Protocol'].value_counts()
    sns.barplot(x=protocol_counts.index, y=protocol_counts.values)
    for i, v in enumerate(protocol_counts.values):
        plt.text(i, v, f"{v/sum(protocol_counts.values)*100:.1f}%", ha='center', va='bottom')
    plt.title('Protocol Distribution')
    plt.savefig("protocol_distribution.png")
    plt.close()

    plt.figure(figsize=(14, 7))
    sns.scatterplot(data=df, x='Timestamp', y='Packet_Length', hue='Anomaly_Score_Iso', palette={1: 'blue', -1: 'red'}, size='Anomaly_Score_XGB')
    plt.title('Anomaly Detection Over Time')
    plt.savefig("anomaly_timeline.png")
    plt.close()

    plt.figure(figsize=(14, 7))
    heatmap_data = df.pivot_table(index='Source_IP', columns='Destination_Port', values='Packet_Length', aggfunc='count', fill_value=0)
    sns.heatmap(heatmap_data, cmap="YlOrRd", annot=False)
    plt.title('Threat Heatmap (Source IP vs Destination Port)')
    plt.savefig("threat_heatmap.png")
    plt.close()

    features = df[['Packet_Length', 'TTL', 'TOS', 'Packet_ID']].fillna(0)
    pca = PCA(n_components=2)
    pca_result = pca.fit_transform(features)
    plt.figure(figsize=(14, 7))
    plt.scatter(pca_result[:, 0], pca_result[:, 1], c=df['Anomaly_Score_Iso'], cmap='coolwarm')
    plt.title('PCA of Network Features')
    plt.savefig("pca_visual.png")
    plt.close()

def generate_firewall_rules(df, attack_types, high_rate_ips):
    rules = {'iptables': [], 'aws_waf': [], 'azure': [], 'snort': []}
    for ip in high_rate_ips:
        rules['iptables'].append(f"iptables -A INPUT -s {ip} -j DROP  # Block {ip}")
        rules['aws_waf'].append(f"Block IP {ip} in AWS WAF")
        rules['azure'].append(f"Deny IP {ip} in Azure Firewall")
        rules['snort'].append(f"drop ip {ip} any -> any any (msg:\"Blocked high-rate IP {ip}\"; sid:{1000000 + len(rules['snort'])};)")
    if any("DDoS" in attack for attack in attack_types):
        top_ip = df['Source_IP'].value_counts().idxmax()
        rules['iptables'].append(f"iptables -A INPUT -s {top_ip} -m limit --limit 50/s -j ACCEPT  # Rate limit {top_ip}")
        rules['snort'].append(f"alert ip {top_ip} any -> any any (msg:\"DDoS from {top_ip}\"; sid:{1000000 + len(rules['snort'])};)")
    return rules

def carve_files_from_payloads(payloads, output_dir="carved_files"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    carved_files = []
    file_signatures = {"PDF": b"%PDF-", "PNG": b"\x89PNG", "JPEG": b"\xFF\xD8\xFF", "EXE": b"MZ", "ZIP": b"PK\x03\x04"}

    for i, payload in enumerate(payloads[:50]):
        payload_bytes = bytes(payload)
        for file_type, sig in file_signatures.items():
            if sig in payload_bytes:
                start_idx = payload_bytes.index(sig)
                end_idx = min(start_idx + 1048576, len(payload_bytes))
                file_data = payload_bytes[start_idx:end_idx]
                file_hash = hashlib.sha256(file_data).hexdigest()[:8]
                filename = f"{output_dir}/{file_type.lower()}_{file_hash}.{file_type.lower()}"
                with open(filename, "wb") as f:
                    f.write(file_data)
                carved_files.append((file_type, filename, len(file_data)))
                yara_matches = yara_scan([file_data])
                if yara_matches != ["No YARA matches found"]:
                    carved_files[-1] = carved_files[-1] + (yara_matches,)
    return carved_files

def reconstruct_tcp_sessions(packets):
    sessions = defaultdict(list)
    reconstructed_data = {}
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flow_key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            sessions[flow_key].append(pkt)
    for flow_key, pkt_list in sessions.items():
        pkt_list.sort(key=lambda x: x[TCP].seq)
        data_stream = b""
        last_ack = 0
        for pkt in pkt_list:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw])
                if pkt[TCP].seq > last_ack:
                    data_stream += payload
                    last_ack = pkt[TCP].seq + len(payload)
        if data_stream:
            reconstructed_data[flow_key] = data_stream
    return reconstructed_data

def deep_packet_inspection(packets):
    http_sessions = []
    suspicious_protocols = []
    for pkt in packets:
        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            http_sessions.append({
                "Type": "Request",
                "Method": req.Method.decode('utf-8', errors='ignore') if hasattr(req, 'Method') else "N/A",
                "Host": req.Host.decode('utf-8', errors='ignore') if hasattr(req, 'Host') else "N/A",
                "Path": req.Path.decode('utf-8', errors='ignore') if hasattr(req, 'Path') else "N/A",
                "Src_IP": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                "Dst_IP": pkt[IP].dst if pkt.haslayer(IP) else "N/A"
            })
        elif pkt.haslayer(HTTPResponse):
            resp = pkt[HTTPResponse]
            raw = resp.original if hasattr(resp, 'original') else b''
            status_line = raw.split(b'\r\n')[0].decode('utf-8', errors='ignore') if raw else "N/A"
            http_sessions.append({
                "Type": "Response",
                "Status": status_line,
                "Src_IP": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                "Dst_IP": pkt[IP].dst if pkt.haslayer(IP) else "N/A"
            })
    return http_sessions[:10], suspicious_protocols[:5]

def simulate_memory_artifacts(payloads):
    memory_artifacts = []
    for i, payload in enumerate(payloads[:15]):
        payload_bytes = bytes(payload)
        strings = re.findall(b"[ -~]{4,}", payload_bytes)
        if strings:
            memory_artifacts.append({"Payload_ID": i, "Strings": [s.decode('ascii', errors='ignore') for s in strings[:5]], "Entropy": calculate_entropy(payload_bytes)
            })
        for offset in range(0, min(len(payload_bytes), 256), 4):
            chunk = payload_bytes[offset:offset+4]
            if len(chunk) == 4:
                try:
                    val = struct.unpack("<I", chunk)[0]
                    if 0x1000 <= val <= 0x7FFFFFFF:
                        memory_artifacts.append({"Payload_ID": i, "Pointer": hex(val), "Offset": offset})
                except struct.error:
                    continue
    return memory_artifacts

def forensic_timeline_analysis(df, alerts):
    timeline_events = []
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], unit='s')
    for idx, row in df.iterrows():
        if row['Anomaly_Score_Iso'] == -1:
            timeline_events.append({"Time": row['Timestamp'], "Event": f"Anomalous Packet from {row['Source_IP']} to {row['Destination_IP']}", "Details": f"Length: {row['Packet_Length']}, Protocol: {row['Protocol']}"})
    for alert in alerts:
        timeline_events.append({"Time": alert.timestamp, "Event": f"Alert: {alert.message}", "Details": f"SID: {alert.sid}, Confidence: {alert.confidence:.2f}, Threat: {alert.threat_level}"})
    timeline_events.sort(key=lambda x: x["Time"])
    return timeline_events

def network_entropy_analysis(payloads, df):
    entropy_values = Parallel(n_jobs=-1)(delayed(calculate_entropy)(p) for p in payloads[:100])
    df_entropy = pd.DataFrame({'Timestamp': df['Timestamp'][:len(entropy_values)], 'Entropy': entropy_values})
    entropy_trend = df_entropy.groupby(df_entropy['Timestamp'].dt.floor('5min'))['Entropy'].mean()
    high_entropy_spikes = entropy_trend[entropy_trend > 6].count()
    return entropy_trend, high_entropy_spikes

def threat_correlation_matrix(alerts):
    if len(alerts) < 2:
        return None
    alert_df = pd.DataFrame([(a.src_ip, a.dst_ip, a.timestamp.timestamp()) for a in alerts], columns=['Src_IP', 'Dst_IP', 'Time'])
    correlation_matrix = alert_df.pivot_table(index='Src_IP', columns='Dst_IP', values='Time', aggfunc='count', fill_value=0)
    return correlation_matrix

# New NIDS Feature: Protocol Anomaly Detection
def detect_protocol_anomalies(packets, alerts, sid_counter):
    unusual_flags = Counter()
    malformed_packets = 0
    for pkt in packets:
        if pkt.haslayer(TCP):
            flags = str(pkt[TCP].flags)
            if flags not in ['S', 'SA', 'A', 'F', 'FA', 'PA', 'R', 'RA']:
                unusual_flags[flags] += 1
                alerts.append(SnortAlert(
                    sid_counter, f"Unusual TCP Flags: {flags}", "Protocol Anomaly", 2, float(pkt.time),
                    pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport, "TCP"
                ))
                sid_counter += 1
        if pkt.haslayer(IP) and pkt[IP].len < 20:  # Minimum IP header length
            malformed_packets += 1
            alerts.append(SnortAlert(
                sid_counter, "Malformed IP Header", "Protocol Anomaly", 3, float(pkt.time),
                pkt[IP].src, None, pkt[IP].dst, None, "IP"
            ))
            sid_counter += 1
    return unusual_flags.most_common(5), malformed_packets, alerts, sid_counter

# New NIDS Feature: Session Hijacking Detection
def detect_session_hijacking(packets, tcp_states, alerts, sid_counter):
    seq_anomalies = []
    for flow_key, states in tcp_states.items():
        if states['rst'] > 5 or (states['syn'] > 1 and states['syn_ack'] == 0):
            src_ip, dst_ip, src_port, dst_port, _ = flow_key
            alerts.append(SnortAlert(
                sid_counter, "Potential Session Hijacking", "Session Anomaly", 2, time.time(),
                src_ip, src_port, dst_ip, dst_port, "TCP"
            ))
            sid_counter += 1
            seq_anomalies.append(flow_key)
    return seq_anomalies, alerts, sid_counter

# New NIDS Feature: Covert Channel Detection
def detect_covert_channels(packets, payloads, alerts, sid_counter):
    dns_tunneling = []
    for pkt in packets:
        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            if len(qname) > 100 or calculate_entropy(qname.encode()) > 5:
                dns_tunneling.append((qname, pkt[IP].src, pkt[IP].dst))
                alerts.append(SnortAlert(
                    sid_counter, "DNS Tunneling Suspected", "Covert Channel", 2, float(pkt.time),
                    pkt[IP].src, None, pkt[IP].dst, None, "UDP"
                ))
                sid_counter += 1
    return dns_tunneling[:5], alerts, sid_counter

# New Function: Nikto Scan and PDF Generation
def nikto_scan(url):
    try:
        result = subprocess.run(['nikto', '-h', url], capture_output=True, text=True)
        nikto_output = result.stdout
    except Exception as e:
        nikto_output = f"Error running Nikto scan: {str(e)}"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "Nikto Vulnerability Scan Report", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Courier", size=10)
    pdf.multi_cell(0, 6, f"URL Scanned: {url}\n\n{nikto_output}")

    pdf_output_path = "NETSYN_Vulnerability_Report.pdf"
    pdf.output(pdf_output_path)
    if os.path.exists(pdf_output_path) and os.path.getsize(pdf_output_path) > 0:
        files.download(pdf_output_path)
        print(f"Nikto report downloaded as '{pdf_output_path}'")
    else:
        print("Error: Nikto PDF file was not generated or is empty.")
    return nikto_output

def generate_report(df, packets, payloads, attack_types, malware_detected, clamav_results, yara_results, vt_results, dns_queries,
                    high_rate_ips, arp_count, alerts, entropy_info, tcp_states, flow_stats, timings, ip_pairs,
                    carved_files, tcp_sessions, http_sessions, suspicious_protocols, memory_artifacts, timeline_events,
                    abuseipdb_results, unusual_flags, malformed_packets, seq_anomalies, covert_channels):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Page Setup
    page_width = 210 - 20  # A4 width minus margins (10mm each side)
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "NETSYN: NIDS Post-Incident Forensic Report", ln=True, align='C')

    # Placeholder QR Code (updated later with hash)
    qr_data = f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nHash: [To be computed]"
    qr = qrcode.make(qr_data)
    qr_img_path = "report_qr.png"
    qr.save(qr_img_path)
    try:
        if os.path.exists(qr_img_path):
            pdf.image(qr_img_path, x=page_width - 20, y=5, w=20)
        else:
            pdf.set_font("Courier", size=10)
            pdf.cell(0, 10, "QR Code not available", ln=True, align='R')
    except Exception as e:
        print(f"Warning: Failed to embed initial QR code: {str(e)}")
        pdf.set_font("Courier", size=10)
        pdf.cell(0, 10, "QR Code embedding failed", ln=True, align='R')
    pdf.ln(10)

    # Horizontal Line Separator
    pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), page_width + 10, pdf.get_y())
    pdf.ln(5)

    # Risk Score Calculation
    total_packets = len(df)
    anomalies = df[df['Anomaly_Score_Iso'] == -1]
    anomaly_rate = len(anomalies) / total_packets if total_packets > 0 else 0
    critical_alerts = sum(1 for a in alerts if a.threat_level in ["High", "Critical"])
    malware_count = len(malware_detected) + len([r for r in yara_results if "No YARA matches" not in r])
    attack_count = len([a for a in attack_types if "No specific attack" not in a])
    avg_entropy = np.mean([calculate_entropy(p) for p in payloads[:15]]) if payloads else 0
    pkt_rate = total_packets / max((df['Timestamp'].max() - df['Timestamp'].min()).total_seconds(), 1) if total_packets > 1 else 0
    unique_ips = df['Source_IP'].nunique()

    risk_features = pd.DataFrame([{
        'anomaly_rate': anomaly_rate, 'critical_alerts_per_1k': critical_alerts / (total_packets / 1000 + 1),
        'malware_per_10_payloads': malware_count / (len(payloads) / 10 + 1), 'attack_count': attack_count,
        'avg_entropy': avg_entropy, 'pkt_rate': pkt_rate, 'unique_ips': unique_ips / (total_packets / 1000 + 1)
    }])
    synthetic_data = pd.DataFrame({
        'anomaly_rate': np.random.uniform(0, 0.5, 1000), 'critical_alerts_per_1k': np.random.uniform(0, 10, 1000),
        'malware_per_10_payloads': np.random.uniform(0, 5, 1000), 'attack_count': np.random.randint(0, 10, 1000),
        'avg_entropy': np.random.uniform(0, 8, 1000), 'pkt_rate': np.random.uniform(0, 1000, 1000),
        'unique_ips': np.random.uniform(0, 10, 1000)
    })
    synthetic_data['risk'] = ((synthetic_data['anomaly_rate'] > 0.1).astype(int) * 20 +
                             (synthetic_data['critical_alerts_per_1k'] > 2).astype(int) * 30 +
                             (synthetic_data['malware_per_10_payloads'] > 1).astype(int) * 25 +
                             (synthetic_data['attack_count'] > 3).astype(int) * 15 +
                             (synthetic_data['avg_entropy'] > 6).astype(int) * 10).clip(0, 100)
    lgb_risk = lgb.LGBMRegressor(n_estimators=100, max_depth=5, random_state=42)
    lgb_risk.fit(synthetic_data.drop('risk', axis=1), synthetic_data['risk'])
    risk_score = round(min(max(lgb_risk.predict(risk_features)[0], 0), 100), 2)

    # 1. Executive Summary
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "1. Executive Summary", ln=True, align='C')
    pdf.set_font("Courier", size=10)
    table_width = page_width
    col_widths = [40, table_width - 40]
    pdf.cell(col_widths[0], 8, "Metric", border=1)
    pdf.cell(col_widths[1], 8, "Value", border=1, ln=True)
    top_sender = Counter(df['Source_IP']).most_common(1)[0] if not df['Source_IP'].empty else ("N/A", 0)
    top_receiver = Counter(df['Destination_IP']).most_common(1)[0] if not df['Destination_IP'].empty else ("N/A", 0)
    rows = [
        ("Date", datetime.now().strftime('%Y-%m-%d')),
        ("Packets Analyzed", f"{total_packets:,}"),
        ("Anomalous Packets", f"{len(anomalies):,}"),
        ("Risk Score", f"{risk_score}/100"),
        ("Top Sender", f"{top_sender[0]} ({resolve_ip(top_sender[0])}): {top_sender[1]:,}"),
        ("Top Receiver", f"{top_receiver[0]} ({resolve_ip(top_receiver[0])}): {top_receiver[1]:,}")
    ]
    for label, value in rows:
        pdf.cell(col_widths[0], 8, label, border=1)
        pdf.cell(col_widths[1], 8, value, border=1, ln=True)
    pdf.ln(10)

    # 2. Security Alerts
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "2. Security Alerts", ln=True, align='C')
    pdf.set_font("Courier", size=8)
    if not alerts:
        pdf.cell(0, 6, "No security alerts detected.", ln=True)
    else:
        col_widths = [15, 30, 15, 15, 30, 75]
        total_table_width = sum(col_widths)
        if total_table_width > page_width:
            scale = page_width / total_table_width
            col_widths = [w * scale for w in col_widths]
        headers = ["SID", "Message", "Threat", "Conf.", "Timestamp", "Flow"]
        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], 8, header, border=1, align='C')
        pdf.ln()
        for alert in alerts[:15]:
            flow_str = f"{alert.src_ip}:{alert.src_port or 'N/A'} -> {alert.dst_ip}:{alert.dst_port or 'N/A'}"
            flow_display = flow_str if len(flow_str) <= 40 else flow_str[:37] + "..."
            msg_str = alert.message[:20] + "..." if len(alert.message) > 20 else alert.message
            pdf.cell(col_widths[0], 8, str(alert.sid), border=1, align='C')
            pdf.cell(col_widths[1], 8, msg_str, border=1, align='L')
            pdf.cell(col_widths[2], 8, alert.threat_level[:8], border=1, align='C')
            pdf.cell(col_widths[3], 8, f"{alert.confidence:.2f}", border=1, align='C')
            pdf.cell(col_widths[4], 8, alert.timestamp.strftime('%Y-%m-%d %H:%M'), border=1, align='C')
            pdf.cell(col_widths[5], 8, flow_display, border=1, align='L')
            pdf.ln()
    pdf.ln(10)

    # 3. Network Traffic Overview
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "3. Network Traffic Overview", ln=True, align='C')
    pdf.set_font("Courier", size=10)
    table_width = page_width
    col_widths = [40, table_width - 40]
    pdf.cell(col_widths[0], 8, "Metric", border=1)
    pdf.cell(col_widths[1], 8, "Value", border=1, ln=True)
    pdf.cell(col_widths[0], 8, "Unique Source IPs", border=1)
    pdf.cell(col_widths[1], 8, str(df['Source_IP'].nunique()), border=1, ln=True)
    pdf.cell(col_widths[0], 8, "Unique Dest. IPs", border=1)
    pdf.cell(col_widths[1], 8, str(df['Destination_IP'].nunique()), border=1, ln=True)
    pdf.cell(col_widths[0], 8, "Avg Packet Length", border=1)
    pdf.cell(col_widths[1], 8, f"{df['Packet_Length'].mean():.2f} bytes", border=1, ln=True)
    pdf.cell(col_widths[0], 8, "ARP Packets", border=1)
    pdf.cell(col_widths[1], 8, str(arp_count), border=1, ln=True)
    pdf.ln(5)
    pdf.cell(0, 6, "Top Source IPs:", ln=True)
    col_widths = [40, 90, 20]
    pdf.cell(col_widths[0], 8, "IP Address", border=1)
    pdf.cell(col_widths[1], 8, "Geolocation", border=1)
    pdf.cell(col_widths[2], 8, "Packets", border=1, ln=True)
    for ip, count in Counter(df['Source_IP']).most_common(5):
        pdf.cell(col_widths[0], 8, ip, border=1)
        pdf.cell(col_widths[1], 8, geoip_lookup(ip)[:40], border=1)
        pdf.cell(col_widths[2], 8, str(count), border=1, ln=True)
    pdf.ln(5)
    pdf.cell(0, 6, "Protocol Distribution:", ln=True)
    col_widths = [40, table_width - 40]
    for proto, count in df['Protocol'].value_counts().items():
        pdf.cell(col_widths[0], 8, proto, border=1)
        pdf.cell(col_widths[1], 8, f"{count} ({count/total_packets*100:.1f}%)", border=1, ln=True)
    pdf.ln(10)

    # 4. Detected Attack Types
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "4. Detected Attack Types", ln=True, align='C')
    pdf.set_font("Courier", size=10)
    pdf.cell(0, 6, "Identified Attacks:", ln=True)
    for attack in attack_types[:10]:
        pdf.cell(10, 6, "- ", ln=False)
        pdf.multi_cell(0, 6, attack[:80])
    if not attack_types:
        pdf.cell(0, 6, "No specific attacks detected.", ln=True)
    pdf.ln(10)

    # 5. Malware and Threat Intelligence
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "5. Malware and Threat Intelligence", ln=True, align='C')
    pdf.set_font("Courier", size=10)
    pdf.cell(0, 6, "Signature-Based Malware:", ln=True)
    for (name, sig), count in malware_detected[:5]:
        pdf.cell(10, 6, "- ", ln=False)
        pdf.cell(0, 6, f"{name}: {count} ({sig})", ln=True)
    pdf.ln(5)
    pdf.cell(0, 6, "ClamAV Results:", ln=True)
    for r in clamav_results[:5]:
        pdf.cell(10, 6, "- ", ln=False)
        pdf.multi_cell(0, 6, r[:80])
    pdf.ln(5)
    pdf.cell(0, 6, "YARA Results:", ln=True)
    for r in yara_results[:5]:
        pdf.cell(10, 6, "- ", ln=False)
        pdf.multi_cell(0, 6, r[:80])
    pdf.ln(5)
    pdf.cell(0, 6, "VirusTotal Results:", ln=True)
    for r in vt_results[:5]:
        pdf.cell(10, 6, "- ", ln=False)
        pdf.multi_cell(0, 6, r[:80])
    pdf.ln(5)
    pdf.cell(0, 6, "OTX Threat Intel (Top IPs):", ln=True)
    otx_results = [otx_lookup(ip) for ip, _ in Counter(df['Source_IP']).most_common(5)]
    for ip, res in list(zip([x[0] for x in Counter(df['Source_IP']).most_common(5)], otx_results))[:5]:
        pdf.cell(10, 6, "- ", ln=False)
        pdf.cell(0, 6, f"{ip}: {res[:50]}", ln=True)
    pdf.ln(5)
    pdf.cell(0, 6, "AbuseIPDB Insights (Top IPs):", ln=True)
    for ip, res in list(zip([x[0] for x in Counter(df['Source_IP']).most_common(5)], abuseipdb_results))[:5]:
        pdf.cell(10, 6, "- ", ln=False)
        pdf.cell(0, 6, f"{ip}: {res[:50]}", ln=True)
    pdf.ln(5)
    pdf.cell(0, 6, "Top DNS Queries:", ln=True)
    for (query, src, dst), count in dns_queries[:5]:
        pdf.cell(10, 6, "- ", ln=False)
        pdf.cell(0, 6, f"{query[:30]} from {src} to {dst}: {count}", ln=True)
    pdf.ln(10)

    # 6. Behavioral Insights
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "6. Behavioral Insights", ln=True, align='C')
    pdf.set_font("Courier", size=10)
    suspicious_dbscan, suspicious_kmeans_ips = advanced_behavioral_profiling(df)
    entropy_trend, high_entropy_spikes = network_entropy_analysis(payloads, df)
    col_widths = [40, table_width - 40]
    pdf.cell(col_widths[0], 8, "Metric", border=1)
    pdf.cell(col_widths[1], 8, "Value", border=1, ln=True)
    pdf.cell(col_widths[0], 8, "DBSCAN Outliers", border=1)
    pdf.cell(col_widths[1], 8, f"{len(suspicious_dbscan)} IPs", border=1, ln=True)
    pdf.cell(col_widths[0], 8, "Top Outlier IPs", border=1)
    pdf.cell(col_widths[1], 8, ", ".join(suspicious_dbscan[:5]), border=1, ln=True)
    pdf.cell(col_widths[0], 8, "KMeans High Pkt IPs", border=1)
    pdf.cell(col_widths[1], 8, f"{len(suspicious_kmeans_ips)} IPs", border=1, ln=True)
    pdf.cell(col_widths[0], 8, "Top KMeans IPs", border=1)
    pdf.cell(col_widths[1], 8, ", ".join(suspicious_kmeans_ips[:5]), border=1, ln=True)
    pdf.cell(col_widths[0], 8, "Entropy Spikes", border=1)
    pdf.cell(col_widths[1], 8, f"{high_entropy_spikes} (>6, 5-min intervals)", border=1, ln=True)
    pdf.ln(10)

    # 7. Forensic Analysis
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "7. Forensic Analysis", ln=True, align='C')
    pdf.set_font("Courier", size=10)
    pdf.cell(0, 6, f"Carved Files: {len(carved_files)}", ln=True)
    col_widths = [30, 80, 30, 50]
    pdf.cell(col_widths[0], 8, "Type", border=1)
    pdf.cell(col_widths[1], 8, "Filename", border=1)
    pdf.cell(col_widths[2], 8, "Size (bytes)", border=1)
    pdf.cell(col_widths[3], 8, "YARA Matches", border=1, ln=True)
    for info in carved_files[:5]:
        ftype, fname, size, *matches = info if len(info) > 3 else (info[0], info[1], info[2], ["None"])
        pdf.cell(col_widths[0], 8, ftype, border=1)
        pdf.cell(col_widths[1], 8, os.path.basename(fname)[:30], border=1)
        pdf.cell(col_widths[2], 8, str(size), border=1)
        pdf.cell(col_widths[3], 8, ", ".join(matches[0])[:20] if matches else "None", border=1, ln=True)
    pdf.ln(5)
    pdf.cell(0, 6, f"TCP Sessions: {len(tcp_sessions)}", ln=True)
    col_widths = [60, 60, 30]
    pdf.cell(col_widths[0], 8, "Source", border=1)
    pdf.cell(col_widths[1], 8, "Destination", border=1)
    pdf.cell(col_widths[2], 8, "Bytes", border=1, ln=True)
    for (src, sport, dst, dport), data in list(tcp_sessions.items())[:5]:
        pdf.cell(col_widths[0], 8, f"{src}:{sport}"[:20], border=1)
        pdf.cell(col_widths[1], 8, f"{dst}:{dport}"[:20], border=1)
        pdf.cell(col_widths[2], 8, str(len(data)), border=1, ln=True)
    pdf.ln(5)
    pdf.cell(0, 6, "HTTP Sessions:", ln=True)
    if not http_sessions:
        pdf.cell(0, 6, "No HTTP sessions detected.", ln=True)
    else:
        col_widths = [20, 100, 50]
        pdf.cell(col_widths[0], 8, "Type", border=1)
        pdf.cell(col_widths[1], 8, "Details", border=1)
        pdf.cell(col_widths[2], 8, "Flow", border=1, ln=True)
        for s in http_sessions[:5]:
            pdf.cell(col_widths[0], 8, s['Type'], border=1)
            pdf.cell(col_widths[1], 8, f"{s.get('Method', s.get('Status'))} {s.get('Host', '')}{s.get('Path', '')}"[:50], border=1)
            pdf.cell(col_widths[2], 8, f"{s['Src_IP']} -> {s['Dst_IP']}"[:25], border=1, ln=True)
    pdf.ln(10)

    # 8. Advanced NIDS Features
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "8. Advanced NIDS Features", ln=True, align='C')
    pdf.set_font("Courier", size=10)
    pdf.cell(0, 6, "Protocol Anomalies:", ln=True)
    col_widths = [40, table_width - 40]
    pdf.cell(col_widths[0], 8, "Unusual TCP Flags", border=1)
    pdf.cell(col_widths[1], 8, f"{len(unusual_flags)} detected: {', '.join([f'{f[0]} ({f[1]})' for f in unusual_flags[:3]])}"[:50], border=1, ln=True)
    pdf.cell(col_widths[0], 8, "Malformed Packets", border=1)
    pdf.cell(col_widths[1], 8, str(malformed_packets), border=1, ln=True)
    pdf.ln(5)
    pdf.cell(0, 6, "Session Hijacking:", ln=True)
    pdf.cell(col_widths[0], 8, "Anomalies", border=1)
    pdf.cell(col_widths[1], 8, f"{len(seq_anomalies)} detected: {', '.join([f'{s[0]}:{s[2]}' for s in seq_anomalies[:3]])}"[:50], border=1, ln=True)
    pdf.ln(5)
    pdf.cell(0, 6, "Covert Channels:", ln=True)
    pdf.cell(col_widths[0], 8, "DNS Tunneling", border=1)
    pdf.cell(col_widths[1], 8, f"{len(covert_channels)} detected: {', '.join([c[0][:20] for c in covert_channels[:3]])}"[:50], border=1, ln=True)
    pdf.ln(10)

    # 9. Visual Analytics
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "9. Visual Analytics", ln=True, align='C')
    pdf.set_font("Courier", size=10)
    pdf.cell(0, 6, "Attached Visualizations:", ln=True)
    visual_files = ["length_distribution.png", "protocol_distribution.png", "anomaly_timeline.png", "threat_heatmap.png", "pca_visual.png"]
    for img in visual_files:
        try:
            if os.path.exists(img) and os.path.getsize(img) > 0:
                pdf.image(img, x=10, w=180)
            else:
                pdf.cell(0, 6, f"Warning: {img} not found or empty", ln=True)
        except Exception as e:
            print(f"Warning: Failed to embed {img}: {str(e)}")
            pdf.cell(0, 6, f"Warning: Failed to embed {img}", ln=True)
        pdf.ln(5)
    pdf.ln(10)

    # 10. Conclusion and Recommendations
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "10. Conclusion and Recommendations", ln=True, align='C')
    pdf.set_font("Courier", size=10)
    pdf.cell(0, 6, "Summary:", ln=True)
    pdf.multi_cell(0, 6, f"Analysis of {len(df)} packets identified {len(anomalies)} anomalies and a risk score of {risk_score}/100.\n"
                         f"- Alerts: {len(alerts)} detected, {critical_alerts} high/critical.\n"
                         f"- Attacks: {len(attack_types)} observed, e.g., {attack_types[0] if attack_types else 'none'}.\n"
                         f"- Malware: {len(malware_detected)} signatures, {len([r for r in yara_results if 'No YARA matches' not in r])} YARA hits.\n"
                         f"- Behavioral: {len(suspicious_dbscan)} DBSCAN outliers, {high_entropy_spikes} entropy spikes.")
    pdf.ln(5)
    pdf.cell(0, 6, "Recommendations:", ln=True)
    pdf.multi_cell(0, 6, f"- Immediate: {'Block IPs ' + ', '.join(high_rate_ips[:3]) + ' and investigate critical alerts.' if risk_score > 75 else 'Review high-rate IPs and alerts.'}\n"
                         f"- Post-Incident: Correlate AbuseIPDB data with timeline, preserve carved files for evidence, update policies based on abuse history and behavioral insights.")
    pdf.ln(10)

    # Generate PDF Hash and Update QR Code
    pdf_output = pdf.output(dest='S').encode('latin1')  # Get PDF content as bytes
    pdf_hash = hashlib.sha256(pdf_output).hexdigest()[:16]  # Simple hash (first 16 chars for brevity)
    qr_data = f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nHash: {pdf_hash}"
    qr = qrcode.make(qr_data)
    qr.save(qr_img_path)
    try:
        pdf.image(qr_img_path, x=page_width - 20, y=5, w=20)  # Replace initial QR code
    except Exception as e:
        print(f"Warning: Failed to update QR code with hash: {str(e)}")

    # Output
    pdf_output_path = "NETSYN_NIDS_Post_Incident_Report.pdf"
    try:
        pdf.output(pdf_output_path)
        if os.path.exists(pdf_output_path) and os.path.getsize(pdf_output_path) > 0:
            files.download(pdf_output_path)
            print(f"Report generated with hash: {pdf_hash}")
        else:
            print("Error: PDF file was not generated or is empty.")
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        # Fallback: Generate a minimal error PDF
        error_pdf = FPDF()
        error_pdf.add_page()
        error_pdf.set_font("Courier", size=10)
        error_pdf.cell(0, 10, "NETSYN: NIDS Post-Incident Forensic Report", ln=True, align='C')
        error_pdf.cell(0, 10, f"Error: {str(e)}", ln=True, align='C')
        error_pdf.output(pdf_output_path)
        if os.path.exists(pdf_output_path):
            files.download(pdf_output_path)
        else:
            print("Error: Failed to generate even the error report PDF.")

def main():
    # Prompt for URL or PCAP
    choice = input("Would you like to scan a URL or upload a PCAP file? (Enter 'URL' or 'PCAP'): ").strip().upper()

    if choice == 'URL':
        url = input("Please enter the URL to scan with Nikto: ").strip()
        nikto_scan(url)
    elif choice == 'PCAP':
        pcap_file = upload_pcap()
        df, packets, payloads, arp_count, alerts, tcp_states, flow_stats, timings, ip_pairs = extract_features(pcap_file)
        sid_counter = 1000001
        unusual_flags, malformed_packets, alerts, sid_counter = detect_protocol_anomalies(packets, alerts, sid_counter)
        df = detect_anomalies(df)
        entropy_info = (calculate_entropy(payloads[0]) if payloads else 0, "N/A" if not payloads else "High" if calculate_entropy(payloads[0]) > 6 else "Low")
        high_rate_ips = [ip for ip, count in Counter(df['Source_IP']).most_common(5) if count > 1500] if not df.empty else []
        attack_types = detect_attack_types(df, arp_count, alerts, tcp_states, flow_stats, ip_pairs)
        malware_detected = detect_malware(payloads)
        clamav_results = clamav_scan(payloads)
        yara_results = yara_scan(payloads)
        payload_hashes = hash_payloads(payloads)
        vt_results = virustotal_lookup(payload_hashes)
        dns_queries = extract_dns_queries(packets)
        abuseipdb_results = [abuseipdb_lookup(ip) for ip in [ip for ip, _ in Counter(df['Source_IP']).most_common(5)] if not df.empty] or ["N/A"]
        seq_anomalies, alerts, sid_counter = detect_session_hijacking(packets, tcp_states, alerts, sid_counter)
        covert_channels, alerts, sid_counter = detect_covert_channels(packets, payloads, alerts, sid_counter)

        for i, p in enumerate(payloads[:15]):
            entropy = calculate_entropy(p)
            if i < len(alerts):
                alerts[i].entropy = entropy
                alerts[i].packet_hash = hashlib.sha256(p).hexdigest()[:16]

        alerts = ml_threat_scoring(df, alerts, entropy_info)
        generate_advanced_visuals(df)
        carved_files = carve_files_from_payloads(payloads)
        tcp_sessions = reconstruct_tcp_sessions(packets)
        http_sessions, suspicious_protocols = deep_packet_inspection(packets)
        memory_artifacts = simulate_memory_artifacts(payloads)
        timeline_events = forensic_timeline_analysis(df, alerts)

        generate_report(df, packets, payloads, attack_types, malware_detected, clamav_results, yara_results, vt_results, dns_queries,
                        high_rate_ips, arp_count, alerts, entropy_info, tcp_states, flow_stats, timings, ip_pairs,
                        carved_files, tcp_sessions, http_sessions, suspicious_protocols, memory_artifacts, timeline_events,
                        abuseipdb_results, unusual_flags, malformed_packets, seq_anomalies, covert_channels)
        print("Report downloaded as 'NETSYN_NIDS_Post_Incident_Report.pdf'")
    else:
        print("Invalid choice. Please enter 'URL' or 'PCAP'.")

if __name__ == "__main__":
    main()
