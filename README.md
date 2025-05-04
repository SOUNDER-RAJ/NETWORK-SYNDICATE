# NETWORK-SYNDICATE
A Post Incident Network Intrusion Detection system for Network Forensic Analysis.

NETSYN is a state-of-the-art Network Intrusion Detection System (NIDS) designed for post-incident forensic analysis of network traffic. Built with Python, NETSYN leverages advanced machine learning, deep packet inspection, and threat intelligence to detect and analyze malicious activities in PCAP files or perform vulnerability scans on URLs. This open-source tool is ideal for cybersecurity professionals, incident responders, and network analysts.
Features
NETSYN provides a comprehensive suite of features for network security analysis:

PCAP Analysis:

Extracts and analyzes packet features (e.g., IP, TCP, UDP, DNS, ICMP, ARP) from PCAP files using Scapy.
Performs deep packet inspection to identify HTTP sessions, DNS queries, and application-layer data.
Reconstructs TCP sessions and carves files (e.g., PDF, PNG, JPEG, EXE) from payloads.
Detects protocol anomalies, session hijacking, and covert channels (e.g., DNS tunneling).
Generates forensic timelines and visual analytics (e.g., packet length distribution, anomaly timelines, PCA visualizations).


Malware Detection:

Uses signature-based detection for known malware (e.g., Mirai, WannaCry, Zeus) with predefined patterns.
Applies YARA rules for advanced malware identification.
Integrates ClamAV for payload scanning and VirusTotal for hash-based threat lookup.
Analyzes payload entropy to detect encrypted or suspicious traffic.


Machine Learning and Anomaly Detection:

Employs Isolation Forest, XGBoost, LightGBM, and Variational Autoencoders (VAE) for anomaly detection.
Clusters traffic using DBSCAN and KMeans to identify behavioral outliers.
Scores threats using ensemble machine learning models for prioritized alerts.
Detects zero-day threats through advanced behavioral profiling.


Threat Intelligence:

Integrates AbuseIPDB and AlienVault OTX for IP reputation checks.
Correlates alerts to identify coordinated attacks using clustering techniques.
Provides geolocation data for IPs using the geocoder library.


Vulnerability Scanning:

Performs web vulnerability scanning using Nikto for user-provided URLs.
Generates detailed PDF reports for scan results.


Reporting:

Produces comprehensive PDF reports with executive summaries, security alerts, traffic overviews, and visual analytics.
Includes QR codes with report metadata and hash for verification.
Suggests firewall rules (iptables, AWS WAF, Azure, Snort) for mitigation.


Additional Features:

Simulates memory artifact analysis to extract strings and pointers from payloads.
Analyzes network entropy trends and packet timing for covert channel detection.
Generates a threat correlation matrix for alert analysis.



Requirements
System Requirements

Operating System: Linux (Ubuntu recommended) or Google Colab for cloud-based execution.
Python Version: Python 3.8 or higher.
Hardware: Minimum 4GB RAM, 4 CPU cores (8GB RAM and 8 cores recommended for large PCAP files).
Dependencies: Install required Python packages and system tools as listed below.

Python Packages
Install the following packages using pip:
pip install scapy==2.5.0 cryptography==38.0.4 pandas==2.0.3 numpy==1.25.2 matplotlib==3.7.2 seaborn==0.12.2
pip install fpdf==1.7.2 scikit-learn==1.3.0 nest_asyncio==1.5.8 dpkt==1.9.8 pyclamd==0.4.0
pip install yara-python==4.5.1 requests==2.31.0 tensorflow==2.15.0 geocoder==1.38.1 qrcode==7.4.2
pip install xgboost==2.0.3 lightgbm==4.3.0 tshark==0.7.2 pypsd==0.2.1 pyod==1.1.3

System Tools
Install the following tools using apt-get (on Ubuntu/Debian):
sudo apt-get update
sudo apt-get install -y clamav tshark nikto
sudo freshclam  # Update ClamAV virus database

API Keys
NETSYN integrates with external threat intelligence services. Obtain the following API keys and replace the placeholders in the code:

AbuseIPDB API Key: For IP reputation checks. Sign up at AbuseIPDB and update the api_key in the abuseipdb_lookup function.
VirusTotal API Key: For hash-based malware lookup. Register at VirusTotal and update the api_key in the virustotal_lookup function.
AlienVault OTX API Key: For threat intelligence. Sign up at AlienVault OTX and update the api_key in the otx_lookup function.

Note: The code includes placeholder API keys for demonstration. Replace them with your own keys for production use.
Additional Notes

The pyod library is optional for ECOD-based anomaly detection. If unavailable, NETSYN falls back to VAE-based detection.
Google Colab users must upload PCAP files manually and ensure API keys are configured.
Ensure clamav and nikto are accessible in the system PATH.


Install Dependencies:Run the pip and apt-get commands listed in the Requirements section.

Configure API Keys:Update the abuseipdb_lookup, virustotal_lookup, and otx_lookup functions with your API keys.

Run the Script:Execute the main script:
python netsyn.py



Usage

Launch the Program:Run python netsyn.py and choose between:

URL: Scan a website using Nikto.
PCAP: Analyze a network capture file.


URL Scanning:

Enter a URL (e.g., http://ex4mple.com).
NETSYN runs a Nikto scan and generates a PDF report (NETSYN_Vulnerability_Report.pdf).


PCAP Analysis:

Upload a PCAP file when prompted (in Google Colab, use the file upload interface).
NETSYN analyzes the file and generates a detailed PDF report (NETSYN_NIDS_Post_Incident_Report.pdf) with:
Executive summary (packets analyzed, risk score, top IPs).
Security alerts (Snort-style with SID, confidence, and threat level).
Traffic overview (IP counts, protocol distribution, geolocation).
Attack types (e.g., DDoS, data exfiltration).
Malware and threat intelligence (YARA, ClamAV, VirusTotal, AbuseIPDB, OTX).
Behavioral insights (DBSCAN/KMeans outliers, entropy spikes).
Forensic analysis (carved files, TCP sessions, HTTP sessions).
Advanced NIDS features (protocol anomalies, session hijacking, covert channels).
Visual analytics (charts and heatmaps).




Output:

Reports are automatically downloaded in Google Colab or saved locally.
Visualizations (e.g., length_distribution.png, threat_heatmap.png) are included in the report.



Example Workflow
$ python netsyn.py
Would you like to scan a URL or upload a PCAP file? (Enter 'URL' or 'PCAP'): PCAP
# Upload 'capture.pcap'
Report downloaded as 'NETSYN_NIDS_Post_Incident_Report.pdf'

Functions
Core Analysis

extract_features(pcap_file): Extracts packet features (IP, ports, protocols, payloads) from PCAP files.
detect_anomalies(df): Applies Isolation Forest and XGBoost for anomaly detection.
advanced_zero_day_detection(df): Uses VAE and ECOD for zero-day threat detection.
advanced_behavioral_profiling(df): Clusters traffic with DBSCAN and KMeans for outlier detection.
detect_attack_types(df, arp_count, alerts, tcp_states, flow_stats, ip_pairs): Identifies attack patterns (e.g., DDoS, exfiltration).
detect_protocol_anomalies(packets, alerts, sid_counter): Detects unusual TCP flags and malformed packets.
detect_session_hijacking(packets, tcp_states, alerts, sid_counter): Identifies potential session hijacking.
detect_covert_channels(packets, payloads, alerts, sid_counter): Detects DNS tunneling and other covert channels.

Malware Detection

detect_malware(payloads): Matches payloads against known malware signatures.
yara_scan(payloads): Applies YARA rules for malware identification.
clamav_scan(payloads): Scans payloads with ClamAV.
virustotal_lookup(hashes): Checks payload hashes against VirusTotal.
calculate_entropy(payload): Computes Shannon entropy for payloads.

Threat Intelligence

abuseipdb_lookup(ip, api_key): Queries AbuseIPDB for IP reputation.
otx_lookup(ip, api_key): Queries AlienVault OTX for threat intelligence.
geoip_lookup(ip): Retrieves geolocation data for IPs.

Forensic Analysis

carve_files_from_payloads(payloads): Extracts files from payloads (e.g., PDF, PNG).
reconstruct_tcp_sessions(packets): Rebuilds TCP sessions for data analysis.
deep_packet_inspection(packets): Analyzes HTTP and other application-layer protocols.
simulate_memory_artifacts(payloads): Extracts strings and pointers from payloads.
forensic_timeline_analysis(df, alerts): Creates a timeline of events and anomalies.
network_entropy_analysis(payloads, df): Analyzes entropy trends for suspicious traffic.

Reporting and Visualization

generate_report(...): Creates a comprehensive PDF report with all findings.
generate_advanced_visuals(df): Produces visualizations (histograms, heatmaps, PCA).
nikto_scan(url): Runs Nikto scans and generates a vulnerability report.


Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a feature branch (git checkout -b feature/new-feature).
Commit changes (git commit -m 'Add new feature').
Push to the branch (git push origin feature/new-feature).
Open a Pull Request.


Built with open-source libraries: Scapy, Pandas, Scikit-learn, TensorFlow, YARA, and more.
Inspired by real-world NIDS and forensic analysis workflows.
Special thanks to the cybersecurity community for tools like ClamAV, Nikto, and Tshark.


