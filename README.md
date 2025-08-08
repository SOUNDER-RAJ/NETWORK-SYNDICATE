# NETWORK SYNDICATE

**Post-Incident NIDS and Automated PCAP/PCAPNG Forensics Tool**

## Abstract

**NETWORK SYNDICATE** is a full-spectrum network forensics and threat detection system built to process `.pcap` and `.pcapng` files for retrospective analysis of security incidents. It integrates malware detection, threat intelligence enrichment, and machine learning-based anomaly detection to deliver a comprehensive PDF report emulating real-world SOC triage and forensics workflows.

Designed as a final-year capstone project, this tool stands as a practical post-incident analysis framework, applicable for educational, research, and operational cybersecurity environments.

---

## Table of Contents

* [Features](#features)
* [Architecture](#architecture)
* [Installation](#installation)
* [Usage](#usage)
* [Output](#output)
* [Technology Stack](#technology-stack)
* [Future Enhancements](#future-enhancements)
* [License](#license)
* [Author](#author)

---

## Features

### 1. Multi-Format Capture Support

* Accepts `.pcap`, `.pcapng`, or raw HTTP-based PCAP file URLs.
* Employs `scapy` and `dpkt` for deep packet dissection.

### 2. Feature-Rich Packet Inspection

* Extracts protocols, flags, TTL, payload lengths, entropy, flow statistics.
* Reconstructs TCP/UDP session metadata.

### 3. Statistical and Heuristic Detection

* Derives packet timing, byte distributions, flow-level entropy.
* Applies heuristics for potential beaconing and DoS indicators.

### 4. Threat Intelligence Correlation

* Integrates:

  * **VirusTotal API**: File and hash reputation
  * **AbuseIPDB**: IP reputation scoring
  * **AlienVault OTX**: Threat actor and IOC correlations

### 5. Malware Scanning

* **YARA** rules for pattern-based detection.
* **ClamAV (pyclamd)** for known malware fingerprinting.
* Flags compressed, encrypted, or obfuscated payloads.

### 6. Machine Learning Analysis

* **Unsupervised DBSCAN Clustering** for anomaly discovery.
* **PCA** for dimensionality reduction and visualization.
* **LightGBM Classifier** for supervised threat classification.

### 7. Automated Forensics Reporting

* PDF report includes:

  * Threat summary, alert categories, risk levels
  * ML outputs with probability scores
  * IOC lookups and correlated data
  * Visualization plots (entropy, protocols, PCA clusters)
  * QR-based cryptographic hash validation

---

## Architecture

```text
[.pcap / .pcapng / URL Input]
          |
[Packet Parsing Engine]
    - scapy
    - dpkt
          |
[Feature Extraction]
    - Protocols, IPs, TTL, Payload Sizes, Entropy
          |
[Threat Intelligence Layer]
    - AbuseIPDB, OTX, VirusTotal
          |
[Malware Scanning]
    - YARA Rules, ClamAV Engine
          |
[ML & Clustering Layer]
    - DBSCAN + PCA
    - LightGBM Classifier
          |
[PDF Report Generator]
    - Visual Charts
    - QR Code Hashing
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/SOUNDER-RAJ/NETWORK-SYNDICATE.git
cd NETWORK-SYNDICATE
```

### 2. Install Python Dependencies


```bash
pip install scapy dpkt pandas numpy matplotlib seaborn fpdf \
            scikit-learn lightgbm yara-python pyclamd \
            requests nest_asyncio tensorflow
```

**Note:**

* Ensure `ClamAV` is installed and its daemon (`clamd`) is active.
* YARA must be installed at the system level.

---

## Usage

1. Start the notebook:

   ```bash
   jupyter notebook NETWORK_SYNDICATE.ipynb
   ```

2. Upload or link a `.pcap` / `.pcapng` capture.

3. Follow in-notebook instructions to:

   * Parse traffic
   * Extract features
   * Run TI and malware scans
   * Perform ML analysis
   * Generate `.pdf` report

---

## Output

Each run produces:

* `NETWORK_SYNDICATE_REPORT.pdf`

The report includes:

* Detailed threat detection summary
* IOC correlation outputs
* Hash-based malware detection results
* Supervised ML predictions with probabilities
* PCA and clustering visuals
* SHA-256 QR code for report integrity

---

## Technology Stack

| Domain                  | Technologies Used                           |
| ----------------------- | ------------------------------------------- |
| **Packet Analysis**     | `scapy`, `dpkt`                             |
| **Data Science**        | `pandas`, `numpy`, `seaborn`, `matplotlib`  |
| **Machine Learning**    | `LightGBM`, `scikit-learn`, `PCA`, `DBSCAN` |
| **Threat Intelligence** | `AbuseIPDB`, `VirusTotal`, `AlienVault OTX` |
| **Malware Detection**   | `yara-python`, `pyclamd`                    |
| **Reporting**           | `fpdf`, `qrcode`, `hashlib`                 |
| **Environment**         | Jupyter Notebook (Python 3.10+)             |

---

## Future Enhancements

* Add live packet capture module
* Integrate Streamlit dashboard for interactive analysis
* Deploy via Docker for platform independence
* Support multi-user REST API backend
* Integrate deep learning for time-sequence threat detection

---

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](./LICENSE) file for details.

```
Copyright 2025 Sounder Raj

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0
```

---

## Author

**Sounder Raj**
GitHub: [SOUNDER-RAJ](https://github.com/SOUNDER-RAJ)
