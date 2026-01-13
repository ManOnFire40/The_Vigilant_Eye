# 🛡️ The Vigilant Eye

A **CLI-based Threat Intelligence Aggregation Tool** that integrates multiple security intelligence providers into a single, interactive command-line interface.

The Vigilant Eye allows security analysts, SOC engineers, and students to quickly investigate **IPs, domains, URLs, and file hashes** using well-known threat intelligence APIs.

---

## 🚀 Features

### 🔍 Integrated Threat Intelligence Sources

* **AbuseIPDB** – IP reputation & abuse confidence scoring
* **IPINFO** – IP privacy, VPN, proxy, and hosting detection
* **VirusTotal** – File, URL, domain, and DNS reputation analysis

### 🧠 Smart CLI Design

* Menu-driven interface
* Interactive parameter input
* Runtime API key injection
* Optional API key persistence
* Bulk analysis via CSV files

### 📦 Bulk Processing

* Bulk IP checks
* Bulk subnet analysis
* Bulk file hash scanning
* Bulk domain and URL checks

---

## 🗂️ Project Structure

```
THE-VIGILANT-EYE
│
├── backend
│   └── API
│       ├── Abuse_IPDB.py
│       ├── IP_info_API.py
│       └── virus_total.py
│
├── main.py
├── README.md
└── requirements.txt
```

---

## ⚙️ Installation

### 1️⃣ Clone the repository

```bash
git clone https://github.com/yourusername/the-vigilant-eye.git
cd the-vigilant-eye
```

### 2️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

> Python **3.9+** is recommended

---

## ▶️ Usage

Run the application:

```bash
python main.py
```

You will be presented with the main menu:

```
===== THE VIGILANT EYE =====
1. AbuseIPDB
2. IPINFO
3. VirusTotal
4. API Key Management
0. Exit
```

---

## 🔑 API Key Management

The tool supports **runtime API key input** directly from the CLI.

### Supported Options

* Set API key for current session
* Save API key to disk for future runs

Navigate to:

```
Main Menu → API Key Management
```

### Required API Keys

| Service    | Required |
| ---------- | -------- |
| AbuseIPDB  | ✅ Yes   |
| IPINFO     | ✅ Yes   |
| VirusTotal | ✅ Yes   |

> API keys are **never hardcoded** in the source code.

---

## 📊 Supported Operations

### AbuseIPDB

* Single IP reputation check
* Subnet reputation check
* Bulk IP checks from CSV
* Bulk subnet checks from CSV

### IPINFO

* IP privacy detection (VPN / Proxy / Hosting)
* Bulk IP privacy checks from CSV

### VirusTotal

* File hash reports
* File behavior summary
* MITRE ATT&CK trees
* URL scanning & reports
* Domain reputation
* DNS resolution
* Bulk hash, URL, and domain checks

---

## 📁 CSV Format Examples

### Bulk IP CSV

```csv
ip
8.8.8.8
1.1.1.1
```

### Bulk Hash CSV

```csv
hash
d41d8cd98f00b204e9800998ecf8427e
```

---

## 🔐 Security Notes

* API keys are stored locally (if saved)
* Do **NOT** commit API keys to version control
* Add key files to `.gitignore`

---

## 🧪 Intended Use

* SOC investigations
* Threat intelligence enrichment
* Blue team tooling
* Cybersecurity education

## 🛠️ Future Enhancements

* JSON / SIEM export
* FastAPI REST interface
* Authentication & role separation
* Rate-limit handling
* Docker support

---

## 👨‍💻 Author

**Mohamed Ehab**
Senior SOC Analyst

---

## 📜 Disclaimer

This tool is intended for **educational and defensive security purposes only**. Misuse of third-party APIs may violate their terms of service.

---

⭐ If you find this project useful, consider giving it a star!
