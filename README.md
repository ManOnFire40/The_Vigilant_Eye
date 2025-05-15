


![White_D3](https://github.com/user-attachments/assets/7ac8e704-73a9-4241-8aaa-a3c0809fd1a9)


## 🛡️ The Vigilant Eye

**The Vigilant Eye** is a powerful desktop application designed for SOC (Security Operations Center) analysts to swiftly investigate and correlate IP-related threat intelligence. It integrates with top threat intelligence platforms including **VirusTotal**, **AbuseIPDB**, and **IPinfo** to provide real-time enrichment and contextual data for IP addresses.

---

### 🚀 Features

* 🔍 **IP Lookup**
  Fetch detailed information about any IP address including geolocation, ASN, and provider details via **IPinfo**.

* ⚠️ **Threat Intelligence**
  Identify malicious indicators like:

  * VPN or Tor usage
  * Hosting providers
  * Abuse scores
  * VirusTotal detections and last analysis

* 🧠 **Correlation View**
  A unified view that merges data across all three platforms to help analysts quickly identify suspicious infrastructure.

* 🖥️ **User-Friendly Desktop UI**
  Lightweight and intuitive interface designed for quick and responsive investigations.

---

### 🔗 Integrations

* [VirusTotal](https://www.virustotal.com/)
* [AbuseIPDB](https://www.abuseipdb.com/)
* [IPinfo](https://ipinfo.io/)

> Note: API keys for each service are required. Free-tier keys are supported.

---

### 🛠️ Installation

```bash
git clone https://github.com/ManOnFire40/the-vigilant-eye.git
cd the-vigilant-eye
python -m venv myenv
source myenv/bin/activate  # or myenv\Scripts\activate on Windows
```

---

### 🔧 Configuration

Create a `.env` or config file to store your API keys:

```
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
IPINFO_API_KEY=your_ipinfo_key
```

---

### 📁 Project Structure

```
the-vigilant-eye/
│
├── API/                  # API integrations (VirusTotal, IPinfo, AbuseIPDB)
├── API_DB/               # Local database or log storage
├── modules/              # Helper modules or business logic
├── main.py               # Application entry point
├── README.md
└── .gitignore
```

---

### 🧑‍💻 Contributing

Contributions are welcome! Please open issues or submit pull requests to help improve the tool.

---


### 📣 Disclaimer

This tool is intended for legitimate security research and SOC operations. Misuse for unauthorized surveillance or privacy violation is strictly discouraged.
