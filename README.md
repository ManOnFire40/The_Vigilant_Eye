## 🛡️ The Vigilant Eye (In Development)

**The Vigilant Eye** is a powerful desktop application designed for SOC (Security Operations Center) analysts to swiftly investigate and correlate IP-related threat intelligence. It integrates with top threat intelligence platforms including **VirusTotal**, **AbuseIPDB**, and **IPinfo** to provide real-time enrichment and contextual data for IP addresses and IOC.

---
<div align="center">
<img src="https://github.com/user-attachments/assets/1ae23fef-a1a1-4f79-b4d0-1a71e9e5a9e2" alt="black_D3" width="500"/>
<div/>

---

### 🚀 Features

* 🔍 **IP Lookup**
  Fetch detailed information about any IP address including geolocation, ASN, and provider details.

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
---


### 🔧 Configuration

Create a `.env` or config file to store your API keys:

```
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
IPINFO_API_KEY=your_ipinfo_key
```



---

### 🧑‍💻 Contributing

Contributions are welcome! Please open issues or submit pull requests to help improve the tool.

---


### 📣 Disclaimer

This tool is intended for legitimate security research and SOC operations. Misuse for unauthorized surveillance or privacy violation is strictly discouraged.
