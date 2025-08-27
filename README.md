# VulnScan 🔍

VulnScan is a lightweight, asynchronous vulnerability scanner written in Python.  
It performs **port scanning, banner grabbing, fingerprinting, and CVE lookups** to detect potential vulnerabilities in target systems — like a mini-Nessus.

---

## ✨ Features
- ⚡ Asynchronous port scanning (fast and efficient)
- 📡 Banner grabbing for common protocols (HTTP, HTTPS, SMTP, etc.)
- 🌐 HTTP title & server header detection
- 🔐 TLS certificate inspection
- 🧩 Fingerprint matching (using `signatures/fingerprints.json`)
- 📊 CVE lookup integration (NVD client, extendable)
- 🎨 Rich console reporting
- 💾 JSON output option

---

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/goliakash/vulnscan.git
   cd vulnscan
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage

Run the scanner against a target:

```bash
python vulnscan.py <target> [--start-port 1 --end-port 1024 --concurrency 200 --save]
```

### Example:
```bash
python vulnscan.py www.example.com --start-port 80 --end-port 1000 --concurrency 300 --save
```

- `--start-port` → starting port number (default: 1)  
- `--end-port` → ending port number (default: 1024)  
- `--concurrency` → number of concurrent scans (default: 200)  
- `--save` → save results as JSON  

---

## 📂 Project Structure

```
vulnscan/
├─ vulnscan.py           # CLI entrypoint (async main)
├─ scanner/
│  ├─ portscan.py        # async port connect + banner grabbing
│  ├─ httpgrab.py        # http title/server header grabbing
│  ├─ tlsgrab.py         # get cert info (optional)
│  └─ fingerprint.py     # match banner -> fingerprint -> product/version
├─ cvelookup/
│  └─ nvd_client.py      # interface to query CVE data (skeleton)
├─ signatures/
│  └─ fingerprints.json  # local fingerprints DB
└─ output/
   └─ formatter.py       # json / pretty printing
```

---

## 🔮 Future Improvements
- [ ] Add database-backed CVE lookup (NVD API or CIRCL API)
- [ ] Add brute-force login modules (SSH, FTP, etc.)
- [ ] Add OS fingerprinting (like Nmap)
- [ ] Add web vulnerability modules (SQLi, XSS detection)

---

## ⚠️ Disclaimer

This tool is for **educational and authorized penetration testing purposes only**.  
Do **NOT** use it against systems you do not own or have explicit permission to test.  

---

Made with ❤️ by [Goli Akash]
