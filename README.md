# Android TCP Traffic Sniffer

A lightweight Python + Frida tool to **intercept, decrypt, and export Android application traffic directly into Burp Suite, Caido, OWASP ZAP, and Wireshark** in real-time — with **zero proxy configuration**, **no CA certificates**, and **100% immunity to SSL pinning**.

Unlike traditional proxy setups that require complex Wi-Fi proxies, iptables redirection, and custom user certificate injection (which modern Android apps often block with Certificate Pinning or custom BoringSSL/Cronet/Flutter stacks), **Android TCP Sniffer hooks directly into Android's native memory space** (`libc.so`, `libssl.so`, `libboringssl.so`) to capture cleartext data before encryption. It automatically reassembles fragmented TCP streams into HTTP flows and exports them directly into industry-standard pentesting tools.

![TCP Sniffer](images/tcp-sniffer.png)

## 🚀 Core Capabilities

- **🎯 Native Burp Suite Export (`--burp`)** — export decrypted HTTPS traffic directly into Burp Suite XML items. Right-click **Target → Restore items** in Burp Suite to inspect, replay, or scan pinned app traffic!
- **🌐 Universal HAR 1.2 Export (`--har`)** — export standard HTTP Archive files compatible with **Burp Suite**, **Caido**, **OWASP ZAP**, **Postman**, and browser DevTools.
- **🦈 Wireshark PCAP Export (`--pcap`)** — stream synthetic IPv4+TCP packets into Wireshark-compatible `.pcap` files with zero external dependencies.
- **🔓 Zero-Proxy & Pinning-Proof** — works on any app, including those with hardcoded certificate pins, Flutter apps, gRPC streams, or apps ignoring system proxies.
- **⚡ Raw TCP & Decrypted SSL** — inspect raw socket traffic (`send`/`recv`), decrypted TLS cleartext (`SSL_write`/`SSL_read`), or both simultaneously.
- **📍 Real Endpoint Resolution** — shows exact source and destination endpoints (`192.168.1.5:48210 → 142.250.180.46:443`), not just opaque file descriptors.
- **🔍 Protocol Detection & SNI Parsing** — automatically identifies HTTP requests/responses, TLS handshakes with SNI hostnames, and JSON payloads.
- **📄 JSON-Lines Logging (`-o`)** — stream structured JSON records with timestamps, hex, and UTF-8 decoded data for automated pipelines.
- **🎯 Live Keyword Filtering (`-f`)** — filter output in real-time by keyword (e.g., `password`, `token`, `GET`).
- **📱 Interactive App Picker** — run with no arguments to pick from currently running apps with a single keystroke.
- **🩺 Setup Diagnostics (`--doctor`)** — built-in diagnostic suite validates Python, Frida, ADB, SELinux mode, and phone daemon health in seconds.

## 📋 Prerequisites

1. **Rooted Android Device** or Emulator
2. **Frida Server** running on the device (see [Frida Server Setup Guide](FRIDA_SETUP_GUIDE.md))
3. **Python 3.7+** installed on your PC
4. **ADB** installed and added to PATH

## 🛠️ Installation

```bash
git clone https://github.com/sowmiksudo/android-tcp-sniffer.git
cd android-tcp-sniffer
pip install -r requirements.txt
```

## ⚡ Quick Start

```bash
# 1. Connect your device via USB
adb devices

# 2. Sniff SSL traffic (default mode)
python analyzer.py com.example.app

# 3. Or just run without arguments for the interactive app picker
python analyzer.py
```

## 📖 CLI Reference

```
usage: android-tcp-sniffer [-h] [-m {tcp,ssl,all}] [-a] [-d DEVICE]
                           [--pcap FILE] [--burp FILE] [--har FILE]
                           [-o FILE] [-f FILTER] [-l] [--doctor]
                           [--no-hexdump] [target]

positional arguments:
  target                Package name or PID (interactive picker if omitted)

options:
  -m, --mode {tcp,ssl,all}
                        Capture mode (default: ssl)
                          tcp  — raw send/recv/read/write hooks on libc.so
                          ssl  — decrypted SSL_read/SSL_write hooks
                          all  — both layers simultaneously
  -a, --attach          Attach to a running process instead of spawning
  -d, --device DEVICE   Frida device ID (default: first USB device)
  --pcap FILE           Save traffic to a Wireshark-compatible PCAP file
  --burp FILE           Save HTTP/HTTPS traffic to Burp Suite XML items file
  --har FILE            Save HTTP/HTTPS traffic to standard HAR file (Burp/Caido/ZAP)
  -o, --output FILE     Save packets to a JSON-lines log file
  -f, --filter FILTER   Only show packets matching this keyword (case-insensitive)
  -l, --list            List running processes on the device
  --doctor              Run setup diagnostics
  --no-hexdump          Show only summary lines, suppress payload display
```

## 🎯 Core Highlight: Multi-Tool Export Suite (Burp, Caido, ZAP, Wireshark)

> [!IMPORTANT]
> **Why this is the heart of Android TCP Sniffer:**
> Getting mobile app traffic into a proxy like **Burp Suite** or **Caido** has become painful due to modern mobile security mechanisms:
> - ❌ Apps implement **SSL Certificate Pinning** (`NetworkSecurityConfig`, OkHttp `CertificatePinner`, TrustKit, or custom C++ verifiers).
> - ❌ Apps bypass the Android OS network stack entirely using **Flutter (Dart SSL)**, **Google Cronet**, or **native BoringSSL**.
> - ❌ Apps explicitly ignore system Wi-Fi proxy settings.
>
> **Android TCP Sniffer eliminates these roadblocks completely.** By intercepting cleartext payloads directly within the process memory space immediately before encryption (`SSL_write`) or after decryption (`SSL_read`), it bypasses all certificate pinning and proxy restrictions. It then reassembles fragmented TCP streams into complete HTTP flows and exports them directly into whichever pentesting software your workflow relies on.

### 📊 Supported Export Formats Matrix

| Pentesting / Analysis Tool | CLI Flag | Output Format | How to Import |
|---|---|---|---|
| **Burp Suite Professional** | `--burp capture.xml` | Native Burp Items XML (Base64) | **Target** tab → Right-click **Site map** → **Restore items** → Select `capture.xml` |
| **Burp Suite Community** | `--burp capture.xml` or `--har capture.har` | Burp XML / HAR 1.2 | Import via BApp extensions: **Burp Import**, **HTTP History Importer**, or **HAR Importer** |
| **Caido** | `--har capture.har` | HTTP Archive 1.2 | In Caido: Go to **Replay** / Settings → Drag & drop or **Import HAR** |
| **OWASP ZAP** | `--har capture.har` | HTTP Archive 1.2 | In ZAP: Menu **Import** → **Import a HAR file** |
| **Postman** | `--har capture.har` | HTTP Archive 1.2 | In Postman: **Import** → Select `.har` to auto-generate a runnable API collection |
| **Wireshark** | `--pcap capture.pcap` | Standard PCAP (LINKTYPE_RAW) | In Wireshark: **File** → **Open** → Full packet dissection with TCP reassembly |
| **Automated Pipelines / SIEM** | `-o session.json` | Structured JSON-Lines | Line-delimited JSON with timestamps, hex, and decoded strings |

---

### 🛠️ Export Workflows & Step-by-Step Guides

#### 1. Exporting Directly into Burp Suite
Bypass all SSL pinning and view decrypted app traffic directly in Burp Suite's Target sitemap and Repeater:
```bash
python analyzer.py com.example.app --burp burp_traffic.xml
```
- **In Burp Suite Professional:**
  1. Open Burp Suite and navigate to the **Target** tab.
  2. Right-click anywhere in the **Site map** pane.
  3. Select **Restore items** from the context menu.
  4. Select `burp_traffic.xml`.
  5. Every endpoint, request header, query parameter, body, and server response immediately populates your Site Map tree and can be sent straight to **Repeater (Ctrl+R)**, **Intruder**, or **Scanner**!
- **In Burp Suite Community:**
  1. Open Burp's **Extender / Extensions** tab → **BApp Store**.
  2. Install **Burp Import** or **HTTP History Importer**.
  3. Load `burp_traffic.xml` directly into your **HTTP history** tab.

#### 2. Exporting Universal HAR for Caido & OWASP ZAP
Export all captured HTTP/HTTPS traffic to the universal HTTP Archive standard:
```bash
python analyzer.py com.example.app --har capture.har
```
- **Caido:** Navigate to **Replay** or **Settings → Import**, then drop `capture.har` in.
- **OWASP ZAP:** Go to **Import → Import a HAR file**.
- **Postman:** Go to **Import**, select `capture.har`, and Postman will automatically generate organized HTTP requests and environments.

#### 3. Simultaneous Multi-Format Capture (All-in-One)
You can combine flags to generate Wireshark PCAPs, Burp XML, HAR files, and JSON logs simultaneously in a single session:
```bash
python analyzer.py com.example.app \
  --burp burp.xml \
  --har capture.har \
  --pcap traffic.pcap \
  -o session.json
```

---

## 📝 Usage Examples

### Basic Sniffing (SSL Mode)

```bash
python analyzer.py com.example.app
```

Output:

```
═══════════════════════════════════════════════════════════
  Android TCP Sniffer
═══════════════════════════════════════════════════════════
  Target:  com.example.app
  Mode:    ssl
  Method:  spawn
  Device:  Pixel 6
═══════════════════════════════════════════════════════════

14:32:05.421 [→] SSL_write    192.168.1.5:48210 → 142.250.180.46:443  326 bytes  [HTTP » GET /api/v1/user HTTP/1.1]
  GET /api/v1/user HTTP/1.1
  Host: api.example.com
  Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
──────────────────────────────────────────────────────────────────────

14:32:05.583 [←] SSL_read     142.250.180.46:443 → 192.168.1.5:48210  1024 bytes  [JSON]
  {
    "id": 12345,
    "name": "John Doe",
    "email": "john@example.com"
  }
──────────────────────────────────────────────────────────────────────
```

### Raw TCP Mode

```bash
python analyzer.py com.example.app --mode tcp
```

### Combined Mode (TCP + SSL)

```bash
python analyzer.py com.example.app --mode all
```

> **Note:** In `all` mode, SSL connections will produce two sets of packets — raw encrypted data from TCP hooks and decrypted plaintext from SSL hooks. This is useful for comparing both layers.

### Attach to a Running App

```bash
python analyzer.py com.example.app --attach
```

### Export to Wireshark PCAP

```bash
python analyzer.py com.example.app --pcap capture.pcap
# Then open capture.pcap in Wireshark
```

### Export to JSON Log

```bash
python analyzer.py com.example.app -o session.json
```

Each line in the log is a JSON object:

```json
{
  "timestamp": "2025-01-15T14:32:05.421000+00:00",
  "direction": "OUT",
  "function": "SSL_write",
  "socket": 42,
  "length": 326,
  "local": {"ip": "192.168.1.5", "port": 48210, "family": 4},
  "remote": {"ip": "142.250.180.46", "port": 443, "family": 4},
  "protocol": "HTTP » GET /api/v1/user HTTP/1.1",
  "data_hex": "474554202f6170692f...",
  "data_text": "GET /api/v1/user HTTP/1.1\r\n..."
}
```

### Filter by Keyword

```bash
# Only show packets containing "password"
python analyzer.py com.example.app -f "password"

# Only show HTTP GET requests
python analyzer.py com.example.app -f "GET"
```

### Interactive App Picker

```bash
python analyzer.py
```

```
  No target specified — listing running apps …

    1  Chrome                              com.android.chrome
    2  Gmail                               com.google.android.gm
    3  Settings                            com.android.settings
    ...

  Select number (or type package name): 1
```

### Setup Diagnostics

```bash
python analyzer.py --doctor
```

```
═══════════════════════════════════════════════════════
  Android TCP Sniffer — Setup Diagnostics
═══════════════════════════════════════════════════════

  ✓  Python             3.11.4
  ✓  Frida Python       16.1.4
  ✓  hexdump            installed
  ✓  ADB                found
  ✓  USB Device         Pixel 6
  ✓  Frida Server       running

  6/6 checks passed
```

### List Running Processes

```bash
python analyzer.py --list
```

```
  Device: Pixel 6

  PID      Name                              Package ID
  ───────  ────────────────────────────────  ───────────────────────────────────
  15339    Chrome                            com.android.chrome
  24409    Google Play Store                 com.android.vending
  13107    WhatsApp                          com.whatsapp
  28224    YouTube                           com.google.android.youtube
  1128     netd                              -

  243 processes
```

## 🔧 Project Structure

```
android-tcp-sniffer/
├── analyzer.py            # Main CLI entry point & packet handler
├── agent.js               # Frida agent: raw TCP hooks (send/recv/read/write)
├── ssl_agent.js           # Frida agent: decrypted SSL hooks (SSL_read/SSL_write)
├── diag.js                # Frida diagnostic script (environment sanity check)
├── FRIDA_SETUP_GUIDE.md   # Step-by-step frida-server setup guide
├── requirements.txt
└── images/
```

## 🔍 Troubleshooting

| Problem | Solution |
|---------|----------|
| `need Gadget to attach on jailed Android` | `frida-server` is not installed or running. See [FRIDA_SETUP_GUIDE.md](FRIDA_SETUP_GUIDE.md) |
| `Frida server is not running` | Start the server: `adb shell "su -c 'chmod 777 /data/local/tmp/frida-server && /data/local/tmp/frida-server > /dev/null 2>&1 &'"` |
| `Process not found` | Check the package name with `python analyzer.py --list` |
| Logs are garbled / unreadable | The traffic is TLS encrypted. Use `--mode ssl` (the default) to see cleartext |
| Version mismatch errors | Ensure frida-server on device matches `python -c "import frida; print(frida.__version__)"` |
| No output at all | Try `--mode all` to capture both layers. Some apps use custom TLS libraries |
| Chrome shows no traffic | Chrome uses a separate network process (`:privileged_process0`) and QUIC (UDP). Test standard Android apps or disable QUIC in `chrome://flags` |
| `--doctor` shows failures | Follow the hints printed by the diagnostics output |

## 🧪 Tested On

- Android 14, rooted with KsuNext
- frida-server: 17.9.1 

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or pull requests.

## 👤 Author

[@sowmiksudo](https://github.com/sowmiksudo) | [sowmiksudo.github.io](https://sowmiksudo.github.io)

## ⚠️ Disclaimer

This tool is for **educational purposes and security research only**. Do not use it to intercept traffic from applications you do not own or have permission to test.
