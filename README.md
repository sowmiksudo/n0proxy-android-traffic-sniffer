# Android TCP Traffic Sniffer

A lightweight Python + Frida tool to **intercept, inspect, and analyze TCP/SSL traffic** from Android applications in real-time — without proxies or certificates.

Unlike proxy tools (Charles / Burp Suite) that require configuring WiFi settings and installing CA certificates, this tool hooks directly into Android's native `libc.so` and `libssl.so` to capture data before it leaves the process.

![TCP Sniffer](images/tcp-sniffer.png)

## 🚀 Features

- **No Proxy Required** — works on any app, even those ignoring system proxy settings.
- **Raw TCP & Decrypted SSL** — capture raw socket traffic, decrypted TLS cleartext, or both simultaneously.
- **IP:Port Resolution** — see exactly where traffic goes (`192.168.1.5:48210 → 142.250.180.46:443`), not just socket numbers.
- **Protocol Detection** — auto-identifies HTTP requests/responses, TLS handshakes with SNI hostnames, and JSON payloads.
- **Wireshark Export** — save captured traffic to `.pcap` files and open them directly in Wireshark.
- **JSON Logging** — export packets to machine-readable JSON-lines format for scripting and analysis.
- **Interactive App Picker** — run without arguments and choose from running apps on the device.
- **Keyword Filtering** — filter live output by keyword (e.g., `password`, `token`, `GET`).
- **Setup Diagnostics** — built-in `--doctor` command checks Python, ADB, Frida, and device connectivity.
- **Smart Filtering** — automatically ignores non-socket file descriptors to prevent log flooding.
- **JSON Pretty-Print** — auto-detects and pretty-prints JSON request/response bodies.
- **Capture Summary** — on exit, see total packets, bytes, direction breakdown, and unique endpoints.

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
                           [--pcap FILE] [-o FILE] [-f FILTER] [-l]
                           [--doctor] [--no-hexdump]
                           [target]

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
  -o, --output FILE     Save packets to a JSON-lines log file
  -f, --filter FILTER   Only show packets matching this keyword (case-insensitive)
  -l, --list            List running processes on the device
  --doctor              Run setup diagnostics
  --no-hexdump          Show only summary lines, suppress payload display
```

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
| `Frida server is not running` | Start the server: `adb shell "su -c '/data/local/tmp/frida-server > /dev/null 2>&1 &'"` |
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
