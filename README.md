# Android TCP Traffic Sniffer

A lightweight Python + Frida tool to intercept, inspect, and analyze raw TCP traffic from Android applications in real-time.

Unlike proxy tools (Charles/Burp) which require configuring WiFi settings and CA certificates, this tool hooks directly into the Android native `libc.so` to capture data before it leaves the device.

## 🚀 Features

* **No Proxy Required:** Works on any app, even those ignoring system proxy settings.
* **Raw TCP Capture:** Intercepts `send`, `recv`, `read`, and `write` system calls.
* **Smart Filtering:** Automatically ignores non-socket file descriptors to prevent log flooding.
* **Auto-Decoding:** Attempts to decode UTF-8 text (HTTP/JSON) automatically.
* **Hexdump View:** Full binary inspection for encrypted or custom protocols.
* **Resilience:** Works on both 32-bit and 64-bit Android architectures.

## 📋 Prerequisites

1.  **Rooted Android Device** or Emulator.
2.  **Frida Server** running on the device.
3.  **Python 3.x** installed on your PC.
4.  **ADB** installed and added to PATH.

## 🛠️ Installation

1.  Clone this repository:
    ```bash
    git clone [https://github.com/sowmiksudo/android-tcp-sniffer.git](https://github.com/sowmiksudo/android-tcp-sniffer.git)
    cd android-tcp-sniffer
    ```

2.  Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## ⚡ Usage

1.  **Connect your device** via USB and ensure ADB is working:
    ```bash
    adb devices
    ```

2.  **Run the sniffer** with the target package name:
    ```bash
    python analyzer.py com.example.app
    ```

3.  **Trigger traffic** in the app. You will see colored logs of outgoing (`->`) and incoming (`<-`) packets.

## 📝 Troubleshooting

* **Error: `Frida server is not running`**
    * Make sure you started the server on the phone: `adb shell "su -c /data/local/tmp/frida-server &"`
* **Error: `Process not found`**
    * Verify the package name using `frida-ps -U`.
* **Logs are "garbage" / unreadable?**
    * The traffic is likely TLS encrypted (HTTPS). This tool hooks the *network* layer. To see plaintext HTTPS, you would need to hook `SSL_write` / `SSL_read` in `libssl.so` instead.

## Test
This script was tested on android 14, rooted with magisk. MagiskFrida was used for frida server on android.

## ⚠️ Disclaimer

This tool is for **educational purposes and security research only**. Do not use it to intercept traffic from applications you do not own or have permission to test.