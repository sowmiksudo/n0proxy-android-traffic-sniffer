# Frida Server Setup Guide for Android

This guide walks you through setting up `frida-server` on your Android device so you can intercept TCP/SSL traffic using **Android TCP Sniffer**.

---

## Why am I seeing `need Gadget to attach on jailed Android`?

If you see this error:
```text
frida.NotSupportedError: need Gadget to attach on jailed Android; its default location is: ...
```
It means **Frida Server is not currently running on your Android device** (or the device is unrooted / "jailed"). 

On Android, Frida needs a root agent daemon (`frida-server`) listening on the device to inject into apps. Without `frida-server` running, Frida assumes you are on an unrooted device and looks for a Frida Gadget `.so` embedded inside the target APK.

Follow the quick steps below to install and run `frida-server`.

---

## Prerequisites

1. **Rooted Android Device** (Magisk, KernelSU, APatch, or SuperSU) or an Android Emulator (AVD, Genymotion, LDPlayer, Nox).
2. **USB Debugging** enabled in Developer Options.
3. **ADB installed** and accessible on your PC command line.

---

## Step 1: Find Your Phone's CPU Architecture

Open PowerShell or terminal on your PC and run:

```bash
adb shell getprop ro.product.cpu.abi
```

Match the output to the Frida download artifact:

| Output | CPU Architecture | Download Name Pattern |
|---|---|---|
| `arm64-v8a` *(most modern phones)* | 64-bit ARM | `frida-server-*-android-arm64.xz` |
| `armeabi-v7a` / `armeabi` | 32-bit ARM | `frida-server-*-android-arm.xz` |
| `x86_64` *(most PC emulators)* | 64-bit Intel/AMD | `frida-server-*-android-x86_64.xz` |
| `x86` | 32-bit Intel/AMD | `frida-server-*-android-x86.xz` |

---

## Step 2: Check Your PC's Frida Version

The `frida-server` version on your phone **must match** your PC's installed Frida library version:

```bash
python -c "import frida; print(frida.__version__)"
```

*Example output:* `17.9.1`

---

## Step 3: Download `frida-server`

1. Go to the official [Frida GitHub Releases](https://github.com/frida/frida/releases).
2. Find the release corresponding to your Frida version (e.g. `17.9.1`).
3. Expand **Assets** and look for:
   ```text
   frida-server-<VERSION>-android-<ARCH>.xz
   ```
   *For example:* `frida-server-17.9.1-android-arm64.xz`
4. Download the file to your PC.

---

## Step 4: Extract the `.xz` Archive

The downloaded file is compressed with `xz`. Extract it to get the raw executable binary:

- **Option A (Python — works everywhere without extra tools):**
  ```powershell
  python -c "import lzma, glob; f=glob.glob('frida-server*android*.xz')[0]; open('frida-server', 'wb').write(lzma.open(f).read()); print('Extracted: frida-server')"
  ```
- **Option B (7-Zip on Windows):** Right-click the `.xz` file → 7-Zip → Extract Here.
- **Option C (Linux / macOS):**
  ```bash
  unxz frida-server-*.xz
  mv frida-server-*-android-* frida-server
  ```

Rename the extracted binary to `frida-server` for simplicity.

---

## Step 5: Push and Run on Android

Run the following commands from your PC terminal:

### 1. Push binary to Android temporary directory:
```bash
adb push frida-server /data/local/tmp/
```

### 2. Grant executable permissions:
```bash
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
```

### 3. Start `frida-server` in background:
```bash
adb shell "su -c '/data/local/tmp/frida-server > /dev/null 2>&1 &'"
```

> [!NOTE]
> **Harmless Warning Notice**: If you see:
> ```text
> libsepol.avtab_read: table is empty
> Unable to load SELinux policy from the kernel: unsupported policy database format
> ```
> **This is completely normal and harmless!** It is an informational warning from Frida's bundled SELinux parser on modern Android kernels (Android 12/13/14) and OEM ROMs (ColorOS, OxygenOS, HyperOS, OneUI). Frida Server is already running in the background.
>
> Using `> /dev/null 2>&1 &` ensures the process detaches cleanly and returns you immediately to your command prompt without hanging the terminal.
>
> *(Also remember to approve the Magisk / Superuser root prompt on your phone if prompted).*

---

## Step 6: Verify Frida is Working

Run the sniffer's built-in diagnostics tool on your PC:

```bash
python analyzer.py --doctor
```

You should see:
```text
  ✓  ADB                found (...)
  ✓  Device (Frida)     RMX3686 (...)
  ✓  Frida Server       running & responsive (...)
```

You can now list all processes and apps with:
```bash
python analyzer.py --list
```

And start sniffing traffic:
```bash
python analyzer.py com.example.app
```

---

## Pro Tip: Automatic 1-Click Installer (Python)

You can run this quick Python script from your PC to automatically detect your phone's architecture, download the exact matching `frida-server` from GitHub, push it to `/data/local/tmp/`, and launch it:

```python
import urllib.request, json, lzma, subprocess, sys

# 1. Get Frida version and device ABI
import frida
ver = frida.__version__
abi = subprocess.check_output(["adb", "shell", "getprop", "ro.product.cpu.abi"], text=True).strip()
arch_map = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "x86_64": "x86_64", "x86": "x86"}
arch = arch_map.get(abi, "arm64")

filename = f"frida-server-{ver}-android-{arch}.xz"
url = f"https://github.com/frida/frida/releases/download/{ver}/{filename}"

print(f"[*] Downloading {filename} ...")
urllib.request.urlretrieve(url, filename)

print("[*] Extracting ...")
with lzma.open(filename) as f_in, open("frida-server", "wb") as f_out:
    f_out.write(f_in.read())

print("[*] Pushing to device ...")
subprocess.run(["adb", "push", "frida-server", "/data/local/tmp/frida-server"], check=True)
subprocess.run(["adb", "shell", "su -c 'chmod 755 /data/local/tmp/frida-server'"], check=True)

print("[*] Starting frida-server ...")
subprocess.run(["adb", "shell", "su -c '/data/local/tmp/frida-server &'"], check=True)
print("[✓] Frida server is up and running!")
```

---

## Troubleshooting

### 1. `frida-server` stops when phone restarts
Android's `/data/local/tmp` preserves the binary, but the process terminates on phone reboot. After restarting your phone, just run:
```bash
adb shell "su -c '/data/local/tmp/frida-server &'"
```
Alternatively, install the **MagiskFrida** module in Magisk/KernelSU to automatically start `frida-server` on boot.

### 2. `Permission denied` when running `su`
Ensure your device is rooted and that your root manager (Magisk, KernelSU, APatch) has granted Shell (UID 2000) superuser permissions.

### 3. Non-Rooted ("Jailed") Devices
If you do not have root access on your phone:
- You cannot run `frida-server` as a global system daemon.
- Instead, you must embed **Frida Gadget** directly into the APK by repackaging it:
  ```bash
  pip install objection
  objection patchapk --source myapp.apk --architecture arm64-v8a
  adb install myapp.objection.apk
  ```
  Once the patched app is opened on the phone, Frida can attach to it without root.
