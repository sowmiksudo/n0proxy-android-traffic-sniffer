#!/usr/bin/env python3
"""
Android TCP Traffic Sniffer
Intercept, inspect, and analyze TCP/SSL traffic from Android apps in real-time.

Usage:
    python analyzer.py com.example.app
    python analyzer.py com.example.app --mode ssl --pcap capture.pcap
    python analyzer.py --list
    python analyzer.py --doctor
"""

import frida
import sys
import os
import json
import time
import struct
import argparse
import textwrap
import subprocess
import shutil
import threading
from datetime import datetime, timezone

# On Windows, ensure stdout & stderr handle UTF-8 console output without charmap crashes
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

try:
    import hexdump as hexdump_mod
except ImportError:
    hexdump_mod = None

from colorama import Fore, Style, init as colorama_init



# ─────────────────────────────────────────────────────────────
#  PCAP Writer (Wireshark-compatible, no external dependency)
# ─────────────────────────────────────────────────────────────

class PcapWriter:
    """
    Writes captured payloads into a standard PCAP file with
    synthetic IPv4 + TCP headers so Wireshark can parse them.
    Uses LINKTYPE_RAW (101) — raw IP packets without Ethernet.
    """

    PCAP_MAGIC = 0xa1b2c3d4
    LINKTYPE_RAW = 101

    def __init__(self, filename):
        self._f = open(filename, 'wb')
        self._pkt_id = 0
        self._seq_out = 1000
        self._seq_in = 1000
        self._write_global_header()

    def _write_global_header(self):
        self._f.write(struct.pack(
            '<IHHiIII',
            self.PCAP_MAGIC, 2, 4,  # magic, major, minor
            0, 0,                    # timezone, sigfigs
            65535,                   # snaplen
            self.LINKTYPE_RAW
        ))
        self._f.flush()

    def write_packet(self, payload, src_ip, src_port, dst_ip, dst_port,
                     direction, timestamp=None):
        if timestamp is None:
            timestamp = time.time()

        raw = bytes(payload) if not isinstance(payload, bytes) else payload

        # Sequence tracking per direction
        if direction == "OUT":
            seq = self._seq_out
            self._seq_out += len(raw)
        else:
            seq = self._seq_in
            self._seq_in += len(raw)

        tcp_hdr = self._tcp_header(src_port, dst_port, seq)
        ip_hdr  = self._ip_header(src_ip, dst_ip, len(tcp_hdr) + len(raw))
        packet  = ip_hdr + tcp_hdr + raw

        ts_sec  = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)
        self._f.write(struct.pack('<IIII', ts_sec, ts_usec, len(packet), len(packet)))
        self._f.write(packet)
        self._f.flush()

    def _ip_header(self, src_ip, dst_ip, payload_len):
        self._pkt_id += 1
        hdr = struct.pack(
            '!BBHHHBBH4s4s',
            0x45, 0,                        # ver+ihl, dscp
            20 + payload_len,               # total length
            self._pkt_id & 0xFFFF, 0x4000,  # id, flags+frag (DF)
            64, 6, 0,                       # ttl, proto=TCP, checksum placeholder
            self._ip_bytes(src_ip),
            self._ip_bytes(dst_ip)
        )
        chk = self._checksum(hdr)
        return hdr[:10] + struct.pack('!H', chk) + hdr[12:]

    def _tcp_header(self, src_port, dst_port, seq):
        return struct.pack(
            '!HHIIBBHHH',
            src_port, dst_port,
            seq, 0,        # seq, ack
            0x50, 0x18,    # data offset (5 words), flags (PSH+ACK)
            65535, 0, 0    # window, checksum, urgent
        )

    @staticmethod
    def _ip_bytes(ip_str):
        try:
            parts = ip_str.split('.')
            if len(parts) == 4:
                return bytes(int(p) for p in parts)
        except (ValueError, AttributeError):
            pass
        return b'\x00\x00\x00\x00'

    @staticmethod
    def _checksum(data):
        if len(data) % 2:
            data += b'\x00'
        words = struct.unpack('!%dH' % (len(data) // 2), data)
        s = sum(words)
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def close(self):
        self._f.close()


# ─────────────────────────────────────────────────────────────
#  Protocol Detection
# ─────────────────────────────────────────────────────────────

HTTP_METHODS = (b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ',
                b'OPTIONS ', b'PATCH ', b'CONNECT ')


def detect_protocol(data):
    """Identify the application-layer protocol from raw bytes."""
    if not data or len(data) < 4:
        return None

    raw = bytes(data)

    # HTTP/2 Connection Preface (gRPC / Firestore)
    if raw.startswith(b'PRI * HTTP/2.0'):
        return "HTTP/2 Preface (gRPC/Firestore)"

    # HTTP request
    for method in HTTP_METHODS:
        if raw.startswith(method):
            line = raw.split(b'\r\n', 1)[0].decode('utf-8', errors='replace')
            if b'Upgrade: websocket' in raw or b'upgrade: websocket' in raw:
                return f"WebSocket Handshake » {line}"
            return f"HTTP » {line}"

    # HTTP response
    if raw[:5] == b'HTTP/':
        line = raw.split(b'\r\n', 1)[0].decode('utf-8', errors='replace')
        if b'101 Switching Protocols' in raw:
            return "WebSocket Handshake « 101 Switching Protocols"
        return f"HTTP « {line}"

    # gRPC stream marker
    if b'application/grpc' in raw:
        return "gRPC Stream (Firestore/Cloud)"

    # WebSocket Frame (RFC 6455)
    if len(raw) >= 2 and (raw[1] & 0x80):  # Masked client frame
        opcode = raw[0] & 0x0F
        if opcode == 0x01:
            return "WebSocket Text Frame"
        elif opcode == 0x02:
            return "WebSocket Binary Frame"
        elif opcode == 0x09:
            return "WebSocket Ping"
        elif opcode == 0x0A:
            return "WebSocket Pong"

    # TLS record (Client Hello / Server Hello)
    if len(raw) >= 6 and raw[0] == 0x16 and raw[1] == 0x03:
        if raw[5] == 0x01:
            sni = _extract_sni(raw)
            return f"TLS ClientHello → {sni}" if sni else "TLS ClientHello"
        if raw[5] == 0x02:
            return "TLS ServerHello"

    # JSON body
    try:
        text = raw[:64].decode('utf-8').lstrip()
        if text and text[0] in ('{', '['):
            return "JSON"
    except UnicodeDecodeError:
        pass

    return None


def _extract_sni(data):
    """Parse TLS ClientHello extensions to extract the SNI hostname."""
    try:
        raw = bytes(data)
        if len(raw) < 43:
            return None

        pos = 43  # past record(5) + handshake(4) + version(2) + random(32)

        # Session ID
        sid_len = raw[pos]; pos += 1 + sid_len

        # Cipher suites
        cs_len = (raw[pos] << 8) | raw[pos + 1]; pos += 2 + cs_len

        # Compression methods
        cm_len = raw[pos]; pos += 1 + cm_len

        # Extensions
        if pos + 2 > len(raw):
            return None
        ext_total = (raw[pos] << 8) | raw[pos + 1]; pos += 2
        ext_end = pos + ext_total

        while pos + 4 <= ext_end:
            ext_type = (raw[pos] << 8) | raw[pos + 1]
            ext_len  = (raw[pos + 2] << 8) | raw[pos + 3]
            pos += 4

            if ext_type == 0 and pos + 5 <= len(raw):  # SNI
                name_len = (raw[pos + 3] << 8) | raw[pos + 4]
                if pos + 5 + name_len <= len(raw):
                    return raw[pos + 5 : pos + 5 + name_len].decode('ascii', errors='replace')

            pos += ext_len
    except (IndexError, ValueError):
        pass
    return None


# ─────────────────────────────────────────────────────────────
#  Packet Statistics
# ─────────────────────────────────────────────────────────────

class PacketStats:
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.out_packets = 0
        self.in_packets = 0
        self.out_bytes = 0
        self.in_bytes = 0
        self.connections = set()
        self.start_time = time.time()

    def record(self, direction, length, remote):
        self.total_packets += 1
        self.total_bytes += length
        if direction == "OUT":
            self.out_packets += 1
            self.out_bytes += length
        else:
            self.in_packets += 1
            self.in_bytes += length
        if remote:
            self.connections.add(f"{remote.get('ip', '?')}:{remote.get('port', '?')}")

    def summary(self):
        elapsed = time.time() - self.start_time
        return (
            f"\n{'═' * 60}\n"
            f"  Capture Summary\n"
            f"{'═' * 60}\n"
            f"  Duration:      {elapsed:.1f}s\n"
            f"  Total:         {self.total_packets} packets  ({_fmt_bytes(self.total_bytes)})\n"
            f"  Outgoing (→):  {self.out_packets} packets  ({_fmt_bytes(self.out_bytes)})\n"
            f"  Incoming (←):  {self.in_packets} packets  ({_fmt_bytes(self.in_bytes)})\n"
            f"  Endpoints:     {len(self.connections)} unique\n"
            f"{'═' * 60}"
        )


def _fmt_bytes(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ─────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────

def _endpoint(info):
    if not info:
        return "unknown"
    return f"{info.get('ip', '?')}:{info.get('port', '?')}"


def _try_text(data):
    """Attempt UTF-8 decode; return string or None."""
    try:
        text = bytes(data).decode('utf-8')
        # Only return if it looks like printable text
        if text.isprintable() or any(c in text for c in '\r\n\t'):
            return text
    except (UnicodeDecodeError, TypeError):
        pass
    return None


def _try_pretty_json(text):
    """Pretty-print JSON if parseable."""
    stripped = text.strip()
    if stripped and stripped[0] in ('{', '['):
        try:
            return json.dumps(json.loads(stripped), indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def format_hexdump(data, max_bytes=256):
    """
    Format binary data as a Wireshark/xxd-style hex dump.
    Guaranteed zero-dependency fallback when the 'hexdump' module is not installed.
    """
    raw = bytes(data)[:max_bytes]
    lines = []
    for i in range(0, len(raw), 16):
        chunk = raw[i:i + 16]
        left = " ".join(f"{b:02x}" for b in chunk[:8])
        right = " ".join(f"{b:02x}" for b in chunk[8:])
        hex_str = f"{left:<23}  {right:<23}".rstrip()
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"  {Fore.LIGHTBLACK_EX}{i:04x}{Style.RESET_ALL}  {hex_str:<48}  {Fore.WHITE}|{ascii_str}|{Style.RESET_ALL}")
    if len(bytes(data)) > max_bytes:
        lines.append(f"  {Fore.YELLOW}… ({len(data) - max_bytes} more binary bytes omitted){Style.RESET_ALL}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
#  Main Sniffer
# ─────────────────────────────────────────────────────────────

class Sniffer:
    def __init__(self, args):
        self.args       = args
        self.stats      = PacketStats()
        self.pcap       = None
        self.log_fh     = None
        self.device     = None
        self.pid        = None
        self.stop_event = threading.Event()

        if args.pcap:
            self.pcap = PcapWriter(args.pcap)
            print(f"  {Fore.CYAN}PCAP:    {args.pcap}{Style.RESET_ALL}")

        if args.output:
            self.log_fh = open(args.output, 'w')
            print(f"  {Fore.CYAN}Log:     {args.output}{Style.RESET_ALL}")

    # ── Frida message callback ──────────────────────────────

    def on_message(self, message, data):
        try:
            if message['type'] == 'send':
                self._handle_packet(message['payload'], data)
            elif message['type'] == 'error':
                print(f"\n{Fore.RED}[-] Agent Error: {message['description']}{Style.RESET_ALL}")
                stack = message.get('stack', '')
                if stack:
                    print(f"    {stack}")
        except Exception as e:
            print(f"{Fore.RED}[-] Handler Error: {e}{Style.RESET_ALL}")

    def _handle_packet(self, payload, data):
        direction  = payload.get('type', '?')
        func_name  = payload.get('func', '?')
        socket_id  = payload.get('socket', -1)
        length     = payload.get('len', 0)
        local_info = payload.get('local')
        remote_info= payload.get('remote')
        ts_ms      = payload.get('ts', time.time() * 1000)
        timestamp  = ts_ms / 1000.0

        # Stats
        self.stats.record(direction, length, remote_info)

        # Protocol detection
        protocol = detect_protocol(data) if data else None

        # Keyword filter
        if self.args.filter and data:
            needle = self.args.filter.lower()
            text = _try_text(data)
            match = False
            if text and needle in text.lower():
                match = True
            if protocol and needle in protocol.lower():
                match = True
            if not match:
                return

        # ── Console output ──
        ts_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:-3]

        if direction == "OUT":
            color = Fore.GREEN
            arrow = "→"
            route = f"{_endpoint(local_info)} → {_endpoint(remote_info)}"
        else:
            color = Fore.BLUE
            arrow = "←"
            route = f"{_endpoint(remote_info)} → {_endpoint(local_info)}"

        header = (
            f"{Fore.WHITE}{ts_str}{Style.RESET_ALL} "
            f"{color}[{arrow}]{Style.RESET_ALL} "
            f"{Fore.YELLOW}{func_name:<12}{Style.RESET_ALL} "
            f"{route}  "
            f"{Fore.CYAN}{length} bytes{Style.RESET_ALL}"
        )
        if protocol:
            header += f"  {Fore.MAGENTA}[{protocol}]{Style.RESET_ALL}"
        print(header)

        # Payload display
        if data and not self.args.no_hexdump:
            text = _try_text(data)
            if text:
                pretty = _try_pretty_json(text)
                display = pretty if pretty else text
                lines = display.split('\n')
                for line in lines[:40]:
                    print(f"  {Fore.WHITE}{line.rstrip()}{Style.RESET_ALL}")
                if len(lines) > 40:
                    print(f"  {Fore.YELLOW}… ({len(lines) - 40} more lines){Style.RESET_ALL}")
            else:
                # Built-in zero-dependency hex dumper (works even without 'hexdump' pip package)
                print(format_hexdump(data))

            print(f"{Fore.WHITE}{'─' * 70}{Style.RESET_ALL}")

        # ── PCAP export ──
        if self.pcap and data:
            if local_info and local_info.get('ip') and local_info.get('port'):
                local_ip = local_info['ip']
                local_port = local_info['port']
            else:
                local_ip = '10.0.0.1'
                local_port = 49152

            if remote_info and remote_info.get('ip') and remote_info.get('port'):
                remote_ip = remote_info['ip']
                remote_port = remote_info['port']
            else:
                remote_ip = '10.0.0.2'
                remote_port = 443 if ('ssl' in func_name.lower()) else 80

            if direction == "OUT":
                src_ip, src_port = local_ip, local_port
                dst_ip, dst_port = remote_ip, remote_port
            else:
                src_ip, src_port = remote_ip, remote_port
                dst_ip, dst_port = local_ip, local_port

            self.pcap.write_packet(data, src_ip, src_port, dst_ip, dst_port,
                                   direction, timestamp)

        # ── JSON log ──
        if self.log_fh and data:
            record = {
                'timestamp': datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
                'direction': direction,
                'function':  func_name,
                'socket':    socket_id,
                'length':    length,
                'local':     local_info,
                'remote':    remote_info,
                'protocol':  protocol,
                'data_hex':  bytes(data).hex(),
                'data_text': _try_text(data),
            }
            self.log_fh.write(json.dumps(record) + '\n')
            self.log_fh.flush()

    # ── Device helpers ──────────────────────────────────────

    @staticmethod
    def _ensure_adb_server():
        """Ensure ADB daemon is running so Frida can communicate with USB devices."""
        try:
            subprocess.run(
                ["adb", "start-server"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False
            )
        except Exception:
            pass

    @staticmethod
    def _ensure_selinux_permissive():
        """Ensure SELinux is set to Permissive on rooted devices to prevent spawn/ptrace timeouts."""
        try:
            res = subprocess.run(["adb", "shell", "getenforce"],
                                 capture_output=True, text=True, timeout=3)
            if "Enforcing" in res.stdout:
                subprocess.run(["adb", "shell", "su -c 'setenforce 0'"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               timeout=3)
        except Exception:
            pass

    @staticmethod
    def _get_adb_devices():
        """Return list of (serial, status, extra) tuples from adb devices."""
        try:
            res = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, timeout=5)
            lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            devices = []
            for line in lines[1:]:  # skip 'List of devices attached'
                parts = line.split()
                if len(parts) >= 2:
                    serial = parts[0]
                    status = parts[1]
                    extra = " ".join(parts[2:]) if len(parts) > 2 else ""
                    devices.append((serial, status, extra))
            return devices
        except Exception:
            return []

    def _get_device(self):
        """
        Find and connect to the Android device.
        Automatically starts ADB daemon, handles timeouts, emulators,
        and provides clear diagnostics if unauthorized/offline.
        """
        self._ensure_adb_server()

        # 1. Explicit device requested via -D / --device
        if self.args.device:
            target_id = self.args.device.strip()
            try:
                return frida.get_device(target_id, timeout=5)
            except Exception:
                try:
                    for d in frida.enumerate_devices():
                        if target_id.lower() in (d.id.lower(), d.name.lower()):
                            return d
                except Exception:
                    pass
                raise RuntimeError(f"Device '{target_id}' not found via Frida.")

        # 2. Try standard USB device lookup with 5-second discovery window
        try:
            return frida.get_usb_device(timeout=5)
        except Exception:
            pass

        # 3. Check all devices known to Frida
        try:
            all_devices = frida.enumerate_devices()
        except Exception:
            all_devices = []

        usb_devices = [d for d in all_devices if d.type == 'usb']
        if len(usb_devices) == 1:
            return usb_devices[0]
        elif len(usb_devices) > 1:
            dev_list = ", ".join(f"{d.name} ({d.id})" for d in usb_devices)
            raise RuntimeError(
                f"Multiple USB devices found: {dev_list}. "
                f"Please specify one with -D <id>"
            )

        # 4. Check for remote / emulator devices (e.g. emulator-5554, 192.168.x.x:5555)
        remote_devices = [
            d for d in all_devices
            if d.id not in ('local', 'socket', 'barebone') and d.type != 'local'
        ]
        if len(remote_devices) == 1:
            return remote_devices[0]

        # 5. Check ADB directly to provide actionable troubleshooting
        adb_devs = self._get_adb_devices()
        if adb_devs:
            for serial, status, _ in adb_devs:
                if status == 'unauthorized':
                    raise RuntimeError(
                        f"Device '{serial}' is UNAUTHORIZED.\n"
                        f"      Unlock your phone and tap 'Allow USB debugging' on the screen."
                    )
                elif status == 'offline':
                    raise RuntimeError(
                        f"Device '{serial}' is OFFLINE.\n"
                        f"      Try reconnecting the USB cable or run: adb kill-server && adb devices"
                    )
                elif status == 'device':
                    # Device is active in ADB, attempt direct connection by serial
                    try:
                        return frida.get_device(serial, timeout=5)
                    except Exception:
                        pass
            dev_summary = ", ".join(f"{s} [{st}]" for s, st, _ in adb_devs)
            raise RuntimeError(
                f"ADB detected devices [{dev_summary}], but Frida could not connect.\n"
                f"      Try restarting ADB: adb kill-server && adb devices"
            )

        raise RuntimeError(
            "No Android device found.\n"
            "      • Connect your device via USB with 'USB Debugging' enabled.\n"
            "      • Run 'adb devices' in your terminal to verify connection."
        )

    # ── --list ──────────────────────────────────────────────

    def list_processes(self):
        device = self._get_device()
        print(f"\n{Fore.CYAN}  Device: {device.name}{Style.RESET_ALL}\n")

        # Map running PIDs to package identifiers
        app_map = {}
        try:
            for a in device.enumerate_applications():
                if a.pid > 0:
                    app_map[a.pid] = a.identifier
        except Exception:
            pass

        procs = sorted(device.enumerate_processes(), key=lambda p: p.name.lower())
        print(f"  {'PID':<8} {'Name':<32} Package ID")
        print(f"  {'─' * 8} {'─' * 32} {'─' * 35}")
        for p in procs:
            pkg = app_map.get(p.pid, "-")
            print(f"  {p.pid:<8} {p.name:<32} {pkg}")
        print(f"\n  {Fore.GREEN}{len(procs)} processes{Style.RESET_ALL}\n")

    # ── --doctor ────────────────────────────────────────────

    def run_doctor(self):
        print(f"\n{Fore.CYAN}{'═' * 55}")
        print(f"  Android TCP Sniffer — Setup Diagnostics")
        print(f"{'═' * 55}{Style.RESET_ALL}\n")

        checks = []

        # Python
        ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        checks.append(("Python", ver, sys.version_info >= (3, 7), None))

        # Frida Python library
        try:
            checks.append(("Frida Python", frida.__version__, True, None))
        except (AttributeError, NameError):
            checks.append(("Frida Python", "NOT INSTALLED", False, "Run: pip install frida-tools"))

        # hexdump library
        checks.append((
            "hexdump",
            "installed" if hexdump_mod else "built-in (zero-dep fallback active)",
            True,
            None
        ))

        # ADB
        self._ensure_adb_server()
        adb_path = shutil.which("adb")
        adb_ok = adb_path is not None
        adb_devs = self._get_adb_devices() if adb_ok else []
        if adb_ok:
            if adb_devs:
                dev_desc = ", ".join(f"{s} [{st}]" for s, st, _ in adb_devs)
                checks.append(("ADB", f"found ({dev_desc})", True, None))
            else:
                checks.append(("ADB", "found (no devices attached)", False,
                               "Connect device via USB and enable USB Debugging"))
        else:
            checks.append(("ADB", "NOT FOUND", False,
                           "Install platform-tools: https://developer.android.com/tools/releases/platform-tools"))

        # Device (via Frida)
        device = None
        try:
            device = self._get_device()
            checks.append(("Device (Frida)", f"{device.name} ({device.id})", True, None))
        except Exception as e:
            unauth = [s for s, st, _ in adb_devs if st == 'unauthorized']
            if unauth:
                checks.append(("Device (Frida)", f"UNAUTHORIZED ({unauth[0]})", False,
                               "Unlock phone and tap 'Allow USB debugging'"))
            else:
                first_line = str(e).strip().split('\n')[0]
                checks.append(("Device (Frida)", first_line, False,
                               "Check USB cable and ensure USB Debugging is ON"))

        # Frida Server on Device
        if device:
            try:
                procs = device.enumerate_processes()
                checks.append(("Frida Server", f"running & responsive ({len(procs)} processes)", True, None))
            except frida.ServerNotRunningError:
                checks.append(("Frida Server", "NOT RUNNING on device", False,
                               'Start it: adb shell "su -c \'/data/local/tmp/frida-server > /dev/null 2>&1 &\'"'))
            except frida.PermissionDeniedError:
                checks.append(("Frida Server", "permission denied (root required)", False,
                               "frida-server requires root permissions"))
            except Exception as e:
                checks.append(("Frida Server", f"error: {e}", False,
                               'Verify frida-server is running: adb shell "su -c \'/data/local/tmp/frida-server > /dev/null 2>&1 &\'"'))

        # SELinux Mode
        if device:
            try:
                se_res = subprocess.run(["adb", "shell", "getenforce"], capture_output=True, text=True, timeout=3)
                se_mode = se_res.stdout.strip()
                if se_mode == "Permissive":
                    checks.append(("SELinux Mode", "Permissive (ready for injection)", True, None))
                elif se_mode == "Enforcing":
                    checks.append(("SELinux Mode", "Enforcing (may cause spawn timeouts)", False,
                                   'Run: adb shell "su -c setenforce 0"'))
                elif se_mode:
                    checks.append(("SELinux Mode", se_mode, True, None))
            except Exception:
                pass

        # Print checklist
        for item in checks:
            name, value, ok = item[0], item[1], item[2]
            icon = f"{Fore.GREEN}✓" if ok else f"{Fore.RED}✗"
            print(f"  {icon}  {name:<18}{Style.RESET_ALL} {value}")

        passed = sum(1 for item in checks if item[2])
        print(f"\n  {Fore.CYAN}{passed}/{len(checks)} checks passed{Style.RESET_ALL}")

        # Suggestions
        failures = [item for item in checks if not item[2] and item[3]]
        if failures:
            print(f"\n  {Fore.YELLOW}Suggestions:{Style.RESET_ALL}")
            for item in failures:
                print(f"  • {item[0]}: {item[3]}")
        print()


    # ── Interactive app picker ──────────────────────────────

    def _pick_app(self, device):
        print(f"\n{Fore.CYAN}  No target specified — listing running apps …{Style.RESET_ALL}\n")

        apps = device.enumerate_applications()
        running = sorted([a for a in apps if a.pid > 0], key=lambda a: a.name.lower())

        if not running:
            print(f"  {Fore.RED}No running apps found.{Style.RESET_ALL}")
            sys.exit(1)

        for i, app in enumerate(running, 1):
            print(f"  {Fore.GREEN}{i:>3}{Style.RESET_ALL}  {app.name:<35} "
                  f"{Fore.WHITE}{app.identifier}{Style.RESET_ALL}")

        print()
        try:
            choice = input(f"  {Fore.CYAN}Select number (or type package name): {Style.RESET_ALL}").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(running):
                return running[idx].identifier, running[idx].pid
            print(f"  {Fore.RED}Invalid selection.{Style.RESET_ALL}")
            sys.exit(1)

        return choice, None

    # ── Main entry ──────────────────────────────────────────

    def run(self):
        args = self.args

        # --- Special modes ---
        if args.doctor:
            self.run_doctor()
            return
        if args.list:
            self.list_processes()
            return

        # --- Connect device ---
        try:
            self.device = self._get_device()
            self._ensure_selinux_permissive()
        except Exception as e:
            print(f"\n  {Fore.RED}[-] Cannot connect to device: {e}{Style.RESET_ALL}")
            print(f"      Run '{Fore.YELLOW}python analyzer.py --doctor{Style.RESET_ALL}' to diagnose.\n")
            sys.exit(1)

        # --- Resolve target ---
        target = args.target
        attach_pid = None

        if not target:
            target, attach_pid = self._pick_app(self.device)

        # --- Resolve target to PID if attaching ---
        if target and target.isdigit():
            attach_pid = int(target)
            args.attach = True
        elif target and args.attach and attach_pid is None:
            # Check applications by package identifier or display name
            try:
                for app in self.device.enumerate_applications():
                    if (app.identifier.lower() == target.lower() or app.name.lower() == target.lower()) and app.pid > 0:
                        attach_pid = app.pid
                        break
            except Exception:
                pass

            # Fallback: check running processes by process name or substring
            if attach_pid is None:
                try:
                    for proc in self.device.enumerate_processes():
                        if proc.name.lower() == target.lower() or target.lower() in proc.name.lower():
                            attach_pid = proc.pid
                            print(f"  {Fore.YELLOW}[i] Matched running process '{proc.name}' (PID {attach_pid}).{Style.RESET_ALL}")
                            break
                except Exception:
                    pass

        # --- Determine which agents to load ---
        script_dir = os.path.dirname(os.path.abspath(__file__))
        agents = []
        if args.mode in ('tcp', 'all'):
            agents.append(os.path.join(script_dir, 'agent.js'))
        if args.mode in ('ssl', 'all'):
            agents.append(os.path.join(script_dir, 'ssl_agent.js'))

        # --- Banner ---
        print(f"\n{Fore.CYAN}{'═' * 60}")
        print(f"  Android TCP Sniffer")
        print(f"{'═' * 60}{Style.RESET_ALL}")
        print(f"  Target:  {Fore.GREEN}{target}{Style.RESET_ALL}")
        print(f"  Mode:    {Fore.GREEN}{args.mode}{Style.RESET_ALL}")
        print(f"  Method:  {Fore.GREEN}{'attach' if args.attach else 'spawn'}{Style.RESET_ALL}")
        print(f"  Device:  {Fore.GREEN}{self.device.name}{Style.RESET_ALL}")
        if args.filter:
            print(f"  Filter:  {Fore.GREEN}{args.filter}{Style.RESET_ALL}")

        # (pcap/log paths printed by __init__ above)
        print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")

        if target and 'chrome' in target.lower() and ':' not in target:
            print(f"  {Fore.YELLOW}[!] Chrome Tip: Chromium uses a separate network process{Style.RESET_ALL}")
            print(f"      and QUIC (UDP) for web browsing. For best results, test a standard app")
            print(f"      (e.g. social, banking, or university apps), or disable QUIC in chrome://flags.\n")

        # --- Attach / Spawn ---
        try:
            if args.attach:
                pid_or_name = attach_pid if attach_pid else target
                session = self.device.attach(pid_or_name)
                print(f"  {Fore.GREEN}[*] Attached to process.{Style.RESET_ALL}")
            else:
                self.pid = self.device.spawn([target])
                session = self.device.attach(self.pid)
                print(f"  {Fore.GREEN}[*] Spawned {target} (PID {self.pid}).{Style.RESET_ALL}")

            def _on_detached(reason, crash):
                print(f"\n  {Fore.RED}[!] Detached: {reason}{Style.RESET_ALL}")
                if crash:
                    print(f"      {crash}")
                self.stop_event.set()
            session.on('detached', _on_detached)

            # Load agent scripts
            for path in agents:
                with open(path, 'r', encoding='utf-8') as fh:
                    code = fh.read()
                script = session.create_script(code)
                script.on('message', self.on_message)
                script.load()

            if not args.attach and self.pid is not None:
                self.device.resume(self.pid)

            print(f"  {Fore.GREEN}[*] Sniffer running. Press Ctrl+C to stop.{Style.RESET_ALL}\n")
            try:
                while not self.stop_event.is_set():
                    time.sleep(0.2)
            except KeyboardInterrupt:
                print(f"\n  {Fore.YELLOW}[*] Stopping …{Style.RESET_ALL}")

        except frida.TimedOutError as e:
            print(f"\n  {Fore.RED}[-] Timed out waiting for app to launch: {e}{Style.RESET_ALL}")
            print(f"      {Fore.YELLOW}Tip: This happens on Android 12+ when SELinux is 'Enforcing'.{Style.RESET_ALL}")
            print('      1. Run:  adb shell "su -c setenforce 0"')
            print(f'      2. Or launch app on phone and attach: python analyzer.py {target} -a')
        except frida.TransportError as e:
            print(f"\n  {Fore.RED}[-] Agent transport error: {e}{Style.RESET_ALL}")
            print(f"      {Fore.YELLOW}Tip: SELinux Enforcing blocks ptrace injection.{Style.RESET_ALL}")
            print('      Run: adb shell "su -c setenforce 0"')
        except frida.ServerNotRunningError:
            print(f"\n  {Fore.RED}[-] Frida server is not running on the device.{Style.RESET_ALL}")
            print('      Start it:  adb shell "su -c \'/data/local/tmp/frida-server > /dev/null 2>&1 &\'"')
            print('      Setup:     See FRIDA_SETUP_GUIDE.md for download & installation instructions.')
        except frida.NotSupportedError as e:
            print(f"\n  {Fore.RED}[-] Frida cannot attach (server not running or jailed Android):{Style.RESET_ALL}")
            print(f"      {e}")
            print('      Start it:  adb shell "su -c \'/data/local/tmp/frida-server > /dev/null 2>&1 &\'"')
            print('      Setup:     See FRIDA_SETUP_GUIDE.md for download & installation instructions.')
        except frida.ProcessNotFoundError:
            print(f"\n  {Fore.RED}[-] Process '{target}' not found.{Style.RESET_ALL}")
            print(f"      Use  python analyzer.py --list  to see running processes.")
        except frida.InvalidArgumentError as e:
            print(f"\n  {Fore.RED}[-] Invalid target: {e}{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n  {Fore.YELLOW}[*] Stopping …{Style.RESET_ALL}")
        finally:
            self._cleanup()

    def _cleanup(self):
        if self.stats.total_packets > 0:
            print(self.stats.summary())

        if self.pcap:
            self.pcap.close()
            print(f"  {Fore.CYAN}[*] PCAP saved → {self.args.pcap}{Style.RESET_ALL}")

        if self.log_fh:
            self.log_fh.close()
            print(f"  {Fore.CYAN}[*] JSON log saved → {self.args.output}{Style.RESET_ALL}")

        if self.pid and self.device:
            try:
                self.device.kill(self.pid)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────
#  CLI Argument Parser
# ─────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog='android-tcp-sniffer',
        description='Intercept and analyze TCP/SSL traffic from Android apps.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s com.example.app                       # spawn & sniff SSL
              %(prog)s com.example.app -m tcp                # raw TCP sockets only
              %(prog)s com.example.app -m all --pcap out.pcap
              %(prog)s com.example.app --attach              # attach to running app
              %(prog)s com.example.app -f "password"         # filter by keyword
              %(prog)s com.example.app -o session.json       # save JSON log
              %(prog)s                                       # interactive app picker
              %(prog)s --list                                # list running processes
              %(prog)s --doctor                              # diagnose your setup
        """),
    )

    parser.add_argument(
        'target', nargs='?', default=None,
        help='Package name or PID  (interactive picker if omitted)')
    parser.add_argument(
        '-m', '--mode', choices=['tcp', 'ssl', 'all'], default='ssl',
        help='Capture mode - tcp: raw sockets, ssl: decrypted TLS (default), all: both')
    parser.add_argument(
        '-a', '--attach', action='store_true',
        help='Attach to a running process instead of spawning it')
    parser.add_argument(
        '-d', '-D', '--device', default=None,
        help='Frida device ID (default: first USB device)')
    parser.add_argument(
        '--pcap', metavar='FILE',
        help='Save traffic to a Wireshark-compatible PCAP file')
    parser.add_argument(
        '-o', '--output', metavar='FILE',
        help='Save packets to a JSON-lines log file')
    parser.add_argument(
        '-f', '--filter', default=None,
        help='Only display packets matching this keyword (case-insensitive)')
    parser.add_argument(
        '-l', '--list', action='store_true',
        help='List running processes on the device and exit')
    parser.add_argument(
        '--doctor', action='store_true',
        help='Run setup diagnostics and exit')
    parser.add_argument(
        '--no-hexdump', action='store_true',
        help='Suppress payload display, show header lines only')

    return parser


# ─────────────────────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────────────────────

def main():
    colorama_init()
    args = build_parser().parse_args()
    Sniffer(args).run()


if __name__ == '__main__':
    main()