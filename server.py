"""WLAN Logger - live scan of nearby Wi-Fi networks, streamed to a browser page.

Browsers have no Wi-Fi API, so this small local server runs the OS scanner
(netsh on Windows, nmcli on Linux) and pushes results to the page over
Server-Sent Events. Every scan is also appended to logs/wlan-YYYY-MM-DD.csv.

Run:  python server.py   then open http://localhost:8765
"""

import csv
import json
import os
import platform
import re
import subprocess
import threading
import time
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("WLAN_PORT", "8765"))
SCAN_INTERVAL = 5  # seconds
ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(ROOT, "logs")

LOCATION_HINTS = ("location", "standort", "requires elevation", "access is denied")


class ScanError(Exception):
    def __init__(self, message, kind="error"):
        super().__init__(message)
        self.kind = kind  # "location" when Windows location permission blocks scanning


def _run(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return proc.returncode, proc.stdout + proc.stderr


def trigger_windows_rescan():
    """Ask Windows for a fresh scan. netsh only reports the cached results of the
    last scan, which Windows refreshes rarely while connected. The new results
    are ready a few seconds later, i.e. by the next cycle."""
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("d1", wintypes.DWORD), ("d2", wintypes.WORD), ("d3", wintypes.WORD), ("d4", ctypes.c_ubyte * 8)]

    class INTERFACE_INFO(ctypes.Structure):
        _fields_ = [("guid", GUID), ("desc", ctypes.c_wchar * 256), ("state", wintypes.DWORD)]

    class INTERFACE_LIST(ctypes.Structure):
        _fields_ = [("count", wintypes.DWORD), ("index", wintypes.DWORD), ("items", INTERFACE_INFO * 1)]

    wlan = ctypes.windll.wlanapi
    handle, version = wintypes.HANDLE(), wintypes.DWORD()
    if wlan.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)) != 0:
        return
    try:
        plist = ctypes.POINTER(INTERFACE_LIST)()
        if wlan.WlanEnumInterfaces(handle, None, ctypes.byref(plist)) != 0:
            return
        count = plist.contents.count
        items = ctypes.cast(ctypes.addressof(plist.contents.items), ctypes.POINTER(INTERFACE_INFO * count)).contents
        for info in items:
            wlan.WlanScan(handle, ctypes.byref(info.guid), None, None, None)
        wlan.WlanFreeMemory(plist)
    finally:
        wlan.WlanCloseHandle(handle, None)


def scan_windows():
    try:
        trigger_windows_rescan()
    except Exception:
        pass  # fall back to whatever Windows has cached
    code, out = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    if code != 0 or "SSID" not in out:
        lower = out.lower()
        if any(h in lower for h in LOCATION_HINTS):
            raise ScanError(out.strip(), kind="location")
        raise ScanError(out.strip() or "netsh returned no data")

    networks, ssid, auth, enc = [], "", "", ""
    current = None
    for raw in out.splitlines():
        line = raw.strip()
        m = re.match(r"^SSID \d+\s*:\s*(.*)$", line)
        if m:
            ssid, auth, enc = m.group(1).strip(), "", ""
            continue
        m = re.match(r"^BSSID \d+\s*:\s*(.*)$", line)
        if m:
            current = {"ssid": ssid or "<hidden>", "bssid": m.group(1).strip().lower(),
                       "auth": auth, "encryption": enc, "signal": None,
                       "radio": "", "band": "", "channel": "", "stations": ""}
            networks.append(current)
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "authentication":
            auth = val
        elif key == "encryption":
            enc = val
        elif current is not None:
            if key == "signal":
                current["signal"] = int(val.rstrip("%") or 0)
            elif key == "radio type":
                current["radio"] = val
            elif key == "band":
                current["band"] = val
            elif key == "channel":
                current["channel"] = val
            elif key == "connected stations":
                current["stations"] = val
    return networks


def scan_linux():
    code, out = _run(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,FREQ,SECURITY", "dev", "wifi", "list", "--rescan", "auto"])
    if code != 0:
        raise ScanError(out.strip() or "nmcli failed")
    networks = []
    for line in out.splitlines():
        # nmcli -t escapes ':' inside fields as '\:'
        parts = re.split(r"(?<!\\):", line)
        if len(parts) < 6:
            continue
        ssid, bssid, signal, chan, freq, sec = [p.replace("\\:", ":") for p in parts[:6]]
        networks.append({"ssid": ssid or "<hidden>", "bssid": bssid.lower(), "auth": sec,
                         "encryption": "", "signal": int(signal or 0), "radio": "",
                         "band": freq, "channel": chan, "stations": ""})
    return networks


def scan():
    system = platform.system()
    if system == "Windows":
        return scan_windows()
    if system == "Linux":
        return scan_linux()
    raise ScanError(f"Scanning not supported on {system}")


class Scanner(threading.Thread):
    """Scans in the background and fans results out to all connected browsers."""

    def __init__(self):
        super().__init__(daemon=True)
        self.lock = threading.Lock()
        self.latest = {"type": "status", "message": "Starting first scan..."}
        self.listeners = []

    def subscribe(self):
        cond = threading.Condition()
        with self.lock:
            self.listeners.append(cond)
        return cond

    def unsubscribe(self, cond):
        with self.lock:
            self.listeners.remove(cond)

    def publish(self, payload):
        with self.lock:
            self.latest = payload
            listeners = list(self.listeners)
        for cond in listeners:
            with cond:
                cond.notify_all()

    def log(self, ts, networks):
        os.makedirs(LOG_DIR, exist_ok=True)
        path = os.path.join(LOG_DIR, f"wlan-{ts[:10]}.csv")
        new_file = not os.path.exists(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(["timestamp", "ssid", "bssid", "signal_pct", "channel", "band", "radio", "auth", "encryption"])
            for n in networks:
                w.writerow([ts, n["ssid"], n["bssid"], n["signal"], n["channel"], n["band"], n["radio"], n["auth"], n["encryption"]])

    def run(self):
        while True:
            ts = datetime.now().isoformat(timespec="seconds")
            try:
                networks = scan()
                self.log(ts, networks)
                self.publish({"type": "scan", "time": ts, "networks": networks})
            except ScanError as e:
                self.publish({"type": "error", "kind": e.kind, "time": ts, "message": str(e)})
            except Exception as e:  # keep the loop alive on unexpected parse errors
                self.publish({"type": "error", "kind": "error", "time": ts, "message": repr(e)})
            time.sleep(SCAN_INTERVAL)


scanner = Scanner()


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.join(ROOT, "static"), **kwargs)

    def log_message(self, fmt, *args):
        pass  # keep the console for scan output only

    def do_GET(self):
        if self.path == "/stream":
            return self.stream()
        if self.path == "/info":
            body = json.dumps({"platform": platform.system(), "interval": SCAN_INTERVAL,
                               "logDir": LOG_DIR}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return super().do_GET()

    def stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        cond = scanner.subscribe()
        try:
            notified = True
            while True:
                if notified:
                    with scanner.lock:
                        payload = scanner.latest
                    self.wfile.write(f"data: {json.dumps(payload)}\n\n".encode())
                else:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
                with cond:
                    notified = cond.wait(timeout=15)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        finally:
            scanner.unsubscribe(cond)


if __name__ == "__main__":
    scanner.start()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"WLAN Logger running on http://localhost:{PORT}  (logs -> {LOG_DIR})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
