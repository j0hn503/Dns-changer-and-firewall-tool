"""
Telegram Exfiltration Blocker & DNS Optimizer
---------------------------------------------
A modern Windows network security GUI that:
  - Blocks known Telegram IP ranges to stop cookie exfiltration.
  - Applies any of a list of free, unlimited public DNS resolvers to active adapters.
  - Flushes the Windows DNS cache.
  - Opens a browser ad-blocking test page (in a private window) to verify the DNS you picked.
  - Sets up a NextDNS profile (advanced DNS) with a guided defaults / extra-rules flow.
  - Restores default network parameters seamlessly.

Requires: Windows, Python 3.8+, customtkinter.
The app starts as a normal user. Firewall and DNS changes need Administrator
rights, so it offers an "Enable admin" button instead of asking at startup.
Double-click firewall_gui.pyw to start it without any console window.
"""

import os
import sys
import base64
import ctypes
import ipaddress
import re
import shutil
import socket
import threading
import time
import subprocess
import webbrowser
import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox

# --------------------------------------------------------------------------
# Configuration & Rules
# --------------------------------------------------------------------------

TELEGRAM_IPS = [
    "149.154.160.0/20", "149.154.164.0/22", "149.154.166.0/23",
    "149.154.167.0/24", "91.108.4.0/22", "91.108.56.0/22", "91.108.8.0/21",
]
TELEGRAM_IP_LIST = ",".join(TELEGRAM_IPS)

TELEGRAM_RULES = [
    {"name": "Block-Telegram-IPs-Out", "kind": "ip", "value": TELEGRAM_IP_LIST, "dir": "out"},
    {"name": "Block-Telegram-IPs-In", "kind": "ip", "value": TELEGRAM_IP_LIST, "dir": "in"},
]

# Browser-based test that checks which ad / tracker domains actually get blocked.
# It works well for DNS-level blocking (it requests many real ad domains).
AD_TEST_URL = "https://adblock.turtlecute.org/"

# --------------------------------------------------------------------------
# NextDNS (advanced resolver) — values taken from the saved profile HTML
# --------------------------------------------------------------------------
# The profile below is the one captured in "html (1).txt" / "html (2).txt".
# It is a temporary NextDNS account that lives in the browser for 7 days.
NEXTDNS_PROFILE_ID = "2d3ed4"
NEXTDNS_HOME = f"https://my.nextdns.io/{NEXTDNS_PROFILE_ID}"
NEXTDNS_SETUP = f"{NEXTDNS_HOME}/setup"
NEXTDNS_SECURITY = f"{NEXTDNS_HOME}/security"
NEXTDNS_PRIVACY = f"{NEXTDNS_HOME}/privacy"

# --------------------------------------------------------------------------
# Hosts-file domain blocking
# --------------------------------------------------------------------------

HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                          "System32", "drivers", "etc", "hosts")
HOSTS_BACKUP_DIR = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")),
    "NetworkSecurityStudio", "hosts-backups")
HOSTS_BLOCK_START = "# >>> Network Security Studio - blocked domains >>>"
HOSTS_BLOCK_END = "# <<< Network Security Studio - blocked domains <<<"
TELEGRAM_DOMAINS = ["telegram.org", "www.telegram.org", "t.me", "web.telegram.org"]

# Free public DNS resolvers with no query limits (no account needed).
# tag: category label shown on the card.
PUBLIC_DNS = [
    # ---- No filtering ----
    {"name": "Cloudflare (Standard)", "tag": "No filter", "servers": ["1.1.1.1", "1.0.0.1"],
     "desc": "Blocks nothing. Fast and privacy-focused. Good baseline for comparing the others."},
    {"name": "Google Public DNS", "tag": "No filter", "servers": ["8.8.8.8", "8.8.4.4"],
     "desc": "Blocks nothing. Very reliable, but no malware or ad protection at all."},
    {"name": "Quad9 (Unfiltered)", "tag": "No filter", "servers": ["9.9.9.10", "149.112.112.10"],
     "desc": "Blocks nothing and has no malware filtering. Resolves everything, with DNSSEC validation."},
    {"name": "AdGuard (Non-filtering)", "tag": "No filter", "servers": ["94.140.14.140", "94.140.14.141"],
     "desc": "Blocks nothing. A plain resolver from AdGuard."},

    # ---- Security only ----
    {"name": "Cloudflare Security", "tag": "Security", "servers": ["1.1.1.2", "1.0.0.2"],
     "desc": "Blocks known malware and phishing domains. Does NOT block ads or trackers."},
    {"name": "Quad9 (Secured)", "tag": "Security", "servers": ["9.9.9.9", "149.112.112.112"],
     "desc": "Blocks malware, phishing and botnet command-and-control domains using threat-intelligence feeds. No ad blocking."},
    {"name": "OpenDNS (Standard)", "tag": "Security", "servers": ["208.67.222.222", "208.67.220.220"],
     "desc": "Blocks known phishing sites only. Does not block ads or general malware."},
    {"name": "CleanBrowsing Security", "tag": "Security", "servers": ["185.228.168.9", "185.228.169.9"],
     "desc": "Blocks malware, phishing and known malicious domains. Adult and ad content still resolve."},
    {"name": "Control D (Malware)", "tag": "Security", "servers": ["76.76.2.2", "76.76.10.2"],
     "desc": "Blocks malware and phishing domains only. No ad blocking."},

    # ---- Ads + Security ----
    {"name": "AdGuard DNS (Default)", "tag": "Ads + Security", "servers": ["94.140.14.14", "94.140.15.15"],
     "desc": "Blocks ads, trackers, malware and phishing domains. Best all-round pick for ad blocking on a router."},
    {"name": "Control D (Ads & Trackers)", "tag": "Ads + Security", "servers": ["76.76.2.1", "76.76.10.1"],
     "desc": "Blocks malware plus ad and tracking domains."},
    {"name": "Control D (Ads + Social)", "tag": "Ads + Security", "servers": ["76.76.2.3", "76.76.10.3"],
     "desc": "Blocks malware, ads, trackers AND social-network domains (Facebook, TikTok and similar)."},
    {"name": "Mullvad DNS (discontinued)", "tag": "Ads + Security", "servers": ["194.242.2.3", "194.242.2.4"],
     "desc": "Variants were: adblock (ads + trackers), base (ads, trackers, malware), extended (+ social media), "
             "family (+ adult, gambling).",
     "note": "Mullvad shut down its public DNS on November 2, 2026 and now sponsors Quad9, so these IPs will stop "
             "working. Use AdGuard DNS (Default) or Control D (Ads & Trackers) for the same kind of blocking.",
     "disabled": True},

    # ---- Family / adult filtering ----
    {"name": "Cloudflare Family", "tag": "Family", "servers": ["1.1.1.3", "1.0.0.3"],
     "desc": "Blocks malware, phishing AND adult content. No ad blocking."},
    {"name": "OpenDNS FamilyShield", "tag": "Family", "servers": ["208.67.222.123", "208.67.220.123"],
     "desc": "Blocks adult content plus phishing sites. Preconfigured, no account needed."},
    {"name": "AdGuard DNS (Family)", "tag": "Family", "servers": ["94.140.14.15", "94.140.15.16"],
     "desc": "Everything in AdGuard Default, plus adult content blocking and enforced Safe Search."},
    {"name": "CleanBrowsing Family", "tag": "Family", "servers": ["185.228.168.168", "185.228.169.168"],
     "desc": "Blocks adult content, proxies/VPN sites and malware, and enforces Safe Search. Strictest of the list."},
]

TAG_COLORS = {
    "No filter": "#52525b",
    "Security": "#15803d",
    "Ads + Security": "#2563eb",
    "Family": "#b45309",
}

# --------------------------------------------------------------------------
# Admin & Process Execution
# --------------------------------------------------------------------------

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def hide_own_console():
    """Hide the console only when it was created for this script (double-click).

    When started from an existing terminal, that terminal is attached too and
    stays visible.
    """
    try:
        kernel32 = ctypes.windll.kernel32
        hwnd = kernel32.GetConsoleWindow()
        if not hwnd:
            return
        pids = (ctypes.c_uint * 16)()
        count = kernel32.GetConsoleProcessList(pids, 16)
        if 0 < count <= 1:
            ctypes.windll.user32.ShowWindow(hwnd, 0)   # SW_HIDE
    except Exception:
        pass


def relaunch_as_admin() -> bool:
    try:
        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = " ".join(f'"{arg}"' for arg in sys.argv[1:])
        else:
            script = os.path.abspath(sys.argv[0])
            pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
            exe = pythonw if os.path.isfile(pythonw) else sys.executable
            params = " ".join(f'"{arg}"' for arg in sys.argv[1:])
            params = f'"{script}" {params}'.strip()
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return int(result) > 32
    except Exception:
        return False


ADMIN_HINT = ("Administrator rights are required for this action. "
              "Click 'Enable admin' at the top right, then try again.")


def require_admin(textbox=None) -> bool:
    if is_admin():
        return True
    if textbox is not None:
        log_text(textbox, "[FAIL] " + ADMIN_HINT)
    return False


# --------------------------------------------------------------------------
# Hosts File Operations
# --------------------------------------------------------------------------

def read_hosts_text() -> str:
    with open(HOSTS_PATH, "rb") as f:
        data = f.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def parse_blocked_domains(text: str) -> list:
    domains = []
    inside = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == HOSTS_BLOCK_START:
            inside = True
            continue
        if stripped == HOSTS_BLOCK_END:
            inside = False
            continue
        if not inside or not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            host = parts[1].lower()
            if host not in domains:
                domains.append(host)
    return domains


def build_hosts_text(original: str, domains: list) -> str:
    lines = original.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    kept = []
    inside = False
    for line in lines:
        stripped = line.strip()
        if stripped == HOSTS_BLOCK_START:
            inside = True
            continue
        if stripped == HOSTS_BLOCK_END:
            inside = False
            continue
        if not inside:
            kept.append(line)

    while kept and not kept[-1].strip():
        kept.pop()

    if domains:
        kept.append("")
        kept.append(HOSTS_BLOCK_START)
        for domain in domains:
            kept.append(f"0.0.0.0 {domain}")
            kept.append(f":: {domain}")
        kept.append(HOSTS_BLOCK_END)

    return "\r\n".join(kept) + "\r\n"


def write_hosts_text(text: str) -> tuple:
    try:
        with open(HOSTS_PATH, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        return True, ""
    except PermissionError:
        return False, "Access denied — administrator rights are required."
    except Exception as exc:
        return False, str(exc)


def backup_hosts_file() -> str:
    os.makedirs(HOSTS_BACKUP_DIR, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    dest = os.path.join(HOSTS_BACKUP_DIR, f"hosts_{stamp}.bak")
    shutil.copy2(HOSTS_PATH, dest)
    return dest


def normalize_hostname(raw: str) -> str:
    value = raw.strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if value.count(":") == 1:
        value = value.rsplit(":", 1)[0]
    value = value.strip(".")
    if re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
        return value
    return ""

def run_args(args, timeout=15):
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, shell=False, creationflags=0x08000000
        )
        out = ((r.stdout or "") + "\n" + (r.stderr or "")).strip()
        return r.returncode, out
    except FileNotFoundError:
        return None, f"Command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return -1, f"Command timed out after {timeout} seconds."
    except Exception as e:
        return 1, f"Unexpected error: {e}"

# --------------------------------------------------------------------------
# Firewall Operations
# --------------------------------------------------------------------------

def netsh_add_rule(rule):
    base = ["netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule['name']}", f"dir={rule['dir']}", "action=block", "enable=yes", f"remoteip={rule['value']}"]
    return run_args(base)

def netsh_delete_rule(name):
    return run_args(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])

def netsh_show_rule(name):
    return run_args(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}", "verbose"])

# --------------------------------------------------------------------------
# DNS Management Operations via PowerShell
# --------------------------------------------------------------------------

def set_system_dns(servers: list) -> tuple:
    server_string = ",".join(f"'{s}'" for s in servers)
    ps_command = (
        "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
        f"Set-DnsClientServerAddress -ServerAddresses ({server_string})"
    )
    return run_args(["powershell", "-NoProfile", "-Command", ps_command])

def reset_system_dns() -> tuple:
    # NOTE: plain string (not an f-string), so single braces are correct here.
    ps_command = (
        "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
        "Set-DnsClientServerAddress -ResetServerAddresses"
    )
    return run_args(["powershell", "-NoProfile", "-Command", ps_command])

def flush_dns_cache() -> tuple:
    return run_args(["ipconfig", "/flushdns"])

# --------------------------------------------------------------------------
# Clipboard & Private Browser Helpers
# --------------------------------------------------------------------------

def copy_to_clipboard(widget, text: str) -> bool:
    """Copy text to the Windows clipboard (Tk first, PowerShell as backup)."""
    ok = False
    try:
        widget.clipboard_clear()
        widget.clipboard_append(text)
        widget.update_idletasks()
        ok = True
    except Exception:
        pass

    # Tk only owns the clipboard while the app runs; PowerShell makes it sticky.
    try:
        payload = base64.b64encode(text.encode("utf-8")).decode("ascii")
        ps = ("[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')) | Set-Clipboard"
              % payload)
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, timeout=10, creationflags=0x08000000,
        )
        ok = ok or res.returncode == 0
    except Exception:
        pass
    return ok


def _default_browser_progid() -> str:
    """ProgId of the default http handler (ChromeHTML, MSEdgeHTM, FirefoxURL...)."""
    try:
        import winreg
        path = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            return str(winreg.QueryValueEx(key, "ProgId")[0])
    except Exception:
        return ""


def _browser_candidates() -> dict:
    local = os.environ.get("LOCALAPPDATA", "")
    pf = os.environ.get("PROGRAMFILES", r"C:\Program Files")
    pf86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
    return {
        "Chrome": (["--incognito"], [
            os.path.join(pf, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(local, "Google", "Chrome", "Application", "chrome.exe"),
        ]),
        "Edge": (["--inprivate"], [
            os.path.join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(local, "Microsoft", "Edge", "Application", "msedge.exe"),
        ]),
        "Brave": (["--incognito"], [
            os.path.join(pf, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
            os.path.join(pf86, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
            os.path.join(local, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
        ]),
        "Firefox": (["-private-window"], [
            os.path.join(pf, "Mozilla Firefox", "firefox.exe"),
            os.path.join(pf86, "Mozilla Firefox", "firefox.exe"),
        ]),
    }


def open_private_window(url: str) -> tuple:
    """Open url in a private/incognito window of the default-ish browser.

    Returns (opened, description). No extensions load in private windows,
    so ad-block tests reflect DNS filtering only.
    """
    candidates = _browser_candidates()
    progid = _default_browser_progid().lower()
    order = ["Edge", "Chrome", "Brave", "Firefox"]
    if "chrome" in progid:
        order = ["Chrome", "Edge", "Brave", "Firefox"]
    elif "firefox" in progid:
        order = ["Firefox", "Edge", "Chrome", "Brave"]
    elif "brave" in progid:
        order = ["Brave", "Chrome", "Edge", "Firefox"]

    for name in order:
        flags, paths = candidates[name]
        exe = next((p for p in paths if p and os.path.isfile(p)), None)
        if not exe:
            continue
        try:
            subprocess.Popen([exe, *flags, url], creationflags=0x08000000)
            return True, f"{name} private window"
        except Exception:
            continue
    return False, ""

# --------------------------------------------------------------------------
# UI Action Dispatchers
# --------------------------------------------------------------------------

def log_text(textbox, text):
    textbox.configure(state="normal")
    textbox.insert("end", text + "\n")
    textbox.see("end")
    textbox.configure(state="disabled")

def clear_box(textbox):
    textbox.configure(state="normal")
    textbox.delete("1.0", "end")
    textbox.configure(state="disabled")

def action_block(rules, textbox):
    clear_box(textbox)
    if not require_admin(textbox):
        return
    all_ok = True
    for rule in rules:
        netsh_delete_rule(rule["name"])
        code, out = netsh_add_rule(rule)
        if code == 0:
            log_text(textbox, f"[OK] BLOCKED: {rule['name']}")
        else:
            log_text(textbox, f"[FAIL] FAILED: {rule['name']}\nReason: {out}")
            all_ok = False
    log_text(textbox, "\n>> RESULT: TELEGRAM IPS BLOCKED" if all_ok else "\n>> RESULT: PARTIAL / FAILED")

def action_remove(rules, textbox):
    clear_box(textbox)
    if not require_admin(textbox):
        return
    for rule in rules:
        code, out = netsh_delete_rule(rule["name"])
        if code == 0:
            log_text(textbox, f"[OK] REMOVED: {rule['name']}")
        elif "no rules match" in out.lower():
            log_text(textbox, f"[INFO] NOT PRESENT: {rule['name']}")
        else:
            log_text(textbox, f"[FAIL] FAILED: {rule['name']}\nReason: {out}")
    log_text(textbox, "\n>> RESULT: OPERATION COMPLETE")

def action_check(rules, textbox):
    clear_box(textbox)
    all_present = True
    for rule in rules:
        code, out = netsh_show_rule(rule["name"])
        present = code == 0 and "no rules match" not in out.lower()
        all_present = all_present and present
        status = "[ACTIVE]" if present else "[MISSING]"
        log_text(textbox, f"{status} {rule['name']}")
    log_text(textbox, "\n>> RESULT: ALL RULES ACTIVE" if all_present else "\n>> RESULT: SOME RULES MISSING")

def action_test(unused_arg, textbox):
    clear_box(textbox)
    log_text(textbox, "Resolving api.telegram.org and verifying IP blocks...\n")

    target_host = "api.telegram.org"
    test_ips = []
    try:
        test_ips = list(set(socket.gethostbyname_ex(target_host)[2]))
        log_text(textbox, f"[INFO] Found active API endpoints: {', '.join(test_ips)}\n")
    except Exception as e:
        log_text(textbox, f"[INFO] DNS Resolution bypassed/failed ({e}). Testing static range samples instead.\n")

    samples = ["149.154.167.50", "91.108.56.100", "149.154.160.10"]
    for ip in samples:
        if ip not in test_ips:
            test_ips.append(ip)

    any_accessible = False
    any_blocked = False

    for ip in test_ips:
        log_text(textbox, f"Checking connectivity to {ip} on port 443...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        try:
            s.connect((ip, 443))
            log_text(textbox, "  -> STATUS: NOT BLOCKED (Connection Established)\n")
            any_accessible = True
        except socket.timeout:
            log_text(textbox, "  -> STATUS: BLOCKED (Dropped / Timed Out)\n")
            any_blocked = True
        except Exception as e:
            log_text(textbox, f"  -> STATUS: BLOCKED (Connection Denied: {e})\n")
            any_blocked = True
        finally:
            s.close()

    if any_accessible:
        log_text(textbox, ">> RESULT: WARNING - Leak detected. Telegram traffic is passing through.")
    elif any_blocked:
        log_text(textbox, ">> RESULT: SUCCESS - All target IP endpoints verified fully BLOCKED.")
    else:
        log_text(textbox, ">> RESULT: Unable to verify (No endpoints could be verified).")

def action_dns_apply(provider, textbox):
    """Apply a DNS provider from PUBLIC_DNS to all active adapters, then flush the cache."""
    clear_box(textbox)
    if not require_admin(textbox):
        return
    log_text(textbox, f"Applying {provider['name']} ({' / '.join(provider['servers'])}) to active adapters...")
    code, out = set_system_dns(provider["servers"])
    if code == 0:
        log_text(textbox, "[OK] DNS servers set.")
        fcode, fout = flush_dns_cache()
        log_text(textbox, "[OK] DNS cache flushed." if fcode == 0 else f"[WARN] Flush failed: {fout}")
        log_text(textbox, f"\n>> RESULT: {provider['name']} is now active.")
        log_text(textbox, "Tip: click 'Open Ad-Block Test' to see what this DNS blocks.")
    else:
        log_text(textbox, f"\n>> RESULT: Execution Failed.\nReason: {out}")

def action_dns_reset(_unused, textbox):
    clear_box(textbox)
    if not require_admin(textbox):
        return
    log_text(textbox, "Resetting system DNS to automatic assignment (DHCP)...")
    code, out = reset_system_dns()
    if code == 0:
        flush_dns_cache()
        log_text(textbox, "\n>> RESULT: DNS restored to automatic (DHCP) and cache flushed.")
    else:
        log_text(textbox, f"\n>> RESULT: Execution Failed.\nReason: {out}")

# --------------------------------------------------------------------------
# GUI Application
# --------------------------------------------------------------------------

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("Network Security Studio")
        self.geometry("1000x760")
        self.configure(fg_color="#18181b")

        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(fill="x", padx=20, pady=(20, 10))
        self.header_frame.grid_columnconfigure(0, weight=1)

        self.title_label = ctk.CTkLabel(self.header_frame, text="Network & Exfiltration Controller", font=ctk.CTkFont(size=24, weight="bold"))
        self.title_label.grid(row=0, column=0, sticky="w")

        self.sub_label = ctk.CTkLabel(self.header_frame, text="Manage Windows Firewall rules and secure DNS endpoints to mitigate risks.", text_color="gray60")
        self.sub_label.grid(row=1, column=0, sticky="w")

        if is_admin():
            ctk.CTkLabel(self.header_frame, text="  ADMIN  ", fg_color="#15803d", corner_radius=6,
                         font=ctk.CTkFont(size=11, weight="bold"), text_color="white"
                         ).grid(row=0, column=1, rowspan=2, sticky="e", padx=(12, 0))
        else:
            self.btn_admin = ctk.CTkButton(
                self.header_frame, text="Limited mode — Enable admin", width=240, height=34,
                fg_color="#b45309", hover_color="#92400e",
                font=ctk.CTkFont(size=12, weight="bold"),
                command=self.enable_admin)
            self.btn_admin.grid(row=0, column=1, rowspan=2, sticky="e", padx=(12, 0))

        self.tabview = ctk.CTkTabview(self, corner_radius=10, fg_color="#27272a", segmented_button_fg_color="#18181b", segmented_button_selected_color="#2563eb", segmented_button_selected_hover_color="#1d4ed8")
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.tab_telegram = self.tabview.add("Telegram IPs")
        self.tab_dns = self.tabview.add("DNS Control")
        self.tab_advanced = self.tabview.add("Advanced DNS")
        self.tab_hosts = self.tabview.add("Domain Block")

        # Group the four firewall-related tabs together under "Telegram IPs".
        inner = ctk.CTkTabview(
            self.tab_telegram, corner_radius=10, fg_color="#1f1f23",
            segmented_button_fg_color="#18181b",
            segmented_button_selected_color="#7c3aed",
            segmented_button_selected_hover_color="#6d28d9",
        )
        inner.pack(fill="both", expand=True, padx=5, pady=5)

        self.tab_block = inner.add("Block")
        self.tab_remove = inner.add("Remove")
        self.tab_check = inner.add("Check")
        self.tab_test = inner.add("Test Rules")

        self.build_standard_tab(self.tab_block, action_block, "Click below to block Telegram IPs in Windows Firewall.", "Block Telegram IPs")
        self.build_standard_tab(self.tab_remove, action_remove, "Click below to clear custom rules from Windows Firewall.", "Remove Telegram Rules")
        self.build_standard_tab(self.tab_check, action_check, "Click below to audit current firewall rules status.", "Check Rules Status")
        self.build_standard_tab(self.tab_test, action_test, "Click below to scan live Telegram IP addresses directly.", "Test Connection Paths")
        self.build_dns_tab()
        self.build_nextdns_tab()
        self.build_hosts_tab()

    def enable_admin(self):
        self.btn_admin.configure(state="disabled", text="Waiting for Windows…")
        if relaunch_as_admin():
            self.after(2000, self.destroy)
        else:
            self._safe_config(self.btn_admin, state="normal", text="Limited mode — Enable admin")
            messagebox.showwarning(
                "Administrator",
                "Windows did not allow elevation.\n\nRight-click firewall_gui.py and choose 'Run as administrator'.",
                parent=self,
            )

    def build_standard_tab(self, parent_tab, action_func, help_text, button_text):
        parent_tab.grid_columnconfigure(0, weight=1)
        parent_tab.grid_rowconfigure(1, weight=1)

        btn_frame = ctk.CTkFrame(parent_tab, fg_color="transparent")
        btn_frame.grid(row=0, column=0, sticky="ew", pady=(10, 15))
        btn_frame.grid_columnconfigure(0, weight=1)

        textbox = ctk.CTkTextbox(parent_tab, font=ctk.CTkFont("Consolas", size=13), fg_color="#111113", text_color="#e4e4e7", corner_radius=8, border_width=1, border_color="#3f3f46")
        textbox.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        log_text(textbox, help_text)

        def run_in_thread():
            btn_action.configure(state="disabled")
            def worker():
                action_func(TELEGRAM_RULES if action_func != action_test else None, textbox)
                self.after(0, lambda: btn_action.configure(state="normal"))
            threading.Thread(target=worker, daemon=True).start()

        btn_action = ctk.CTkButton(btn_frame, text=button_text, height=40, font=ctk.CTkFont(weight="bold"), fg_color="#2563eb", hover_color="#1d4ed8", command=run_in_thread)
        btn_action.grid(row=0, column=0, sticky="ew", padx=5)

    # ------------------------------------------------------------------
    # Domain blocking via the hosts file
    # ------------------------------------------------------------------
    def build_hosts_tab(self):
        tab = self.tab_hosts
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        # ---------------- Header ----------------
        hdr = ctk.CTkFrame(tab, fg_color="#1f1f23", corner_radius=12)
        hdr.grid(row=0, column=0, sticky="ew", padx=5, pady=(8, 6))
        hdr.grid_columnconfigure(0, weight=1)

        hl = ctk.CTkFrame(hdr, fg_color="transparent")
        hl.grid(row=0, column=0, sticky="w", padx=16, pady=12)
        ctk.CTkLabel(hl, text="  HOSTS  ", fg_color="#b91c1c", corner_radius=6,
                     font=ctk.CTkFont(size=11, weight="bold"), text_color="white").pack(anchor="w")
        ctk.CTkLabel(hl, text="Block domains for other apps",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", pady=(6, 2))
        ctk.CTkLabel(hl, text="Blocks names like discord.com or tiktok.com system-wide. This is separate from the "
                              "Telegram IP rules, which use the firewall. The 'Telegram' button just adds a preset.",
                     text_color="gray55", font=ctk.CTkFont(size=11), justify="left",
                     wraplength=560).pack(anchor="w")

        self.hosts_status = ctk.CTkLabel(hdr, text="", text_color="gray55", font=ctk.CTkFont(size=11),
                                         justify="right", anchor="e", wraplength=240)
        self.hosts_status.grid(row=0, column=1, sticky="e", padx=16, pady=12)

        # ---------------- Body: domains + tools ----------------
        body = ctk.CTkFrame(tab, fg_color="transparent")
        body.grid(row=1, column=0, sticky="ew", padx=5)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, minsize=260)

        lc = ctk.CTkFrame(body, fg_color="#1f1f23", corner_radius=12)
        lc.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        ctk.CTkLabel(lc, text="BLOCKED DOMAINS", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="gray55").pack(anchor="w", padx=16, pady=(10, 4))

        add_row = ctk.CTkFrame(lc, fg_color="transparent")
        add_row.pack(fill="x", padx=16)
        self.hosts_entry = ctk.CTkEntry(add_row, height=30, font=ctk.CTkFont("Consolas", size=12),
                                        fg_color="#111113", border_width=1, border_color="#3f3f46",
                                        placeholder_text="domain.com")
        self.hosts_entry.pack(side="left", fill="x", expand=True)
        self.hosts_entry.bind("<Return>", lambda _e: add_from_entry())
        ctk.CTkButton(add_row, text="Add", width=54, height=30, fg_color="#2563eb",
                      hover_color="#1d4ed8", font=ctk.CTkFont(size=12, weight="bold"),
                      command=lambda: add_from_entry()).pack(side="left", padx=(6, 0))
        ctk.CTkButton(add_row, text="Telegram", width=84, height=30, fg_color="#27272a",
                      hover_color="#3f3f46", font=ctk.CTkFont(size=12, weight="bold"),
                      command=lambda: add_defaults()).pack(side="left", padx=(6, 0))

        list_wrap = ctk.CTkFrame(lc, fg_color="#18181b", corner_radius=8, height=96)
        list_wrap.pack(fill="x", padx=12, pady=(6, 0))
        list_wrap.pack_propagate(False)

        self.hosts_listbox = tk.Listbox(
            list_wrap, bg="#18181b", fg="#e4e4e7", selectbackground="#2563eb",
            selectforeground="white", highlightthickness=0, borderwidth=0,
            activestyle="none", font=("Consolas", 11))
        self.hosts_listbox.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=6)

        hs_scroll = ctk.CTkScrollbar(list_wrap, command=self.hosts_listbox.yview, width=10,
                                     button_color="#3f3f46", button_hover_color="#52525b")
        hs_scroll.pack(side="right", fill="y", padx=(2, 4), pady=6)
        self.hosts_listbox.configure(yscrollcommand=hs_scroll.set)
        self.hosts_listbox.bind("<Delete>", lambda _e: remove_selected())

        lfoot = ctk.CTkFrame(lc, fg_color="transparent")
        lfoot.pack(fill="x", padx=16, pady=(4, 10))
        ctk.CTkLabel(lfoot, text="Writes are automatic — a backup is made first.",
                     text_color="gray55", font=ctk.CTkFont(size=10)).pack(side="left")
        ctk.CTkButton(lfoot, text="Remove all", width=90, height=26, fg_color="#7f1d1d",
                      hover_color="#991b1b", font=ctk.CTkFont(size=11, weight="bold"),
                      command=lambda: remove_all()).pack(side="right")
        ctk.CTkButton(lfoot, text="Remove selected", width=128, height=26, fg_color="#3f3f46",
                      hover_color="#52525b", font=ctk.CTkFont(size=11, weight="bold"),
                      command=lambda: remove_selected()).pack(side="right", padx=(6, 0))

        tc = ctk.CTkFrame(body, fg_color="#1f1f23", corner_radius=12)
        tc.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        ctk.CTkLabel(tc, text="TOOLS", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="gray55").pack(anchor="w", padx=16, pady=(10, 6))
        for label, action in (
            ("Backup now", lambda: backup_now()),
            ("Restore backup…", lambda: restore_backup()),
            ("Open hosts file", lambda: open_hosts()),
            ("Backups folder", lambda: open_backups()),
        ):
            ctk.CTkButton(tc, text=label, height=30, fg_color="#27272a", hover_color="#3f3f46",
                          font=ctk.CTkFont(size=12, weight="bold"),
                          command=action).pack(fill="x", padx=16, pady=3)

        # ---------------- Hosts viewer ----------------
        vc = ctk.CTkFrame(tab, fg_color="#1f1f23", corner_radius=12)
        vc.grid(row=2, column=0, sticky="nsew", padx=5, pady=(6, 8))
        vc.grid_columnconfigure(0, weight=1)
        vc.grid_rowconfigure(1, weight=1)

        vh = ctk.CTkFrame(vc, fg_color="transparent")
        vh.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 4))
        ctk.CTkLabel(vh, text="HOSTS FILE", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="gray55").pack(side="left")
        ctk.CTkLabel(vh, text=HOSTS_PATH, font=ctk.CTkFont(size=10),
                     text_color="gray40").pack(side="left", padx=10)
        ctk.CTkButton(vh, text="Refresh", width=76, height=26, fg_color="#27272a",
                      hover_color="#3f3f46", font=ctk.CTkFont(size=11, weight="bold"),
                      command=lambda: refresh_all()).pack(side="right")

        self.hosts_view = ctk.CTkTextbox(vc, font=ctk.CTkFont("Consolas", size=11),
                                         fg_color="#111113", text_color="#d4d4d8",
                                         corner_radius=8, border_width=0, wrap="word")
        self.hosts_view.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.hosts_view.configure(state="disabled")

        # ---------------- Actions ----------------
        def current_domains():
            try:
                return parse_blocked_domains(read_hosts_text())
            except Exception:
                return []

        def set_status(message=""):
            text = f"{len(current_domains())} domain(s) blocked"
            if message:
                text += f" · {message}"
            if not is_admin():
                text += "\nLimited mode — writing needs admin."
            self._safe_config(self.hosts_status, text=text)

        def refresh_view(text=None):
            try:
                content = read_hosts_text() if text is None else text
            except Exception as exc:
                content = f"[Cannot read hosts file]\n{exc}"
            self.hosts_view.configure(state="normal")
            self.hosts_view.delete("1.0", "end")
            self.hosts_view.insert("1.0", content)
            self.hosts_view.configure(state="disabled")

        def refresh_list():
            self.hosts_listbox.delete(0, "end")
            domains = current_domains()
            if not domains:
                self.hosts_listbox.insert("end", "  (no domains blocked yet)")
                self.hosts_listbox.itemconfig(0, foreground="#52525b")
                return
            for domain in domains:
                self.hosts_listbox.insert("end", domain)

        def refresh_all():
            refresh_list()
            refresh_view()
            set_status()

        def ensure_admin():
            if is_admin():
                return True
            messagebox.showwarning(
                "Administrator required",
                "Writing the hosts file needs Administrator rights.\n\n"
                "Click 'Enable admin' at the top right, then try again.",
                parent=self)
            return False

        def save_domains(domains, message):
            if not ensure_admin():
                return False
            try:
                original = read_hosts_text()
            except Exception as exc:
                messagebox.showerror("Hosts file", f"Cannot read the hosts file:\n{exc}", parent=self)
                return False

            backed_up = False
            try:
                backup_hosts_file()
                backed_up = True
            except Exception as exc:
                if not messagebox.askyesno("Backup failed",
                                           f"Could not back up the hosts file:\n{exc}\n\nContinue anyway?",
                                           parent=self):
                    return False

            new_text = build_hosts_text(original, domains)
            ok, error = write_hosts_text(new_text)
            if not ok:
                messagebox.showerror("Write failed", f"{error}\n\nTry 'Enable admin'.", parent=self)
                return False

            flush_dns_cache()
            refresh_view(new_text)
            refresh_list()
            set_status(message + (" · backed up" if backed_up else ""))
            return True

        def add_domains(raw_domains):
            domains = current_domains()
            added, invalid = [], []
            for raw in raw_domains:
                domain = normalize_hostname(raw)
                if not domain:
                    invalid.append(raw)
                    continue
                if domain not in domains:
                    domains.append(domain)
                    added.append(domain)

            saved = False
            if added:
                saved = save_domains(domains, f"added {len(added)}")
            if invalid:
                messagebox.showwarning("Invalid hostname",
                                       "Skipped:\n" + "\n".join(invalid), parent=self)
            return saved

        def add_from_entry():
            raw = self.hosts_entry.get().strip()
            if not raw:
                return
            candidates = [c for c in re.split(r"[\s,;]+", raw) if c]
            if add_domains(candidates):
                self.hosts_entry.delete(0, "end")

        def add_defaults():
            domains = current_domains()
            missing = [d for d in TELEGRAM_DOMAINS if d not in domains]
            if not missing:
                set_status("Telegram domains are already blocked")
                return
            save_domains(domains + missing, f"added {len(missing)} Telegram domain(s)")

        def remove_domain(domain):
            domains = [d for d in current_domains() if d != domain]
            save_domains(domains, f"removed {domain}")

        def remove_selected():
            selection = self.hosts_listbox.curselection()
            if not selection:
                return
            domain = self.hosts_listbox.get(selection[0])
            if domain in current_domains():
                remove_domain(domain)

        def remove_all():
            if not current_domains():
                set_status("nothing to remove")
                return
            if not messagebox.askyesno("Remove all",
                                       "Remove every domain managed by this app from the hosts file?",
                                       parent=self):
                return
            save_domains([], "removed all domains")

        def backup_now():
            try:
                path = backup_hosts_file()
            except Exception as exc:
                messagebox.showerror("Backup failed", str(exc), parent=self)
                return
            set_status(f"backup: {os.path.basename(path)}")

        def restore_backup():
            if not ensure_admin():
                return
            os.makedirs(HOSTS_BACKUP_DIR, exist_ok=True)
            path = filedialog.askopenfilename(
                title="Restore hosts backup", initialdir=HOSTS_BACKUP_DIR,
                filetypes=[("Hosts backups", "*.bak"), ("All files", "*.*")], parent=self)
            if not path:
                return
            if not messagebox.askyesno("Restore hosts",
                                       f"Replace the current hosts file with:\n{os.path.basename(path)}",
                                       parent=self):
                return
            try:
                backup_hosts_file()          # keep a copy of the current file too
                shutil.copy2(path, HOSTS_PATH)
            except Exception as exc:
                messagebox.showerror("Restore failed", f"{exc}\n\nTry 'Enable admin'.", parent=self)
                return
            flush_dns_cache()
            refresh_view()
            refresh_list()
            set_status("restored backup")

        def open_hosts():
            try:
                subprocess.Popen(["notepad.exe", HOSTS_PATH])
            except Exception as exc:
                messagebox.showerror("Notepad", str(exc), parent=self)

        def open_backups():
            try:
                os.makedirs(HOSTS_BACKUP_DIR, exist_ok=True)
                os.startfile(HOSTS_BACKUP_DIR)
            except Exception as exc:
                messagebox.showerror("Backups", str(exc), parent=self)

        refresh_all()

    def build_dns_tab(self):
        tab = self.tab_dns
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)   # provider list + detail panel
        tab.grid_rowconfigure(3, weight=0)   # log

        self.dns_selected = None
        self.dns_list_buttons = []

        # ---------------- Log box ----------------
        dns_textbox = ctk.CTkTextbox(tab, height=140, font=ctk.CTkFont("Consolas", size=13), fg_color="#111113",
                                     text_color="#e4e4e7", corner_radius=8, border_width=1, border_color="#3f3f46")
        dns_textbox.grid(row=3, column=0, sticky="ew", padx=5, pady=(5, 5))
        log_text(dns_textbox, "1) Pick a filter  2) Pick a provider  3) Click 'Apply this DNS'.\n"
                              "Changes apply to every active adapter. For your TP-Link, enter the same IPs in the router's DNS settings.")

        # ---------------- Filter bar ----------------
        filter_tags = ["No filter", "Security", "Ads + Security", "Family"]
        filter_bar = ctk.CTkFrame(tab, fg_color="transparent")
        filter_bar.grid(row=0, column=0, sticky="ew", padx=5, pady=(10, 6))
        filter_bar.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(filter_bar, text="What do you need?", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=(5, 12))
        seg = ctk.CTkSegmentedButton(
            filter_bar, values=filter_tags, height=36,
            fg_color="#18181b", selected_color="#2563eb", selected_hover_color="#1d4ed8",
            unselected_color="#27272a", unselected_hover_color="#3f3f46",
            command=lambda v: show_category(v),
        )
        seg.grid(row=0, column=1, sticky="ew")

        # ---------------- Body: list (left) + detail (right) ----------------
        body = ctk.CTkFrame(tab, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=0, minsize=290)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        list_frame = ctk.CTkFrame(body, fg_color="#1f1f23", corner_radius=10, width=290)
        list_frame.grid(row=0, column=0, sticky="nsew", padx=(5, 8), pady=5)
        list_frame.grid_propagate(False)
        list_frame.grid_columnconfigure(0, weight=1)

        detail = ctk.CTkFrame(body, fg_color="#1f1f23", corner_radius=10)
        detail.grid(row=0, column=1, sticky="nsew", padx=(0, 5), pady=5)
        detail.grid_columnconfigure(0, weight=1)
        detail.grid_rowconfigure(5, weight=1)

        lbl_name = ctk.CTkLabel(detail, text="", font=ctk.CTkFont(size=22, weight="bold"), anchor="w")
        lbl_name.grid(row=0, column=0, sticky="w", padx=20, pady=(18, 4))

        lbl_tag = ctk.CTkLabel(detail, text="", font=ctk.CTkFont(size=12, weight="bold"), corner_radius=6, text_color="white")
        lbl_tag.grid(row=1, column=0, sticky="w", padx=20, pady=(0, 12))

        lbl_ips = ctk.CTkLabel(detail, text="", font=ctk.CTkFont("Consolas", size=15), justify="left", anchor="w", text_color="#93c5fd")
        lbl_ips.grid(row=2, column=0, sticky="w", padx=20, pady=(0, 12))

        ctk.CTkLabel(detail, text="WHAT IT BLOCKS", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="gray60", anchor="w").grid(row=3, column=0, sticky="w", padx=20)
        lbl_desc = ctk.CTkLabel(detail, text="", justify="left", anchor="w", wraplength=480, text_color="#e4e4e7",
                                font=ctk.CTkFont(size=14))
        lbl_desc.grid(row=4, column=0, sticky="w", padx=20, pady=(2, 8))

        lbl_note = ctk.CTkLabel(detail, text="", justify="left", anchor="nw", wraplength=480, text_color="#fbbf24")
        lbl_note.grid(row=5, column=0, sticky="nw", padx=20)

        btn_apply = ctk.CTkButton(detail, text="Apply this DNS", height=44, font=ctk.CTkFont(size=14, weight="bold"),
                                  fg_color="#2563eb", hover_color="#1d4ed8",
                                  command=lambda: run_task(action_dns_apply, self.dns_selected))
        btn_apply.grid(row=6, column=0, sticky="ew", padx=20, pady=(8, 18))

        # ---------------- Bottom action bar ----------------
        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=2, column=0, sticky="ew", pady=(5, 0))
        bar.grid_columnconfigure((0, 1), weight=1)

        btn_test = ctk.CTkButton(bar, text="Open Ad-Block Test (Private)", height=40, font=ctk.CTkFont(weight="bold"),
                                 fg_color="#0d9488", hover_color="#0f766e", command=lambda: open_test_site())
        btn_test.grid(row=0, column=0, padx=5, sticky="ew")

        btn_rst = ctk.CTkButton(bar, text="Restore Default DNS (DHCP)", height=40, font=ctk.CTkFont(weight="bold"),
                                fg_color="#b91c1c", hover_color="#991b1b",
                                command=lambda: run_task(action_dns_reset, None))
        btn_rst.grid(row=0, column=1, padx=5, sticky="ew")

        ctk.CTkLabel(
            bar,
            text="DNS cache flushes automatically on every change. The ad-block test opens private (no extensions), so it scores your DNS only.",
            font=ctk.CTkFont(size=11), text_color="gray55",
        ).grid(row=1, column=0, columnspan=2, pady=(7, 0))

        # ---------------- Behaviour ----------------
        def refresh_apply_state(busy=False):
            p = self.dns_selected
            unusable = p is None or p.get("disabled", False)
            btn_apply.configure(state="disabled" if (busy or unusable) else "normal")

        def set_busy(busy):
            state = "disabled" if busy else "normal"
            btn_rst.configure(state=state)
            refresh_apply_state(busy)

        def run_task(func, arg):
            if func is action_dns_apply and not arg:
                return
            set_busy(True)
            def worker():
                func(arg, dns_textbox)
                self.after(0, lambda: set_busy(False))
            threading.Thread(target=worker, daemon=True).start()

        def open_test_site():
            ok, detail = open_private_window(AD_TEST_URL)
            clear_box(dns_textbox)
            if ok:
                log_text(dns_textbox, f"[OK] Opened the ad-block test in a {detail}:\n{AD_TEST_URL}\n")
            else:
                webbrowser.open(AD_TEST_URL)
                log_text(dns_textbox, f"[INFO] No private-capable browser found. Opened in the default browser:\n{AD_TEST_URL}\n")
            log_text(dns_textbox, "A private window loads NO extensions, so the result reflects what your DNS blocks only.\n"
                                  "Workflow: Apply DNS (cache flushes automatically) -> restart browser -> run the test -> compare providers.\n"
                                  "Turn OFF the browser's 'Secure DNS / DNS over HTTPS' first, "
                                  "otherwise the browser bypasses the Windows DNS.")

        def select(p):
            self.dns_selected = p
            for b, prov in self.dns_list_buttons:
                b.configure(fg_color="#2563eb" if prov is p else "#27272a")
            lbl_name.configure(text=p["name"])
            lbl_tag.configure(text=f"  {p['tag']}  ", fg_color=TAG_COLORS.get(p["tag"], "#52525b"))
            ips = [f"Primary:   {p['servers'][0]}"]
            if len(p["servers"]) > 1:
                ips.append(f"Secondary: {p['servers'][1]}")
            lbl_ips.configure(text="\n".join(ips))
            lbl_desc.configure(text=p["desc"])
            lbl_note.configure(text=p.get("note", ""))
            refresh_apply_state()

        def show_category(tag):
            for b, _ in self.dns_list_buttons:
                b.destroy()
            self.dns_list_buttons = []
            items = [p for p in PUBLIC_DNS if p["tag"] == tag]
            for i, p in enumerate(items):
                b = ctk.CTkButton(list_frame, text=p["name"], height=46, anchor="w", corner_radius=8,
                                  font=ctk.CTkFont(size=14, weight="bold"),
                                  text_color="gray55" if p.get("disabled") else "white",
                                  fg_color="#27272a", hover_color="#3f3f46",
                                  command=lambda prov=p: select(prov))
                b.grid(row=i, column=0, sticky="ew", padx=10, pady=(10 if i == 0 else 4, 4))
                self.dns_list_buttons.append((b, p))
            if items:
                select(items[0])

        seg.set("Ads + Security")
        show_category("Ads + Security")

    # ------------------------------------------------------------------
    # NextDNS (Advanced DNS) tab
    # ------------------------------------------------------------------
    @staticmethod
    def _safe_config(widget, **kwargs):
        try:
            if widget.winfo_exists():
                widget.configure(**kwargs)
        except Exception:
            pass

    @staticmethod
    def _grab_dialog(dlg):
        try:
            if dlg.winfo_exists():
                dlg.lift()
                dlg.focus_force()
                dlg.grab_set()
        except Exception:
            pass

    def nd_log(self, text):
        box = getattr(self, "nextdns_logbox", None)
        if box is not None:
            log_text(box, text)

    def build_nextdns_tab(self):
        tab = self.tab_advanced
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(4, weight=1)

        self._nd_steps = None

        # ---------------- Hero card ----------------
        hero = ctk.CTkFrame(tab, fg_color="#1f1f23", corner_radius=12)
        hero.grid(row=0, column=0, sticky="ew", padx=5, pady=(10, 8))
        hero.grid_columnconfigure(0, weight=1)

        left = ctk.CTkFrame(hero, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=18, pady=14)

        ctk.CTkLabel(left, text="  NEXTDNS  ", fg_color="#15803d", corner_radius=6,
                     font=ctk.CTkFont(size=11, weight="bold"), text_color="white").pack(anchor="w")
        ctk.CTkLabel(left, text="Advanced DNS with real filtering",
                     font=ctk.CTkFont(size=19, weight="bold")).pack(anchor="w", pady=(7, 2))
        ctk.CTkLabel(left, text="Ad, tracker, malware and phishing filtering in the cloud, plus AI rules and per-device logs. "
                                "One profile covers this PC or your whole router.",
                     text_color="gray55", font=ctk.CTkFont(size=12), justify="left",
                     wraplength=540).pack(anchor="w")

        right = ctk.CTkFrame(hero, fg_color="transparent")
        right.grid(row=0, column=1, sticky="e", padx=18, pady=14)
        ctk.CTkButton(right, text="Steps to Configure", width=250, height=46,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      fg_color="#b91c1c", hover_color="#991b1b",
                      command=self.show_nextdns_steps).pack()
        ctk.CTkLabel(right, text="manual · 2 minutes", font=ctk.CTkFont(size=11),
                     text_color="gray55").pack(pady=(5, 0))

        # ---------------- DNS servers + apply cards ----------------
        cards = ctk.CTkFrame(tab, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", padx=5, pady=(2, 6))
        cards.grid_columnconfigure(0, weight=1, uniform="nd")
        cards.grid_columnconfigure(1, weight=1, uniform="nd")

        srv = ctk.CTkFrame(cards, fg_color="#1f1f23", corner_radius=12)
        srv.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        srv_head = ctk.CTkFrame(srv, fg_color="transparent")
        srv_head.pack(fill="x", padx=16, pady=(13, 7))
        ctk.CTkLabel(srv_head, text="DNS SERVERS (LINKED IP)", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="gray55").pack(side="left")
        ctk.CTkButton(srv_head, text="Paste", width=66, height=26, fg_color="#2563eb",
                      hover_color="#1d4ed8", font=ctk.CTkFont(size=12, weight="bold"),
                      command=self.paste_nextdns_dns).pack(side="right")

        btn_copy = ctk.CTkButton(srv_head, text="Copy", width=60, height=26, fg_color="#27272a",
                                 hover_color="#3f3f46", font=ctk.CTkFont(size=12, weight="bold"))

        def copy_both():
            values = self._nextdns_server_values()
            if not values:
                btn_copy.configure(text="Empty")
            else:
                ok = copy_to_clipboard(self, "\n".join(values))
                btn_copy.configure(text="Copied" if ok else "Failed")
            self.after(1300, lambda: self._safe_config(btn_copy, text="Copy"))

        btn_copy.configure(command=copy_both)
        btn_copy.pack(side="right", padx=(0, 6))

        def server_row(parent, label):
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=2)
            ctk.CTkLabel(row, text=label, width=80, anchor="w", text_color="gray55",
                         font=ctk.CTkFont(size=12)).pack(side="left")
            entry = ctk.CTkEntry(row, height=30, font=ctk.CTkFont("Consolas", size=13),
                                 fg_color="#111113", border_width=1, border_color="#3f3f46",
                                 placeholder_text="from NextDNS Setup")
            entry.pack(side="left", fill="x", expand=True)
            return entry

        self.nd_entry_primary = server_row(srv, "Primary")
        self.nd_entry_secondary = server_row(srv, "Secondary")
        ctk.CTkLabel(srv, text="Paste the pair from Setup, or type your own. Copy puts both on the clipboard "
                               "(for your router). NextDNS matches them through the linked IP.",
                     text_color="gray55", font=ctk.CTkFont(size=11), justify="left",
                     wraplength=420).pack(anchor="w", padx=16, pady=(7, 13))

        act = ctk.CTkFrame(cards, fg_color="#1f1f23", corner_radius=12)
        act.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        ctk.CTkLabel(act, text="APPLY", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="gray55").pack(anchor="w", padx=16, pady=(13, 7))
        self.btn_nd_apply = ctk.CTkButton(act, text="Apply NextDNS to Windows", height=38,
                                          fg_color="#15803d", hover_color="#166534",
                                          font=ctk.CTkFont(size=13, weight="bold"),
                                          command=self.apply_nextdns_dns)
        self.btn_nd_apply.pack(fill="x", padx=16)
        ctk.CTkLabel(act, text="Applies to every active adapter (cache flushes automatically). A browser with "
                               "Secure DNS (DoH) ON bypasses Windows DNS — switch it off.",
                     text_color="gray55", font=ctk.CTkFont(size=11), justify="left",
                     wraplength=420).pack(anchor="w", padx=16, pady=(8, 13))

        # ---------------- Manual edit button ----------------
        edit_row = ctk.CTkFrame(tab, fg_color="transparent")
        edit_row.grid(row=2, column=0, sticky="ew", padx=5, pady=(2, 6))
        ctk.CTkButton(edit_row, text="Edit My Profile", width=180, height=38,
                      fg_color="#7c3aed", hover_color="#6d28d9",
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=self.open_nextdns_profile).pack(side="left")
        ctk.CTkLabel(edit_row, text="Why this button? NextDNS rules live in your online profile, not in this app. "
                                    "Reopen it anytime to change blocklists, filters, AI rules or defaults by hand.",
                     text_color="gray55", font=ctk.CTkFont(size=11), justify="left",
                     wraplength=600).pack(side="left", padx=12)

        # ---------------- What the 2 rules add ----------------
        info = ctk.CTkFrame(tab, fg_color="#1f1f23", corner_radius=12)
        info.grid(row=3, column=0, sticky="ew", padx=5, pady=(0, 6))
        info.grid_columnconfigure(0, weight=1, uniform="inf")
        info.grid_columnconfigure(1, weight=1, uniform="inf")

        def rule_card(column, title, desc):
            box = ctk.CTkFrame(info, fg_color="transparent")
            box.grid(row=0, column=column, sticky="nsew",
                     padx=(16, 10) if column == 0 else (10, 16), pady=12)
            ctk.CTkLabel(box, text=title, font=ctk.CTkFont(size=11, weight="bold"),
                         text_color="#4ade80").pack(anchor="w")
            ctk.CTkLabel(box, text=desc, font=ctk.CTkFont(size=11), text_color="gray55",
                         justify="left", wraplength=380).pack(anchor="w", pady=(2, 0))

        rule_card(0, "AI-DRIVEN THREAT DETECTION · SECURITY TAB",
                  "AI engine that blocks DGA, phishing, typosquatting and decoy domains before they load.")
        rule_card(1, "BLOCK ROTATING AD DOMAINS · PRIVACY TAB",
                  "Stops ad networks that keep switching domains to slip past normal blocklists.")

        # ---------------- Activity log ----------------
        log_card = ctk.CTkFrame(tab, fg_color="#1f1f23", corner_radius=12)
        log_card.grid(row=4, column=0, sticky="nsew", padx=5, pady=(0, 8))
        log_card.grid_columnconfigure(0, weight=1)
        log_card.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(log_card, text="ACTIVITY", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="gray55").grid(row=0, column=0, sticky="w", padx=16, pady=(10, 4))

        self.nextdns_logbox = ctk.CTkTextbox(log_card, height=110, font=ctk.CTkFont("Consolas", size=12),
                                             fg_color="#111113", text_color="#e4e4e7", corner_radius=8,
                                             border_width=0, wrap="word")
        self.nextdns_logbox.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        log_text(self.nextdns_logbox,
                 f"Profile {NEXTDNS_PROFILE_ID} · browser-local temporary account (7 days).")
        log_text(self.nextdns_logbox,
                 "Red button: manual steps — keep the defaults or add the 2 rules.")
        log_text(self.nextdns_logbox,
                 "Then 'Apply NextDNS to Windows' — the cache flushes automatically.")

    # ---------------- Tab actions ----------------
    def _nextdns_server_values(self) -> list:
        values = []
        for entry in (self.nd_entry_primary, self.nd_entry_secondary):
            text = entry.get().strip()
            if text:
                values.append(text)
        return values

    def paste_nextdns_dns(self) -> bool:
        """Fill the two fields from the clipboard (first two valid IPv4 addresses)."""
        try:
            text = self.clipboard_get() or ""
        except Exception:
            text = ""

        found = []
        for token in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", text):
            try:
                ipaddress.ip_address(token)
            except ValueError:
                continue
            if token not in found:
                found.append(token)

        if not found:
            self.nd_log("[FAIL] No IPv4 address on the clipboard. Copy the DNS servers from the NextDNS Setup page first.")
            return False

        self.nd_entry_primary.delete(0, "end")
        self.nd_entry_primary.insert(0, found[0])
        self.nd_entry_secondary.delete(0, "end")
        if len(found) > 1:
            self.nd_entry_secondary.insert(0, found[1])

        self.nd_log(f"[OK] Pasted DNS servers: {' / '.join(found[:2])}")
        if len(found) > 2:
            self.nd_log(f"[INFO] Found {len(found)} addresses — used the first two. Edit the fields if needed.")
        return True

    def apply_nextdns_dns(self):
        servers = self._nextdns_server_values()
        clear_box(self.nextdns_logbox)

        if not servers:
            log_text(self.nextdns_logbox, "[FAIL] Enter at least one DNS server (for example 45.90.28.183).")
            return

        invalid = []
        for server in servers:
            try:
                ipaddress.ip_address(server)
            except ValueError:
                invalid.append(server)
        if invalid:
            log_text(self.nextdns_logbox, f"[FAIL] Not a valid IP address: {', '.join(invalid)}")
            log_text(self.nextdns_logbox, "Use plain IPv4/IPv6 addresses, one per field.")
            return

        if not require_admin(self.nextdns_logbox):
            return

        log_text(self.nextdns_logbox, f"Applying NextDNS ({' / '.join(servers)}) to all active adapters...")
        self.btn_nd_apply.configure(state="disabled")

        def worker():
            code, out = set_system_dns(servers)
            if code == 0:
                log_text(self.nextdns_logbox, "[OK] DNS servers set.")
                fcode, fout = flush_dns_cache()
                log_text(self.nextdns_logbox, "[OK] DNS cache flushed automatically."
                         if fcode == 0 else f"[WARN] Flush failed: {fout}")
                log_text(self.nextdns_logbox, "\n>> RESULT: NextDNS is now active on this PC.")
                log_text(self.nextdns_logbox, "Open the profile to confirm this device shows up in Logs. "
                                              "A browser with Secure DNS ON will bypass it.")
            else:
                log_text(self.nextdns_logbox, f"\n>> RESULT: Execution failed.\nReason: {out}")
            self.after(0, lambda: self.btn_nd_apply.configure(state="normal"))

        threading.Thread(target=worker, daemon=True).start()

    def open_nextdns_profile(self):
        webbrowser.open(NEXTDNS_HOME)
        self.nd_log(f"[OK] Opened your NextDNS profile: {NEXTDNS_HOME}")
        self.nd_log("Use it to change blocklists, filters, AI detection, logging or the defaults.")

    # ---------------- Manual steps dialog ----------------
    def show_nextdns_steps(self):
        try:
            if self._nd_steps is not None and self._nd_steps.winfo_exists():
                self._nd_steps.lift()
                self._nd_steps.focus_force()
                return
        except Exception:
            pass

        dlg = ctk.CTkToplevel(self)
        self._nd_steps = dlg
        dlg.title("NextDNS — steps to configure")
        dlg.configure(fg_color="#18181b")
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.protocol("WM_DELETE_WINDOW", dlg.destroy)
        dlg.withdraw()
        dlg.grid_columnconfigure(0, weight=1)

        head = ctk.CTkFrame(dlg, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=26, pady=(20, 8))
        ctk.CTkLabel(head, text="Steps to configure NextDNS",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(head,
                     text=f"Profile {NEXTDNS_PROFILE_ID} · manual setup · about 2 minutes · no script, no extension.",
                     text_color="gray55", font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(3, 0))

        # ---------------- Step 1 ----------------
        card1 = ctk.CTkFrame(dlg, fg_color="#1f1f23", corner_radius=10)
        card1.grid(row=1, column=0, sticky="ew", padx=26, pady=(0, 10))
        ctk.CTkLabel(card1, text="1 · In NextDNS: keep the defaults, or add the 2 rules",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkLabel(card1,
                     text="Keep the defaults if that is enough: both rules below stay OFF, and malware, phishing, "
                          "DGA, typosquatting, cryptojacking and CSAM stay ON.",
                     wraplength=800, justify="left", text_color="#d4d4d8",
                     font=ctk.CTkFont(size=12)).pack(anchor="w", padx=16, pady=(0, 8))
        ctk.CTkLabel(card1, text="Add the 2 rules (recommended):",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#fca5a5").pack(anchor="w", padx=16)

        def rule_row(text, button_text, url):
            row = ctk.CTkFrame(card1, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=(6, 0))
            ctk.CTkLabel(row, text=text, justify="left", text_color="#e4e4e7",
                         font=ctk.CTkFont(size=12), wraplength=540).pack(side="left")
            ctk.CTkButton(row, text=button_text, width=140, height=32,
                          fg_color="#2563eb", hover_color="#1d4ed8",
                          font=ctk.CTkFont(size=12, weight="bold"),
                          command=lambda u=url: webbrowser.open(u)).pack(side="right")

        rule_row("Security tab  →  turn ON  AI-Driven Threat Detection",
                 "Open Security", NEXTDNS_SECURITY)
        rule_row("Privacy tab  →  turn ON  Block Rotating Ad Domains",
                 "Open Privacy", NEXTDNS_PRIVACY)
        ctk.CTkLabel(card1, text="Changes save instantly on those pages — there is no save button.",
                     text_color="gray55", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=16, pady=(6, 12))

        # ---------------- Step 2 ----------------
        card2 = ctk.CTkFrame(dlg, fg_color="#1f1f23", corner_radius=10)
        card2.grid(row=2, column=0, sticky="ew", padx=26, pady=(0, 10))
        ctk.CTkLabel(card2, text="2 · Put the 2 DNS servers into this app",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkLabel(card2,
                     text="The pair changes with the profile, so this app does not assume one. Open Setup, copy the "
                          "two DNS servers, then click Paste — they go straight into the fields on this tab.",
                     wraplength=800, justify="left", text_color="#d4d4d8",
                     font=ctk.CTkFont(size=12)).pack(anchor="w", padx=16, pady=(0, 7))

        lbl_primary = ctk.CTkLabel(card2, text="", font=ctk.CTkFont("Consolas", size=13),
                                   text_color="#93c5fd", anchor="w")
        lbl_secondary = ctk.CTkLabel(card2, text="", font=ctk.CTkFont("Consolas", size=13),
                                     text_color="#93c5fd", anchor="w")

        def refresh():
            primary = self.nd_entry_primary.get().strip() or "not set yet"
            secondary = self.nd_entry_secondary.get().strip() or "not set yet"
            lbl_primary.configure(text=f"Primary      {primary}")
            lbl_secondary.configure(text=f"Secondary    {secondary}")

        def paste_here():
            if self.paste_nextdns_dns():
                refresh()

        btn_row = ctk.CTkFrame(card2, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 8))
        ctk.CTkButton(btn_row, text="Open Setup", width=130, height=32, fg_color="#27272a",
                      hover_color="#3f3f46", font=ctk.CTkFont(size=12, weight="bold"),
                      command=lambda: webbrowser.open(NEXTDNS_SETUP)).pack(side="left")
        ctk.CTkButton(btn_row, text="Paste from clipboard", width=185, height=32, fg_color="#2563eb",
                      hover_color="#1d4ed8", font=ctk.CTkFont(size=12, weight="bold"),
                      command=paste_here).pack(side="left", padx=(8, 0))

        lbl_primary.pack(anchor="w", padx=16, pady=(0, 2))
        lbl_secondary.pack(anchor="w", padx=16, pady=(0, 4))
        ctk.CTkLabel(card2, text="These are the live values in the Primary / Secondary fields on this tab.",
                     text_color="gray55", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=16, pady=(0, 12))
        refresh()

        # ---------------- Step 3 ----------------
        card3 = ctk.CTkFrame(dlg, fg_color="#1f1f23", corner_radius=10)
        card3.grid(row=3, column=0, sticky="ew", padx=26, pady=(0, 10))
        ctk.CTkLabel(card3, text="3 · Apply",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkLabel(card3,
                     text="Close this window and click 'Apply NextDNS to Windows' on this tab. "
                          "The DNS cache is flushed automatically.",
                     wraplength=800, justify="left", text_color="#d4d4d8",
                     font=ctk.CTkFont(size=12)).pack(anchor="w", padx=16, pady=(0, 12))

        # ---------------- Footer ----------------
        foot = ctk.CTkFrame(dlg, fg_color="transparent")
        foot.grid(row=4, column=0, sticky="ew", padx=26, pady=(2, 18))
        ctk.CTkButton(foot, text="Open my profile", width=170, height=36, fg_color="#7c3aed",
                      hover_color="#6d28d9", command=self.open_nextdns_profile).pack(side="left")
        ctk.CTkButton(foot, text="Done", width=110, height=36, fg_color="#2563eb",
                      hover_color="#1d4ed8", command=dlg.destroy).pack(side="right")

        dlg.update_idletasks()
        width = 900
        height = min(dlg.winfo_reqheight() + 6, 940)
        self.update_idletasks()
        x = self.winfo_rootx() + max(0, (self.winfo_width() - width) // 2)
        y = self.winfo_rooty() + max(0, (self.winfo_height() - height) // 2)
        dlg.geometry(f"{width}x{height}+{x}+{y}")

        dlg.deiconify()
        dlg.after(200, lambda d=dlg: self._grab_dialog(d))

def main():
    hide_own_console()
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
