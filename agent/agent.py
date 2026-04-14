import time
import json
import uuid
import subprocess
import socket
import threading
import requests
import psutil

import os

# Configuration
API_URL = os.environ.get("CLOUDSHIELD_API_URL", "http://localhost:5000/api/agent-scan")
AGENT_KEY = os.environ.get("AGENT_KEY", "default-agent-key-123")
AGENT_ID = str(uuid.uuid4())
SYNC_INTERVAL = 30
TRIVY_INTERVAL = 1200 # 20 minutes

# Global State
last_trivy_scan_time = 0
current_cves = {"critical": 0, "high": 0, "medium": 0, "low": 0}

def run_trivy_scan():
    global current_cves
    print("[*] Running background Trivy filesystem scan...")
    try:
        # Run trivy on root filesystem
        result = subprocess.run(
            ["trivy", "fs", "/", "--format", "json", "--quiet", "--scanners", "vuln"],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            cves = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for result_block in data.get("Results", []):
                for vuln in result_block.get("Vulnerabilities", []):
                    sev = vuln.get("Severity", "UNKNOWN").lower()
                    if sev in cves:
                        cves[sev] += 1
            current_cves = cves
            print(f"[+] Trivy scan complete. Found: {current_cves}")
        else:
            print("[-] Trivy scan failed or returned non-zero code.")
    except Exception as e:
        print(f"[-] Trivy execution error: {str(e)}")

def get_system_telemetry():
    global last_trivy_scan_time, current_cves
    
    # 1. basic OS & CPU
    hostname = socket.gethostname()
    cpu_percent = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    os_info = f"{psutil.os.name} {psutil.os.uname().release}" if hasattr(psutil.os, 'uname') else "Windows/Unknown"

    # 2. Top 10 processes by CPU
    processes = []
    for proc in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent']), key=lambda p: p.info['cpu_percent'] or 0, reverse=True)[:10]:
        processes.append({"pid": proc.info['pid'], "name": proc.info['name'], "cpu": proc.info['cpu_percent']})

    # 3. Open ports
    open_ports = []
    try:
        conns = psutil.net_connections(kind='inet')
        for conn in conns:
            if conn.status == 'LISTEN':
                open_ports.append({"port": conn.laddr.port, "ip": conn.laddr.ip})
    except psutil.AccessDenied:
        pass # Requires admin/root for all ports, will get what it can
        
    # Deduplicate open ports
    unique_ports = {p['port']: p for p in open_ports}.values()

    # 4. Trivy Check
    if time.time() - last_trivy_scan_time > TRIVY_INTERVAL:
        last_trivy_scan_time = time.time()
        threading.Thread(target=run_trivy_scan, daemon=True).start()

    payload = {
        "agentId": AGENT_ID,
        "timestamp": time.time(),
        "hostname": hostname,
        "os": os_info,
        "cpu_percent": cpu_percent,
        "ram_percent": ram.percent,
        "top_processes": processes,
        "open_ports": list(unique_ports)[:20], # limit to 20 for payload size optimization
        "cves": current_cves
    }
    
    return payload

def ship_telemetry():
    while True:
        payload = get_system_telemetry()
        
        headers = {
            "Content-Type": "application/json",
            "x-agent-key": AGENT_KEY
        }
        
        # Retry logic: 3 attempts
        for attempt in range(3):
            try:
                print(f"[*] Sending telemetry sync (Attempt {attempt+1}/3)...")
                res = requests.post(API_URL, json=payload, headers=headers, timeout=10)
                if res.status_code == 200:
                    print("[+] Sync successful.")
                    break
                else:
                    print(f"[-] Server returned {res.status_code}: {res.text}")
            except Exception as e:
                print(f"[-] Network error: {str(e)}")
            time.sleep(2)
            
        time.sleep(SYNC_INTERVAL)

if __name__ == "__main__":
    print(f"Starting CloudShield System Agent (ID: {AGENT_ID})")
    ship_telemetry()
