import socket
import threading
import queue
import requests
import subprocess
import sys
import os

SQLMAP_PATH = r"C:\Users\abdur\sqlmap\sqlmap.py"


print("\n===== Security Learning Tool =====")
name = input("Enter your name: ").strip()
print(f"\nWelcome {name}!\n")

def show_menu():
    print("\n1) SQL Injection Checker\n2) Port Scanner\n3) Service Detection\n4) SQLMap Simulator\n5) Exit")

def sql_injection_check():
    print("\n[ SQL Injection Checker ]")
    url = input("Enter full URL (e.g. http://testphp.vulnweb.com/artists.php?artist=1): ").strip()
    
    if not url.startswith('http'):
        url = 'http://' + url
    
    payloads = ["'", "' OR '1'='1", "' OR 1=1--", "admin'--", "1' AND '1'='2"]
    
    print(f"\nTesting {url}...")
    
    try:
        base = requests.get(url, timeout=5, allow_redirects=True, verify=False)
        base_len = len(base.text)
        base_code = base.status_code
        print(f"[*] Base response: {base_code} ({base_len} bytes)")
        
        vulnerable = False
        for p in payloads:
            test_url = url + requests.utils.quote(p)
            r = requests.get(test_url, timeout=5, allow_redirects=True, verify=False)
            diff = abs(len(r.text) - base_len)
            
            if r.status_code != base_code:
                print(f"[!] VULNERABLE - Status changed with: {p}")
                vulnerable = True
            elif diff > 100:
                print(f"[!] VULNERABLE - Size changed {diff} bytes with: {p}")
                vulnerable = True
            elif 'error' in r.text.lower() or 'sql' in r.text.lower() or 'mysql' in r.text.lower():
                print(f"[!] VULNERABLE - SQL error detected with: {p}")
                vulnerable = True
        
        if not vulnerable:
            print("[✓] No obvious SQL injection found")
            
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect. Is the server running? Check URL format.")
    except Exception as e:
        print(f"[ERROR] {str(e)[:100]}")

def port_worker(host, q, results):
    while not q.empty():
        port = q.get()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex((host, port)) == 0:
                    results.append(port)
        except:
            pass
        finally:
            q.task_done()

def port_scan():
    print("\n[ Port Scanner ]")
    host = input("Enter target (e.g. scanme.nmap.org or 45.33.32.156): ").strip()
    
    q = queue.Queue()
    results = []
    
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    for p in common_ports:
        q.put(p)
    for p in range(1, 1025):
        if p not in common_ports:
            q.put(p)
    
    print(f"\nScanning {host}...")
    
    threads = [threading.Thread(target=port_worker, args=(host, q, results), daemon=True) for _ in range(50)]
    for t in threads:
        t.start()
    
    q.join()
    
    if results:
        print(f"\n[✓] Open ports: {sorted(results)}")
    else:
        print("\n[!] No open ports found in range 1-1024")

def service_detection():
    print("\n[ Service Detection - No Root Required ]")
    target = input("Enter target (e.g. scanme.nmap.org): ").strip()
    
    try:
        import nmap
        nm = nmap.PortScanner()
        print("\nScanning top ports...")
        nm.scan(target, arguments="-sV --top-ports 20")
        
        if target in nm.all_hosts():
            print(f"\n[✓] Target: {target}")
            for proto in nm[target].all_protocols():
                ports = sorted(nm[target][proto].keys())
                for port in ports:
                    service = nm[target][proto][port]
                    state = service.get('state', '')
                    name = service.get('name', 'unknown')
                    product = service.get('product', '')
                    version = service.get('version', '')
                    
                    info = f"{name}"
                    if product:
                        info += f" ({product}"
                        if version:
                            info += f" {version}"
                        info += ")"
                    
                    print(f"  Port {port}/{proto}: {state} - {info}")
        else:
            print("[!] No results found")
            
    except ImportError:
        print("[ERROR] python-nmap not installed. Run: pip install python-nmap")
    except Exception as e:
        print(f"[ERROR] {str(e)[:100]}")

def database_simulator():
    print("\n[ SQLMap Simulator ]")
    url = input("Enter vulnerable URL: ").strip()

    if not url.startswith('http'):
        url = 'http://' + url

    if not os.path.exists(SQLMAP_PATH):
        print("[ERROR] sqlmap.py not found at:", SQLMAP_PATH)
        return

    print(f"\nRunning sqlmap on {url}...\n")

    try:
        subprocess.run(
            ["python", SQLMAP_PATH, "-u", url, "--batch", "--tables"],
            timeout=120
        )
    except subprocess.TimeoutExpired:
        print("[!] Timeout - sqlmap took too long")
    except Exception as e:
        print(f"[ERROR] {str(e)[:100]}")

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

while True:
    show_menu()
    choice = input("\nChoice (1-5): ").strip()
    
    if choice == "1":
        sql_injection_check()
    elif choice == "2":
        port_scan()
    elif choice == "3":
        service_detection()
    elif choice == "4":
        database_simulator()
    elif choice == "5":
        print(f"\nGoodbye {name}!\n")
        sys.exit()
    else:
        print("[!] Invalid choice")