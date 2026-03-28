import socket
import concurrent.futures
import time

TARGET_IP = "51.159.54.97"
PORTS_TO_SCAN = range(1, 1025)

def scan_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((TARGET_IP, port)) == 0:
            print(f"[+] Port {port} : OUVERT")
        sock.close()
    except:
        pass 

def run_scanner():
    print(f"[*] Scan multi-threadé sur : {TARGET_IP} (Ports 1-{max(PORTS_TO_SCAN)})")
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(scan_port, PORTS_TO_SCAN)

    print(f"[*] Terminé en {round(time.time() - start_time, 2)} secondes.")

if __name__ == "__main__":
    run_scanner()