import socket
import ssl

TARGET_IP = "51.159.54.97"
PORTS_TO_TEST = {22: False, 25: False, 80: False, 443: True, 465: True, 993: True}

def grab_banner(ip, port, use_ssl):
    print(f"[*] Port {port} (SSL: {use_ssl})...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        if use_ssl:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=ip)
        
        sock.connect((ip, port))
        if port in [80, 443]:
            sock.send(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode('utf-8'))
        
        banner = sock.recv(2048)
        if banner:
            print(f"[+] Bannière :\n    {banner.decode('utf-8', errors='ignore').strip().replace(chr(10), chr(10)+'    ')}")
    except Exception as e:
        print(f"[-] Échec : {e}")
    finally:
        try: sock.close()
        except: pass

if __name__ == "__main__":
    for port, is_ssl in PORTS_TO_TEST.items():
        grab_banner(TARGET_IP, port, is_ssl)