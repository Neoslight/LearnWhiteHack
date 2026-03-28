import requests
import re

TARGET_URL = "https://www.supercinebattle-test.fr"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

def enumerate_wordpress():
    print(f"[*] Fingerprinting WordPress sur : {TARGET_URL}\n")
    try:
        response = requests.get(TARGET_URL, headers=HEADERS, timeout=10)
        if response.status_code != 200: return
        html = response.text

        version = re.search(r'<meta name="generator" content="WordPress (.*?)"', html)
        print(f"[+] Version : {version.group(1)}" if version else "[-] Version introuvable.")

        themes = set(re.findall(r'/wp-content/themes/([^/]+)/', html))
        print(f"[+] Thème(s) : {', '.join(themes)}" if themes else "[-] Aucun thème détecté.")

        plugins = set(re.findall(r'/wp-content/plugins/([^/]+)/', html))
        if plugins:
            print("[+] Plugins détectés :")
            for p in plugins: print(f"    - {p}")
        else:
            print("[-] Aucun plugin visible.")
    except Exception as e:
        print(f"[!] Erreur : {e}")

if __name__ == "__main__":
    enumerate_wordpress()