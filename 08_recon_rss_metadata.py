import requests
import re

TARGET_URL = "https://www.supercinebattle-test.fr"
HEADERS = {"User-Agent": "Mozilla/5.0"}

def check_plugin_and_rss():
    print("[*] Analyse de version & Flux RSS...\n")
    
    # Version
    readme = requests.get(f"{TARGET_URL}/wp-content/plugins/seriously-simple-podcasting/readme.txt", headers=HEADERS)
    if readme.status_code == 200:
        match = re.search(r"Stable tag:\s*([\d.]+)", readme.text)
        print(f"[+] Version plugin : {match.group(1)}" if match else "[-] Version introuvable.")

    # RSS
    rss = requests.get(f"{TARGET_URL}/feed/podcast/", headers=HEADERS)
    if rss.status_code == 200:
        patterns = {
            "Email": r"[\w\.-]+@[\w\.-]+\.\w+",
            "Chemin": r"/[a-z0-9\._\-/]+wp-content/[a-z0-9\._\-/]+"
        }
        for label, pattern in patterns.items():
            matches = list(set(re.findall(pattern, rss.text, re.IGNORECASE)))
            if matches: print(f"    [!] {label}(s) trouvé(s) : {matches[:3]}")

if __name__ == "__main__":
    check_plugin_and_rss()