import requests
import json

TARGET_URL = "https://www.supercinebattle-test.fr"
WELL_KNOWN_FILES = [
    "security.txt", "core/security.txt", "openid-configuration",
    "assetlinks.json", "apple-app-site-association"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def scan_well_known():
    print(f"[*] Analyse du répertoire .well-known sur {TARGET_URL}\n")
    for file in WELL_KNOWN_FILES:
        url = f"{TARGET_URL}/.well-known/{file}"
        try:
            response = requests.get(url, headers=HEADERS, timeout=5)
            if response.status_code == 200:
                print(f"[+] TROUVÉ : {url}")
                if "application/json" in response.headers.get("Content-Type", "") or file.endswith(".json"):
                    try:
                        print(json.dumps(response.json(), indent=4)[:300] + "...\n")
                    except json.JSONDecodeError:
                        print("    [!] Erreur de parsing JSON.")
                else:
                    print(response.text[:300] + "\n")
            elif response.status_code in [403, 404]:
                print(f"[-] {response.status_code} : {url}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Erreur : {e}")

if __name__ == "__main__":
    scan_well_known()