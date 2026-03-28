import requests
import time

TARGET_TECHS = ["seriously-simple-podcasting", "wordpress", "nginx"]

def search_cve(keyword):
    print(f"[*] Recherche CVE pour : '{keyword}'")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code == 200:
            vulns = response.json().get("vulnerabilities", [])
            if vulns:
                print(f"[+] {len(vulns)} résultat(s). Top 3 :")
                for v in vulns[:3]:
                    cve = v.get("cve", {})
                    desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "N/A")
                    print(f"    - ID: {cve.get('id')} | Desc: {desc[:100]}...")
            else:
                print("[-] Aucune vulnérabilité trouvée.")
        elif response.status_code == 403:
            print("[!] Erreur 403 : Rate Limit du NVD atteint.")
    except Exception as e:
        print(f"[!] Erreur : {e}")

if __name__ == "__main__":
    for tech in TARGET_TECHS:
        search_cve(tech)
        time.sleep(6) # Respect du Rate Limit