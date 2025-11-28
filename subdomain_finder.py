import requests
import sys
import os

import time

def fetch_crtsh(domain):
    print("  - Interrogation de crt.sh...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()
    
    # On tente 3 fois car crt.sh est souvent instable
    for attempt in range(3):
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name_value = entry['name_value']
                        for sub in name_value.split('\n'):
                            sub = sub.strip().lower()
                            if sub.endswith(domain) and '*' not in sub:
                                subdomains.add(sub)
                    # Si on a réussi à parser les données, on sort de la boucle
                    break
                except ValueError:
                    print(f"    Attention: Réponse invalide de crt.sh (tentative {attempt+1}/3)")
            else:
                print(f"    crt.sh a répondu avec le code {response.status_code} (tentative {attempt+1}/3)")
        except Exception as e:
            print(f"    Erreur de connexion à crt.sh: {e} (tentative {attempt+1}/3)")
        
        if attempt < 2:
            time.sleep(2)
            
    return subdomains

def fetch_hackertarget(domain):
    print("  - Interrogation de HackerTarget...")
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains = set()
    try:
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            lines = response.text.split('\n')
            for line in lines:
                if ',' in line:
                    sub = line.split(',')[0].strip().lower()
                    if sub.endswith(domain):
                        subdomains.add(sub)
    except Exception as e:
        print(f"    Erreur HackerTarget: {e}")
    return subdomains

def fetch_alienvault(domain):
    print("  - Interrogation de AlienVault OTX...")
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subdomains = set()
    try:
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            if 'passive_dns' in data:
                for entry in data['passive_dns']:
                    sub = entry.get('hostname', '').strip().lower()
                    if sub and sub.endswith(domain):
                        subdomains.add(sub)
    except Exception as e:
        print(f"    Erreur AlienVault: {e}")
    return subdomains

def save_to_file(domain, new_subdomains):
    # Création du dossier de résultats
    output_dir = "resultats"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    filename = os.path.join(output_dir, f"subdomains_{domain}.txt")
    existing_subdomains = set()
    
    # Lire le fichier existant si présent
    if os.path.exists(filename):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        existing_subdomains.add(line.strip().lower())
        except Exception as e:
            print(f"Erreur lors de la lecture du fichier existant : {e}")

    # Fusionner les listes
    all_subdomains = existing_subdomains.union(new_subdomains)
    sorted_subdomains = sorted(list(all_subdomains))
    
    # Sauvegarder
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for sub in sorted_subdomains:
                f.write(f"{sub}\n")
        
        added_count = len(all_subdomains) - len(existing_subdomains)
        print(f"\nSauvegardé dans '{filename}'")
        print(f"Total: {len(sorted_subdomains)} sous-domaines.")
        if existing_subdomains:
            print(f"Nouveaux ajoutés: {added_count}")
            
    except Exception as e:
        print(f"Erreur lors de l'écriture du fichier : {e}")

def main():
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Entrez le domaine (ex: google.com) : ")
    
    if not domain:
        print("Aucun domaine spécifié.")
        sys.exit(1)

    print(f"Recherche des sous-domaines pour : {domain}...")
    
    results = set()
    
    # Appel des différentes sources
    results.update(fetch_crtsh(domain))
    results.update(fetch_hackertarget(domain))
    results.update(fetch_alienvault(domain))
    
    if results:
        print(f"\nTrouvé {len(results)} sous-domaines uniques lors de cette recherche.")
        save_to_file(domain, results)
    else:
        print("Aucun sous-domaine trouvé.")

if __name__ == "__main__":
    main()
