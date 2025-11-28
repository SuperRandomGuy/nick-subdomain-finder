import requests
import sys
import os
import re
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

def fetch_anubis(domain):
    print("  - Interrogation de Anubis...")
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    subdomains = set()
    try:
        # User-Agent parfois nécessaire pour éviter les blocages
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code == 200:
            data = response.json()
            # Anubis renvoie une liste directe de strings
            for sub in data:
                sub = sub.strip().lower()
                if sub.endswith(domain):
                    subdomains.add(sub)
    except Exception as e:
        print(f"    Erreur Anubis: {e}")
    return subdomains

def fetch_threatminer(domain):
    print("  - Interrogation de ThreatMiner...")
    url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
    subdomains = set()
    try:
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            if data.get('status_code') == '200' and 'results' in data:
                for sub in data['results']:
                    sub = sub.strip().lower()
                    if sub.endswith(domain):
                        subdomains.add(sub)
    except Exception as e:
        print(f"    Erreur ThreatMiner: {e}")
    return subdomains

def fetch_threatcrowd(domain):
    print("  - Interrogation de ThreatCrowd...")
    # L'API de ThreatCrowd est parfois capricieuse ou derrière Cloudflare
    url = f"http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    subdomains = set()
    try:
        # On ajoute un User-Agent pour éviter certains blocages
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=25)
        
        if response.status_code == 200:
            try:
                data = response.json()
                if data.get('response_code') == '1' and 'subdomains' in data:
                    for sub in data['subdomains']:
                        sub = sub.strip().lower()
                        if sub.endswith(domain):
                            subdomains.add(sub)
            except ValueError:
                # Si le JSON est invalide, on ignore silencieusement ou on log
                print("    ThreatCrowd a renvoyé une réponse non-JSON (probablement une erreur serveur ou rate limit).")
        elif response.status_code == 503:
             print("    ThreatCrowd est indisponible (503).")
    except Exception as e:
        print(f"    Erreur ThreatCrowd: {e}")
    return subdomains

def fetch_sonar(domain):
    print("  - Interrogation de Sonar Omnisint...")
    url = f"https://sonar.omnisint.io/subdomains/{domain}"
    subdomains = set()
    try:
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            for sub in data:
                sub = sub.strip().lower()
                if sub.endswith(domain):
                    subdomains.add(sub)
    except Exception as e:
        print(f"    Erreur Sonar: {e}")
    return subdomains

def fetch_wayback(domain):
    print("  - Interrogation de Wayback Machine...")
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    subdomains = set()
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            # Skip header row if present
            if data and len(data) > 0 and data[0] == ["original"]:
                data = data[1:]
            
            for entry in data:
                # entry is like ["http://sub.example.com/path"]
                if entry:
                    url_val = entry[0]
                    # Extract domain from URL
                    parts = url_val.split('://')
                    if len(parts) > 1:
                        host = parts[1].split('/')[0]
                    else:
                        host = parts[0].split('/')[0]
                    
                    # Remove port if any
                    host = host.split(':')[0]
                    
                    host = host.strip().lower()
                    if host.endswith(domain):
                        subdomains.add(host)
    except Exception as e:
        print(f"    Erreur Wayback: {e}")
    return subdomains

def fetch_rapiddns(domain):
    print("  - Interrogation de RapidDNS...")
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    subdomains = set()
    try:
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            # Pattern to find domains ending with .domain in table cells
            pattern = r'<td>\s*([\w\.-]+\.' + re.escape(domain) + r')\s*</td>'
            matches = re.findall(pattern, response.text)
            for sub in matches:
                subdomains.add(sub.strip().lower())
    except Exception as e:
        print(f"    Erreur RapidDNS: {e}")
    return subdomains

def find_subdomains_iterative(domain):
    """
    Générateur qui renvoie la progression et les résultats.
    Yields: dict avec 'step', 'message', 'progress', et éventuellement 'data'
    """
    yield {"step": "init", "message": f"Démarrage de la recherche pour {domain}...", "progress": 5}
    
    all_results = set()
    
    # Liste des sources à interroger : (Nom, Fonction, PoidsProgression)
    # On garde crt.sh pour la fin car souvent plus lent/instable
    sources = [
        ("HackerTarget", fetch_hackertarget, 10),
        ("AlienVault", fetch_alienvault, 10),
        ("Anubis", fetch_anubis, 10),
        ("ThreatMiner", fetch_threatminer, 10),
        ("ThreatCrowd", fetch_threatcrowd, 10),
        ("RapidDNS", fetch_rapiddns, 10),
        ("Wayback", fetch_wayback, 15),
        ("crt.sh", fetch_crtsh, 20), # Plus gros poids car plus long
        ("Sonar", fetch_sonar, 10)
    ]
    
    current_progress = 5
    
    for name, func, weight in sources:
        yield {"step": name.lower(), "message": f"Interrogation de {name}...", "progress": current_progress}
        
        # Appel de la fonction de récupération
        new_subs = func(domain)
        
        # Calcul des nouveaux résultats uniques pour ce lot
        unique_new = new_subs - all_results
        if unique_new:
            all_results.update(unique_new)
            # On envoie immédiatement les nouveaux résultats trouvés
            yield {
                "step": "partial_result", 
                "source": name, 
                "new_subdomains": sorted(list(unique_new))
            }
            
        current_progress += weight
        yield {"step": f"{name.lower()}_done", "message": f"{name} terminé ({len(new_subs)} trouvés)", "progress": current_progress}
    
    # Sauvegarde
    yield {"step": "saving", "message": "Sauvegarde des résultats...", "progress": 98}
    save_to_file(domain, all_results)
    
    final_list = sorted(list(all_results))
    yield {"step": "finish", "message": f"Terminé ! {len(final_list)} sous-domaines trouvés au total.", "progress": 100, "data": final_list}

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
