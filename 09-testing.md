# 9. Tests et Validation

Ce chapitre présente les méthodes et outils pour tester et valider la configuration de SPF, DKIM, DMARC et ARC. Un processus de test rigoureux est essentiel pour garantir la délivrabilité et la sécurité.

## 9.1 Tests DNS préliminaires

### Vérification des enregistrements DNS

#### Test SPF

```bash
# Vérifier l'enregistrement SPF
dig TXT exemple.fr +short | grep spf

# Vérifier depuis plusieurs serveurs DNS
dig @8.8.8.8 TXT exemple.fr +short | grep spf
dig @1.1.1.1 TXT exemple.fr +short | grep spf

# Test avec nslookup
nslookup -type=TXT exemple.fr

# Vérifier avec host
host -t TXT exemple.fr
```

#### Test DKIM

```bash
# Vérifier la clé DKIM publique
dig TXT default._domainkey.exemple.fr +short

# Test avec multiples sélecteurs
for selector in default s1 s2 google; do
    echo "=== Sélecteur: $selector ==="
    dig TXT ${selector}._domainkey.exemple.fr +short
done

# Vérifier la longueur de la clé
dig TXT default._domainkey.exemple.fr +short | tr -d '"' | tr -d ' ' | wc -c
```

#### Test DMARC

```bash
# Vérifier l'enregistrement DMARC
dig TXT _dmarc.exemple.fr +short

# Vérifier pour sous-domaine
dig TXT _dmarc.subdomain.exemple.fr +short

# Tester avec dmarcian
curl -s "https://dmarcian.com/dmarc-inspector/?domain=exemple.fr"
```

#### Test ARC

```bash
# Vérifier la clé ARC publique
dig TXT arc._domainkey.exemple.fr +short
```

### Validation de la propagation DNS

```bash
#!/bin/bash
# check-dns-propagation.sh

DOMAIN="exemple.fr"
SELECTOR="default"

DNS_SERVERS=(
    "8.8.8.8"        # Google
    "1.1.1.1"        # Cloudflare
    "9.9.9.9"        # Quad9
    "208.67.222.222" # OpenDNS
)

echo "=== SPF Propagation ==="
for dns in "${DNS_SERVERS[@]}"; do
    echo -n "$dns: "
    dig @$dns TXT $DOMAIN +short | grep spf || echo "NOT FOUND"
done

echo ""
echo "=== DKIM Propagation ==="
for dns in "${DNS_SERVERS[@]}"; do
    echo -n "$dns: "
    dig @$dns TXT ${SELECTOR}._domainkey.$DOMAIN +short | head -1 || echo "NOT FOUND"
done

echo ""
echo "=== DMARC Propagation ==="
for dns in "${DNS_SERVERS[@]}"; do
    echo -n "$dns: "
    dig @$dns TXT _dmarc.$DOMAIN +short || echo "NOT FOUND"
done
```

## 9.2 Validation syntaxique

### Validation SPF

**Outil : spf-test**

```bash
# Installation
pip3 install spf-test

# Test syntaxe SPF
spf-test check exemple.fr

# Test avec IP source
spf-test check exemple.fr --ip 192.0.2.10 --sender test@exemple.fr
```

**Validation en ligne de commande**

```python
#!/usr/bin/env python3
# validate-spf.py

import re
import sys
import dns.resolver

def validate_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record = None
        
        for rdata in answers:
            text = str(rdata).strip('"')
            if text.startswith('v=spf1'):
                spf_record = text
                break
        
        if not spf_record:
            print(f"❌ Aucun enregistrement SPF trouvé pour {domain}")
            return False
        
        print(f"✅ Enregistrement SPF trouvé: {spf_record}")
        
        # Vérifications
        checks = [
            (spf_record.startswith('v=spf1'), "Commence par v=spf1"),
            (spf_record.endswith((' -all', ' ~all', ' ?all', ' +all')), "Se termine par un qualificateur all"),
            (spf_record.count(' ') <= 10, "Nombre de mécanismes raisonnable"),
            (len(spf_record) <= 255, "Longueur < 255 caractères"),
        ]
        
        for check, desc in checks:
            status = "✅" if check else "❌"
            print(f"{status} {desc}")
        
        return all(c[0] for c in checks)
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    result = validate_spf(domain)
    sys.exit(0 if result else 1)
```

### Validation DKIM

**Test de la clé publique**

```python
#!/usr/bin/env python3
# validate-dkim.py

import dns.resolver
import re
import sys
from base64 import b64decode

def validate_dkim(domain, selector):
    dkim_domain = f"{selector}._domainkey.{domain}"
    
    try:
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        dkim_record = ''.join([str(rdata).strip('"') for rdata in answers])
        
        print(f"✅ Enregistrement DKIM trouvé pour {dkim_domain}")
        print(f"Contenu: {dkim_record[:80]}...")
        
        # Parsing
        parts = {}
        for part in dkim_record.split(';'):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                parts[key.strip()] = value.strip()
        
        # Vérifications
        checks = [
            ('v' in parts and parts['v'] == 'DKIM1', "Version DKIM1"),
            ('k' in parts and parts['k'] in ['rsa', 'ed25519'], "Type de clé valide"),
            ('p' in parts and len(parts['p']) > 100, "Clé publique présente et suffisamment longue"),
            ('h' not in parts or 'sha256' in parts['h'], "Algorithme SHA256 autorisé"),
        ]
        
        for check, desc in checks:
            status = "✅" if check else "⚠️"
            print(f"{status} {desc}")
        
        # Estimer la taille de la clé
        if 'p' in parts:
            try:
                key_data = b64decode(parts['p'] + '==')
                key_size = len(key_data) * 8
                print(f"📏 Taille estimée de la clé: ~{key_size} bits")
                if key_size < 2000:
                    print("⚠️  Attention: clé < 2048 bits (recommandé: 2048)")
            except:
                print("⚠️  Impossible de décoder la clé publique")
        
        return all(c[0] for c in checks)
        
    except dns.resolver.NXDOMAIN:
        print(f"❌ Enregistrement DKIM non trouvé: {dkim_domain}")
        return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <domain> <selector>")
        sys.exit(1)
    
    domain = sys.argv[1]
    selector = sys.argv[2]
    result = validate_dkim(domain, selector)
    sys.exit(0 if result else 1)
```

### Validation DMARC

```python
#!/usr/bin/env python3
# validate-dmarc.py

import dns.resolver
import re
import sys

def validate_dmarc(domain):
    dmarc_domain = f"_dmarc.{domain}"
    
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_record = str(answers[0]).strip('"')
        
        print(f"✅ Enregistrement DMARC trouvé: {dmarc_record}")
        
        # Parsing
        parts = {}
        for part in dmarc_record.split(';'):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                parts[key.strip()] = value.strip()
        
        # Vérifications
        checks = [
            ('v' in parts and parts['v'] == 'DMARC1', "Version DMARC1"),
            ('p' in parts and parts['p'] in ['none', 'quarantine', 'reject'], "Politique valide"),
            ('rua' in parts or 'ruf' in parts, "Au moins une adresse de rapport configurée"),
        ]
        
        for check, desc in checks:
            status = "✅" if check else "❌"
            print(f"{status} {desc}")
        
        # Afficher les paramètres importants
        if 'p' in parts:
            print(f"📋 Politique: {parts['p']}")
        if 'sp' in parts:
            print(f"📋 Politique sous-domaines: {parts['sp']}")
        if 'pct' in parts:
            print(f"📋 Pourcentage: {parts['pct']}%")
        if 'rua' in parts:
            print(f"📧 Rapports agrégés: {parts['rua']}")
        if 'ruf' in parts:
            print(f"📧 Rapports forensiques: {parts['ruf']}")
        
        # Avertissements
        if parts.get('p') == 'none':
            print("⚠️  Politique 'none' : mode monitoring uniquement")
        
        if parts.get('pct') and int(parts['pct']) < 100:
            print(f"⚠️  Seulement {parts['pct']}% des emails soumis à la politique")
        
        return all(c[0] for c in checks)
        
    except dns.resolver.NXDOMAIN:
        print(f"❌ Enregistrement DMARC non trouvé: {dmarc_domain}")
        return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    result = validate_dmarc(domain)
    sys.exit(0 if result else 1)
```

## 9.3 Tests d'envoi d'emails

### Test basique avec mail

```bash
# Envoyer un email simple
echo "Ceci est un test" | mail -s "Test SPF/DKIM/DMARC" destinataire@exemple.com

# Envoyer avec From: personnalisé
echo "Test" | mail -s "Test" -a "From: expediteur@exemple.fr" destinataire@exemple.com

# Envoyer avec pièce jointe
echo "Test avec PJ" | mail -s "Test" -A /path/to/file.pdf destinataire@exemple.com
```

### Test avec swaks

**Installation**

```bash
# Debian/Ubuntu
apt install -y swaks

# Rocky/AlmaLinux
dnf install -y swaks

# macOS
brew install swaks
```

**Tests basiques**

```bash
# Test SMTP simple
swaks --to destinataire@exemple.com \
      --from expediteur@exemple.fr \
      --server mail.exemple.fr

# Test avec authentification
swaks --to destinataire@exemple.com \
      --from expediteur@exemple.fr \
      --server mail.exemple.fr \
      --auth-user user@exemple.fr \
      --auth-password 'password'

# Test avec TLS
swaks --to destinataire@exemple.com \
      --from expediteur@exemple.fr \
      --server mail.exemple.fr \
      --tls

# Test avec en-têtes personnalisés
swaks --to destinataire@exemple.com \
      --from expediteur@exemple.fr \
      --server mail.exemple.fr \
      --header "X-Test: true" \
      --body "Corps du message"
```

### Services de test automatisés

#### Port25 Verifier

```bash
# Envoyer à l'adresse de test
echo "Test authentification email" | mail -s "Test" check-auth@verifier.port25.com

# Vous recevrez un rapport détaillé incluant:
# - Résultat SPF
# - Résultat DKIM avec détails de signature
# - Résultat DMARC
# - Alignement des identifiants
# - En-têtes complets
```

#### DKIM Core Validator

```bash
# Envoyer à l'adresse de test DKIM
echo "Test DKIM signature" | mail -s "Test DKIM" autorespond+dkim@dk.elandsys.com

# Rapport reçu contient:
# - Validation de la signature DKIM
# - Vérification de la clé publique DNS
# - Canonicalisation utilisée
# - Algorithme de hachage
```

#### Mail Tester

```bash
# 1. Visiter https://www.mail-tester.com/
# 2. Noter l'adresse email générée (ex: test-abc123@srv1.mail-tester.com)
# 3. Envoyer un email à cette adresse
echo "Test complet" | mail -s "Test Mail-Tester" test-abc123@srv1.mail-tester.com

# 4. Consulter le rapport (score /10) incluant:
#    - SPF, DKIM, DMARC
#    - SpamAssassin score
#    - Blacklists
#    - Configuration serveur
```

## 9.4 Analyse des en-têtes email

### Extraire et analyser les en-têtes

#### Gmail

1. Ouvrir l'email
2. Cliquer sur les trois points (⋮)
3. Sélectionner "Afficher l'original"
4. Rechercher les sections :

```
Received-SPF: pass
Authentication-Results: spf=pass; dkim=pass; dmarc=pass
DKIM-Signature: v=1; a=rsa-sha256; d=exemple.fr; ...
```

#### Outlook / Office 365

1. Ouvrir l'email
2. Fichier → Propriétés → En-têtes Internet
3. Copier et analyser

### Script d'analyse d'en-têtes

```python
#!/usr/bin/env python3
# analyze-headers.py

import re
import sys
import email
from email.parser import Parser

def analyze_email_headers(file_path):
    with open(file_path, 'r') as f:
        msg = Parser().parse(f)
    
    print("=== Analyse des en-têtes d'authentification ===")
    print()
    
    # SPF
    spf_header = msg.get('Received-SPF', 'Non trouvé')
    print(f"📬 SPF: {spf_header}")
    if 'pass' in spf_header.lower():
        print("   ✅ SPF PASS")
    elif 'fail' in spf_header.lower():
        print("   ❌ SPF FAIL")
    
    print()
    
    # DKIM
    dkim_sig = msg.get('DKIM-Signature', '')
    if dkim_sig:
        print("🔐 DKIM Signature présente:")
        # Parser les paramètres DKIM
        dkim_params = {}
        for param in dkim_sig.split(';'):
            param = param.strip()
            if '=' in param:
                key, value = param.split('=', 1)
                dkim_params[key.strip()] = value.strip()
        
        print(f"   - Version: {dkim_params.get('v', 'N/A')}")
        print(f"   - Algorithme: {dkim_params.get('a', 'N/A')}")
        print(f"   - Domaine: {dkim_params.get('d', 'N/A')}")
        print(f"   - Sélecteur: {dkim_params.get('s', 'N/A')}")
        print(f"   - Canonicalisation: {dkim_params.get('c', 'N/A')}")
    else:
        print("❌ Aucune signature DKIM trouvée")
    
    print()
    
    # Authentication-Results
    auth_results = msg.get('Authentication-Results', 'Non trouvé')
    print(f"🔍 Authentication-Results:")
    print(f"   {auth_results}")
    
    # Analyser les résultats
    if 'spf=pass' in auth_results.lower():
        print("   ✅ SPF pass")
    if 'dkim=pass' in auth_results.lower():
        print("   ✅ DKIM pass")
    if 'dmarc=pass' in auth_results.lower():
        print("   ✅ DMARC pass")
    if 'arc=pass' in auth_results.lower():
        print("   ✅ ARC pass")
    
    print()
    
    # ARC (si présent)
    arc_headers = [(k, v) for k, v in msg.items() if k.startswith('ARC-')]
    if arc_headers:
        print(f"🔗 En-têtes ARC détectés: {len(arc_headers)}")
        for header, value in arc_headers:
            print(f"   {header}: {value[:80]}...")
    
    print()
    print("=== Informations d'acheminement ===")
    
    # From / Return-Path
    print(f"📤 From: {msg.get('From', 'N/A')}")
    print(f"📮 Return-Path: {msg.get('Return-Path', 'N/A')}")
    print(f"📬 To: {msg.get('To', 'N/A')}")
    
    # Received headers
    received_headers = msg.get_all('Received', [])
    print(f"\n📨 Nombre de sauts (Received): {len(received_headers)}")
    for i, received in enumerate(received_headers[:3], 1):
        print(f"   Saut {i}: {received[:80]}...")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <email_file.eml>")
        sys.exit(1)
    
    analyze_email_headers(sys.argv[1])
```

## 9.5 Tests de conformité des fournisseurs

### Gmail

```bash
# Créer un compte Gmail de test
# Envoyer des emails depuis votre serveur
echo "Test Gmail" | mail -s "Test" votre.compte.test@gmail.com

# Vérifier :
# 1. L'email arrive-t-il dans Inbox (pas Spam) ?
# 2. Y a-t-il des avertissements de sécurité ?
# 3. Afficher l'original et vérifier Authentication-Results
```

**Critères Gmail :**
- SPF : PASS requis
- DKIM : PASS requis (minimum 1024 bits, recommandé 2048)
- DMARC : PASS recommandé
- Alignement : Relaxed minimum
- Reverse DNS (PTR) : obligatoire

### Microsoft 365 / Outlook.com

```bash
# Tester avec compte Outlook.com
echo "Test Outlook" | mail -s "Test" votre.compte.test@outlook.com

# Vérifier via SNDS (Sender Reputation Data)
# https://sendersupport.olc.protection.outlook.com/snds/
```

**Critères Microsoft :**
- SPF : PASS ou Neutral acceptable
- DKIM : Fortement recommandé
- DMARC : Requis pour bonnes pratiques
- Réputation IP : critique

### Yahoo Mail

```bash
# Tester avec compte Yahoo
echo "Test Yahoo" | mail -s "Test" votre.compte.test@yahoo.com
```

**Critères Yahoo :**
- DKIM : Obligatoire (2048 bits minimum)
- DMARC : Obligatoire avec p=reject ou p=quarantine
- SPF : Recommandé

### Tests automatisés multi-fournisseurs

```bash
#!/bin/bash
# test-all-providers.sh

FROM="test@exemple.fr"
SUBJECT="Test automatisé $(date +%Y%m%d-%H%M%S)"
BODY="Test d'authentification email\n\nSPF, DKIM, DMARC"

PROVIDERS=(
    "test-gmail@gmail.com"
    "test-outlook@outlook.com"
    "test-yahoo@yahoo.com"
    "test-icloud@icloud.com"
    "test-proton@protonmail.com"
)

echo "Envoi d'emails de test..."

for recipient in "${PROVIDERS[@]}"; do
    echo "Envoi vers: $recipient"
    echo -e "$BODY" | mail -s "$SUBJECT" -a "From: $FROM" "$recipient"
    sleep 2
done

echo ""
echo "Tests envoyés. Vérifiez manuellement :"
echo "1. Réception (Inbox vs Spam)"
echo "2. En-têtes Authentication-Results"
echo "3. Avertissements de sécurité"
```

## 9.6 Outils de test en ligne

### MXToolbox

```bash
# Tests via API (nécessite compte gratuit)
curl -X GET "https://mxtoolbox.com/api/v1/Lookup/spf?argument=exemple.fr" \
     -H "Authorization: Bearer YOUR_API_KEY"

curl -X GET "https://mxtoolbox.com/api/v1/Lookup/dmarc?argument=exemple.fr" \
     -H "Authorization: Bearer YOUR_API_KEY"
```

**Tests web disponibles :**
- https://mxtoolbox.com/spf.aspx
- https://mxtoolbox.com/dkim.aspx
- https://mxtoolbox.com/dmarc.aspx
- https://mxtoolbox.com/SuperTool.aspx (tout-en-un)

### DMARC Analyzer

**URL :** https://www.dmarcanalyzer.com/

- Test DMARC complet
- Validation SPF
- Validation DKIM
- Simulation de rapports

### Google Admin Toolbox

**URL :** https://toolbox.googleapps.com/apps/checkmx/

```bash
# Via curl
curl -X POST "https://toolbox.googleapps.com/apps/checkmx/check" \
     -d "domain=exemple.fr"
```

Tests inclus :
- Enregistrements MX
- SPF
- DMARC
- DKIM (si sélecteur fourni)

## 9.7 Tests de charge et performance

### Test de charge avec postal

```bash
# Installer postal (outil de test SMTP)
git clone https://github.com/psmiraglia/postal.git
cd postal
pip3 install -r requirements.txt

# Test de charge
python3 postal.py \
    --host mail.exemple.fr \
    --port 25 \
    --from test@exemple.fr \
    --to destinataire@exemple.com \
    --count 100 \
    --threads 10
```

### Surveiller les performances

```bash
#!/bin/bash
# monitor-smtp-performance.sh

HOST="mail.exemple.fr"
PORT=25
LOGFILE="/var/log/smtp-performance.log"

while true; do
    START=$(date +%s%N)
    
    timeout 5 bash -c "echo QUIT | nc $HOST $PORT > /dev/null 2>&1"
    RESULT=$?
    
    END=$(date +%s%N)
    DURATION=$(( (END - START) / 1000000 ))
    
    if [ $RESULT -eq 0 ]; then
        echo "$(date -Iseconds) SUCCESS ${DURATION}ms" >> "$LOGFILE"
    else
        echo "$(date -Iseconds) FAILED ${DURATION}ms" >> "$LOGFILE"
    fi
    
    sleep 60
done
```

## 9.8 Tests de sécurité

### Test des politiques SPF strictes

```bash
# Tester depuis une IP non autorisée
swaks --to destinataire@exemple.com \
      --from spoofed@exemple.fr \
      --server mail-externe.autre-domaine.com

# Vérifier les logs du destinataire
# Attendu: SPF fail
```

### Test de signature DKIM invalide

```bash
# Modifier manuellement un email signé DKIM
# Attendu: DKIM fail lors de la vérification

# Simuler avec un script
cat << 'EOF' > test-dkim-tamper.py
import email
from email.parser import Parser

with open('email_signe.eml', 'r') as f:
    msg = Parser().parse(f)

# Modifier le corps (invalide la signature)
msg.set_payload(msg.get_payload() + "\n\nTEXTE AJOUTE")

with open('email_modifie.eml', 'w') as f:
    f.write(msg.as_string())
EOF

python3 test-dkim-tamper.py
```

### Test de conformité DMARC

```bash
# Test d'alignement SPF
# From: user@exemple.fr
# MAIL FROM: <bounce@autre-domaine.com>
# Attendu: DMARC fail (alignement SPF échoue)

swaks --to destinataire@exemple.com \
      --from user@exemple.fr \
      --envelope-from bounce@autre-domaine.com \
      --server mail.exemple.fr
```

## 9.9 Documentation des résultats

### Template de rapport de test

```markdown
# Rapport de Test - Authentification Email

**Date :** 2026-02-10
**Domaine :** exemple.fr
**Testeur :** Nom Prénom

## Résumé Exécutif

- ✅ SPF : Configuré et fonctionnel
- ✅ DKIM : Signature valide (2048 bits)
- ✅ DMARC : Politique enforce (p=reject)
- ✅ Délivrabilité : 100% des emails de test délivrés

## Tests DNS

### SPF
```
v=spf1 mx ip4:192.0.2.10 -all
```
- Syntaxe : ✅
- Propagation : ✅ (vérifié sur 4 DNS publics)
- Lookups : 3/10

### DKIM
```
Sélecteur : default
Algorithme : rsa-sha256
Taille clé : 2048 bits
```
- Clé publique DNS : ✅
- Syntaxe : ✅
- Longueur adéquate : ✅

### DMARC
```
v=DMARC1; p=reject; rua=mailto:dmarc@exemple.fr
```
- Syntaxe : ✅
- Politique : reject
- Rapports configurés : ✅

## Tests d'Envoi

### Gmail
- Délivrabilité : ✅ Inbox
- SPF : PASS
- DKIM : PASS
- DMARC : PASS
- Score Mail-Tester : 9.5/10

### Outlook.com
- Délivrabilité : ✅ Inbox
- SPF : PASS
- DKIM : PASS
- DMARC : PASS

### Yahoo Mail
- Délivrabilité : ✅ Inbox
- SPF : PASS
- DKIM : PASS
- DMARC : PASS

## Tests de Sécurité

- ✅ Spoofing bloqué (SPF fail)
- ✅ Modification détectée (DKIM fail)
- ✅ Alignement vérifié (DMARC)

## Recommandations

1. Aucune action requise - configuration optimale
2. Continuer le monitoring des rapports DMARC
3. Planifier rotation clé DKIM dans 6 mois

## Annexes

- Logs complets : voir `/var/log/tests-2026-02-10.log`
- En-têtes emails : voir dossier `headers/`
```

## 9.10 Automatisation des tests

### Script de test complet

```bash
#!/bin/bash
# comprehensive-email-test.sh

DOMAIN="exemple.fr"
SELECTOR="default"
TEST_EMAIL="test-$(date +%s)@exemple.fr"
LOG_DIR="/var/log/email-tests"
REPORT_FILE="${LOG_DIR}/report-$(date +%Y%m%d-%H%M%S).txt"

mkdir -p "${LOG_DIR}"

echo "=================================" | tee "${REPORT_FILE}"
echo "Test Complet - Authentification Email" | tee -a "${REPORT_FILE}"
echo "Date: $(date)" | tee -a "${REPORT_FILE}"
echo "Domaine: ${DOMAIN}" | tee -a "${REPORT_FILE}"
echo "=================================" | tee -a "${REPORT_FILE}"
echo "" | tee -a "${REPORT_FILE}"

# Test DNS
echo "[1/5] Tests DNS..." | tee -a "${REPORT_FILE}"

# SPF
SPF=$(dig +short TXT "${DOMAIN}" | grep spf)
if [ -n "$SPF" ]; then
    echo "✅ SPF: $SPF" | tee -a "${REPORT_FILE}"
else
    echo "❌ SPF: Non trouvé" | tee -a "${REPORT_FILE}"
fi

# DKIM
DKIM=$(dig +short TXT "${SELECTOR}._domainkey.${DOMAIN}")
if [ -n "$DKIM" ]; then
    echo "✅ DKIM: Clé trouvée" | tee -a "${REPORT_FILE}"
else
    echo "❌ DKIM: Non trouvé" | tee -a "${REPORT_FILE}"
fi

# DMARC
DMARC=$(dig +short TXT "_dmarc.${DOMAIN}")
if [ -n "$DMARC" ]; then
    echo "✅ DMARC: $DMARC" | tee -a "${REPORT_FILE}"
else
    echo "❌ DMARC: Non trouvé" | tee -a "${REPORT_FILE}"
fi

echo "" | tee -a "${REPORT_FILE}"

# Test services locaux
echo "[2/5] Tests Services..." | tee -a "${REPORT_FILE}"

for service in postfix opendkim opendmarc; do
    if systemctl is-active --quiet "$service"; then
        echo "✅ $service: actif" | tee -a "${REPORT_FILE}"
    else
        echo "❌ $service: inactif" | tee -a "${REPORT_FILE}"
    fi
done

echo "" | tee -a "${REPORT_FILE}"

# Test d'envoi
echo "[3/5] Test d'envoi..." | tee -a "${REPORT_FILE}"

echo "Test automatisé" | mail -s "Test Auto $(date)" check-auth@verifier.port25.com
if [ $? -eq 0 ]; then
    echo "✅ Email envoyé à Port25" | tee -a "${REPORT_FILE}"
else
    echo "❌ Échec d'envoi" | tee -a "${REPORT_FILE}"
fi

echo "" | tee -a "${REPORT_FILE}"

# Analyse des logs
echo "[4/5] Analyse logs (dernière heure)..." | tee -a "${REPORT_FILE}"

SPF_PASS=$(grep -c "SPF pass" /var/log/mail.log | tail -100 || echo 0)
DKIM_PASS=$(grep -c "DKIM pass" /var/log/mail.log | tail -100 || echo 0)
DMARC_PASS=$(grep -c "DMARC pass" /var/log/mail.log | tail -100 || echo 0)

echo "SPF pass: $SPF_PASS" | tee -a "${REPORT_FILE}"
echo "DKIM pass: $DKIM_PASS" | tee -a "${REPORT_FILE}"
echo "DMARC pass: $DMARC_PASS" | tee -a "${REPORT_FILE}"

echo "" | tee -a "${REPORT_FILE}"

# Rapport final
echo "[5/5] Résumé..." | tee -a "${REPORT_FILE}"
echo "Rapport complet: ${REPORT_FILE}" | tee -a "${REPORT_FILE}"
echo "" | tee -a "${REPORT_FILE}"
echo "Pour analyse approfondie :" | tee -a "${REPORT_FILE}"
echo "- Vérifier les rapports DMARC reçus" | tee -a "${REPORT_FILE}"
echo "- Consulter https://www.mail-tester.com/" | tee -a "${REPORT_FILE}"
echo "- Analyser en-têtes emails reçus" | tee -a "${REPORT_FILE}"

echo "" | tee -a "${REPORT_FILE}"
echo "=================================" | tee -a "${REPORT_FILE}"
echo "Test terminé avec succès" | tee -a "${REPORT_FILE}"
echo "=================================" | tee -a "${REPORT_FILE}"
```

**Rendre exécutable et automatiser :**

```bash
chmod +x /usr/local/bin/comprehensive-email-test.sh

# Cron hebdomadaire
echo "0 8 * * 1 /usr/local/bin/comprehensive-email-test.sh" | crontab -
```

## 9.11 Checklist de validation finale

```markdown
### Checklist Tests Email

#### DNS
☐ SPF publié et syntaxe valide
☐ DKIM clé publique accessible
☐ DMARC publié avec adresses rapports
☐ PTR (reverse DNS) configuré
☐ Propagation DNS vérifiée (24-48h)

#### Services
☐ Postfix actif et opérationnel
☐ OpenDKIM actif et signe correctement
☐ OpenDMARC actif
☐ Logs sans erreurs critiques

#### Tests d'envoi
☐ Email vers Gmail délivré (Inbox)
☐ Email vers Outlook délivré (Inbox)
☐ Email vers Yahoo délivré (Inbox)
☐ Port25 Verifier : tous PASS
☐ Mail-Tester score ≥ 8/10

#### Sécurité
☐ Spoofing bloqué (test SPF fail)
☐ Modification détectée (test DKIM)
☐ Alignement DMARC vérifié
☐ Politique DMARC appropriée (none/quarantine/reject)

#### Monitoring
☐ Scripts de monitoring en place
☐ Alertes configurées
☐ Rotation des clés planifiée
☐ Documentation à jour
```

## Conclusion

Un processus de test rigoureux et régulier est essentiel pour garantir l'efficacité des mécanismes d'authentification email. Les tests doivent couvrir à la fois les aspects techniques (DNS, signatures) et pratiques (délivrabilité réelle). L'automatisation des tests permet de détecter rapidement les problèmes et maintenir une configuration optimale.