# DEPLOIEMENT THE MINUTE (VPS Linux, ~5 minutes)

## 0. Prerequis
- VPS Debian/Ubuntu avec IP publique, acces root/sudo
- Domaine dont le DNS A pointe vers l'IP du VPS (fait chez le registrar)

## 1. Preparer le VPS (une fois)
    sudo useradd -r -m -d /opt/minute minute
    sudo mkdir -p /opt/minute/data
    sudo apt install -y caddy    # ou https://caddyserver.com/docs/install

## 2. Copier les 3 fichiers depuis cette machine
    scp server/target/release/minute-server  root@VPS:/opt/minute/
    scp server/config.json                   root@VPS:/opt/minute/
    scp index.html                           root@VPS:/opt/minute/
    # puis sur le VPS :
    sudo sed -i 's|"site_index": "../index.html"|"site_index": "/opt/minute/index.html"|' /opt/minute/config.json
    sudo chown -R minute:minute /opt/minute
    sudo chmod 600 /opt/minute/config.json

## 3. Lancer le service
    sudo cp deploy/minute-server.service /etc/systemd/system/
    sudo systemctl enable --now minute-server
    sudo systemctl status minute-server    # doit dire: listening on http://127.0.0.1:8080

## 3b. (optionnel) Codes promo influenceurs - chaque code = UNE gravure gratuite
    # 100 codes uniques, usage unique, imprimes UNE SEULE fois (garde-les) :
    sudo -u minute /opt/minute/minute-server gencodes 100 /opt/minute/config.json
    sudo systemctl restart minute-server    # les codes sont charges au demarrage
    # regenerer plus tard = gencodes PUIS restart. Etat : minute-server codes /opt/minute/config.json

## 4. HTTPS
    # deploy/Caddyfile cible deja minuteofforever.com (verifie que TU possedes ce domaine)
    sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
    sudo systemctl reload caddy

## 5. VERIFICATIONS FINALES (obligatoires)
    1. Ouvrir https://minuteofforever.com -> la montre s'affiche
    2. VERIFIER DES YEUX que l'adresse affichee lors d'un claim correspond
       bien a l'adresse (ou a l'xpub) de VOTRE config.json
    3. Admin (JAMAIS expose au public : Caddy renvoie 404 sur /admin depuis internet).
       Tunnel SSH direct au port serveur, puis ouvrir en local :
         ssh -L 9000:127.0.0.1:8080 <vps>
         http://localhost:9000/admin/<token du config.json>
    4. curl https://minuteofforever.com/api/health -> payments_open:true

## 6. Sauvegarde (l'actif = data/)
    # cron quotidien sur le VPS, copie hors-site :
    rsync -a /opt/minute/data/ user@ailleurs:/backup/minute/

## 7. Auto-maintenance (le serveur se tient tout seul)
    # mises a jour de securite automatiques :
    sudo apt install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades
    # le service redemarre seul (Restart=always dans l'unite systemd)
    # sauvegarde quotidienne hors-site (cron, 03h00) :
    echo '0 3 * * * root rsync -a /opt/minute/data/ USER@AILLEURS:/backup/minute/' | sudo tee /etc/cron.d/minute-backup
    # verification d'integrite de la chaine chaque nuit :
    echo '30 3 * * * minute /opt/minute/minute-server verify /opt/minute/data/chain.jsonl || echo CHAINE BRISEE' | sudo tee -a /etc/cron.d/minute-backup

## 8. Ancrage Bitcoin automatique (OpenTimestamps - cout : 0 sat)
    # Le sommet de la chaine scelle TOUT l'historique (chaque maillon contient
    # le hash du precedent) : un ancrage par nuit couvre toutes les gravures.
    # OTS est GRATUIT : les serveurs calendriers agregent des milliers de
    # hashes dans LEURS transactions Bitcoin et paient les frais.
    sudo apt install -y pipx
    sudo -u minute pipx install opentimestamps-client
    # chaque nuit a 04h00 : instantane date + preuve d'ancrage .ots
    echo '0 4 * * * minute mkdir -p /opt/minute/data/anchors && cp /opt/minute/data/chain.jsonl /opt/minute/data/anchors/chain-$(date +\%F).jsonl && /opt/minute/.local/bin/ots stamp /opt/minute/data/anchors/chain-$(date +\%F).jsonl' | sudo tee -a /etc/cron.d/minute-backup
    # la preuve devient definitive quand la transaction du calendrier confirme
    # (quelques heures) ; n'importe qui peut alors verifier pour toujours :
    #   ots verify chain-AAAA-MM-JJ.jsonl.ots

## 8b. Lien vers le BLOC Bitcoin (le site affiche "see the Bitcoin block")
    # Quand un .ots a confirme (quelques heures apres le stamp), extraire le
    # bloc et l'ecrire dans anchors/latest.json -> le client lit ce fichier et
    # transforme l'ancre des gravures en lien vers le bloc, verifiable par tous.
    #   ots upgrade /opt/minute/data/anchors/chain-AAAA-MM-JJ.jsonl.ots
    #   ots info    /opt/minute/data/anchors/chain-AAAA-MM-JJ.jsonl.ots   # lire "Bitcoin block N"
    #   echo '{"block_height": N}' > /opt/minute/data/anchors/latest.json
    # Format accepte par le client : {"block_height": N} (URL mempool.space/block/N)
    # ou {"block_url": "https://blockstream.info/block-height/N"} pour forcer l'URL.
    # Automatisable en cron (04h15) une fois le format d'`ots info` verifie chez toi.

## 9. Affiliation : le rituel mensuel (2 minutes, 1 signature)
    # La chaine des mains tourne toute seule : 25% A PLAT pour tout le monde
    # (chaque acheteur recoit son lien a 25%, tu gardes 75% sur CHAQUE vente
    # affiliee ; commissions accumulees UNIQUEMENT sur ventes gravees).
    # Modele plat single-tier : PAS de 2e etage (retire du code, CWE-639).
    # Auto-parrainage bloque (parrain = adresse de recompense, OU meme IP).
    # Chaque mois :
    1. Lister ce qui est du :
       sudo -u minute /opt/minute/minute-server payouts /opt/minute/config.json
    2. Dans Sparrow : UNE transaction groupee vers ces adresses (les soldes
       sous le seuil de 10 000 sats sont reportes au mois suivant).
    3. Sur /admin/<token> : coller le txid dans MARK PAYOUTS PAID.
       Le txid devient PUBLIC sur /affiliates.json : paiements prouvables
       sur Bitcoin par n'importe qui - c'est l'aimant a recruteurs.
    # LOI : commissions UNIQUEMENT sur ventes gravees, jamais un sat pour du recrutement.

## 10. Sceau du site (LE DERNIER geste, quand plus RIEN ne bouge)
    # Le site se notarise LUI-MEME sur Bitcoin : la preuve vit dans le footer
    # (banniere verte "authentic" / rouge "modified", recalculee dans le
    # navigateur du visiteur). Tant que non scelle, le footer ne montre rien.
    # 1) Calculer le hash du index.html FINAL :
    python3 PREUVES/seal-site.py hash index.html
    # 2) Dans Sparrow : diffuser UNE transaction avec une sortie OP_RETURN egale
    #    a ce hash (32 octets). Noter le txid et le bloc de confirmation.
    # 3) Ecrire l'ancrage (le hash reste IDENTIQUE - la self-consistance s'affiche) :
    python3 PREUVES/seal-site.py anchor <txid> <bloc> index.html
    # 4) Re-deployer ce index.html final (scp au VPS) + reload. Le footer se scelle.
    # Verif : PREUVES/seal-test.sh prouve le round-trip (python == navigateur).

## Rappels
- Le binaire est compile sur CETTE machine (Linux x86_64) : compatible VPS standard.
- 2FA sur les comptes VPS + registrar (la seule vraie attaque = substitution d'adresse).
- Apres CHAQUE redeploiement : re-verifier l'adresse des yeux (point 5.2).
