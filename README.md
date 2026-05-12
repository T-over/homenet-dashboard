# 🏠 HomeNet Dashboard

Application web locale auto-hébergée pour superviser votre réseau domestique : scan des appareils, mesures de débit, détection de CVEs et alertes en temps réel.

```
╔══════════════════════════════════════════════════════════════╗
║  HomeNet Dashboard                            22:14:08  ●   ║
╠══════════════════════════════════════════════════════════════╣
║  📡 Appareils  │  ⬇ Download  │  ⬆ Upload  │  🛡 CVE Crit  ║
║       8        │   94.2 Mbps  │  42.1 Mbps  │      0       ║
╠══════════════════════════════════════════════════════════════╣
║  🖧 Carte réseau                                             ║
║  192.168.1.1   │ router       │ Xiaomi       │ ● En ligne   ║
║  192.168.1.12  │ nas-theo     │ Synology     │ ● En ligne   ║
║  192.168.1.45  │ android-s24  │ Samsung      │ ○ Hors ligne ║
╠══════════════════════════════════════════════════════════════╣
║  📶 Graphique débits (24h)   │  🔔 Alertes                  ║
║  ▁▂▄▆▇▆▅▄▃▄▅▆▇▇▆▅           │  [HAUTE] Nouvel appareil     ║
╚══════════════════════════════════════════════════════════════╝
```

## Prérequis

- **Python 3.11+**
- **nmap** installé sur le système : `sudo apt install nmap`
- Accès root ou sudo pour les scans réseau

## Installation

```bash
# 1. Cloner le projet
git clone https://github.com/T-over/homenet-dashboard.git
cd homenet-dashboard

# 2. Créer un environnement virtuel
python3 -m venv .venv
source .venv/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Configurer l'environnement
cp .env.example .env
nano .env

# 5. Lancer le serveur
sudo .venv/bin/python main.py
```

Ouvrez ensuite `http://localhost:8000` dans votre navigateur.

## Configuration systemd

Créez `/etc/systemd/system/homenet.service` :

```ini
[Unit]
Description=HomeNet Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/homenet-dashboard
ExecStart=/opt/homenet-dashboard/.venv/bin/python main.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Activez le service :

```bash
sudo cp -r . /opt/homenet-dashboard
sudo systemctl daemon-reload
sudo systemctl enable homenet
sudo systemctl start homenet
```

## Accès depuis votre téléphone (Tailscale)

1. Installer Tailscale sur la VM : `curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up`
2. Installer Tailscale sur votre téléphone
3. Récupérer l'IP Tailscale : `tailscale ip -4`
4. Accéder depuis le téléphone : `http://<IP-TAILSCALE>:8000`

## Sécurité

⚠️ **Ne jamais exposer ce dashboard directement sur Internet** sans authentification forte.
- Accès exclusivement via VPN (Tailscale, WireGuard)
- Ne pas ouvrir le port 8000 dans votre box/routeur

## Variables d'environnement

| Variable | Description | Défaut |
|---|---|---|
| `NETWORK_RANGE` | Plage CIDR à scanner | `192.168.1.0/24` |
| `SPEEDTEST_INTERVAL_MIN` | Intervalle speedtest (min) | `60` |
| `ALERT_THRESHOLD_MBPS` | Seuil débit bas (Mbps) | `50.0` |
| `DATABASE_PATH` | Chemin base SQLite | `homenet.db` |
| `HOST` | Interface d'écoute | `0.0.0.0` |
| `PORT` | Port du serveur | `8000` |
| `NVD_API_KEY` | Clé API NIST (optionnel) | — |
