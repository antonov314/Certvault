#!/bin/bash

# Proxmox LXC Container Setup & CertVault Installer
# v1.0

# Configuratie variabelen
CONTAINER_ID="999"  # Pas dit aan naar gewenste container ID
CONTAINER_NAME="certvault"
CONTAINER_PASSWORD="CertVault@2024"  # Verander dit wachtwoord
CONTAINER_HOSTNAME="certvault"
CONTAINER_IP="dhcp"  # Verander naar statisch IP indien gewenst
CONTAINER_MEMORY="1024"  # 1GB RAM
CONTAINER_SWAP="512"    # 512MB SWAP
CONTAINER_CORES="2"     # 2 CPU cores
CONTAINER_STORAGE="local-lvm"  # Pas aan naar je Proxmox storage
CONTAINER_TEMPLATE="local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.gz"

echo "CertVault - Proxmox LXC Container Installer"
echo "----------------------------------------"

# Check of we root zijn
if [ "$EUID" -ne 0 ]; then 
    echo "Dit script moet als root worden uitgevoerd"
    exit 1
fi

# Check of pct (Proxmox Container Tools) beschikbaar is
if ! command -v pct &> /dev/null; then
    echo "Proxmox Container Tools (pct) niet gevonden. Is dit een Proxmox server?"
    exit 1
fi

echo "1. LXC Container aanmaken..."
pct create $CONTAINER_ID $CONTAINER_TEMPLATE \
    --hostname $CONTAINER_HOSTNAME \
    --password $CONTAINER_PASSWORD \
    --memory $CONTAINER_MEMORY \
    --swap $CONTAINER_SWAP \
    --cores $CONTAINER_CORES \
    --net0 name=eth0,ip=$CONTAINER_IP,bridge=vmbr0 \
    --storage $CONTAINER_STORAGE \
    --unprivileged 1 \
    --features nesting=1

echo "2. Container starten..."
pct start $CONTAINER_ID

# Wacht tot container volledig is opgestart
echo "Wachten tot container is opgestart..."
sleep 10

echo "3. Basis packages installeren..."
pct exec $CONTAINER_ID -- bash -c "apt update && apt upgrade -y"
pct exec $CONTAINER_ID -- bash -c "apt install -y python3 python3-pip python3-venv git"

echo "4. CertVault applicatie downloaden..."
pct exec $CONTAINER_ID -- bash -c "cd /opt && git clone https://github.com/antonov314/Certvault.git"

echo "5. CertVault installeren..."
pct exec $CONTAINER_ID -- bash -c "cd /opt/Certvault && chmod +x install.sh && ./install.sh"

echo "6. Systemd service aanmaken..."
# Maak service bestand
cat > /tmp/certvault.service << EOL
[Unit]
Description=CertVault SSL Certificate Generator
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/Certvault
Environment=PATH=/opt/Certvault/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/opt/Certvault/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOL

# Kopieer service bestand naar container
pct push $CONTAINER_ID /tmp/certvault.service /etc/systemd/system/certvault.service

# Start de service
pct exec $CONTAINER_ID -- bash -c "systemctl daemon-reload && systemctl enable certvault && systemctl start certvault"

echo "----------------------------------------"
echo "Installatie voltooid!"
echo "CertVault is geïnstalleerd in container: $CONTAINER_ID"
echo "Je kunt de applicatie bereiken op: http://<container-ip>:5000"
echo ""
echo "Container informatie:"
echo "- ID: $CONTAINER_ID"
echo "- Naam: $CONTAINER_NAME"
echo "- Gebruiker: root"
echo "- Wachtwoord: $CONTAINER_PASSWORD"
echo ""
echo "IP-adres van de container ophalen:"
echo "pct exec $CONTAINER_ID -- ip addr show eth0"
echo ""
echo "Service status controleren:"
echo "pct exec $CONTAINER_ID -- systemctl status certvault" 