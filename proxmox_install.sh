#!/bin/bash

# Proxmox LXC Container Setup & CertVault Installer
# v1.2

# Kleuren voor output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}CertVault - Proxmox LXC Container Installer${NC}"
echo "----------------------------------------"

# Check of we root zijn
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Dit script moet als root worden uitgevoerd${NC}"
    exit 1
fi

# Check of pct (Proxmox Container Tools) beschikbaar is
if ! command -v pct &> /dev/null; then
    echo -e "${RED}Proxmox Container Tools (pct) niet gevonden. Is dit een Proxmox server?${NC}"
    exit 1
fi

# Functie om input te valideren
validate_input() {
    local input=$1
    local default=$2
    if [ -z "$input" ]; then
        echo "$default"
    else
        echo "$input"
    fi
}

# Functie om beschikbare storage te detecteren
get_available_storage() {
    echo -e "\n${YELLOW}Beschikbare Storage Locaties:${NC}"
    # Haal storage informatie op
    pvesm status | tail -n +2 | while read -r line; do
        storage=$(echo "$line" | awk '{print $1}')
        type=$(echo "$line" | awk '{print $2}')
        available=$(echo "$line" | awk '{print $5}')
        echo "$storage ($type, $available beschikbaar)"
    done
}

# Functie om beschikbare CT templates te detecteren
get_available_templates() {
    echo -e "\n${YELLOW}Beschikbare CT Templates:${NC}"
    local count=1
    # Array om templates op te slaan
    declare -a templates
    
    # Zoek templates in verschillende locaties
    while IFS= read -r template; do
        templates+=("$template")
        echo "$count) $template"
        ((count++))
    done < <(pveam list local | grep -E "ubuntu-22.04|ubuntu-20.04|debian-11|debian-12" | awk '{print $1}')
    
    # Vraag gebruiker om keuze
    read -p "Kies een template nummer [1]: " template_choice
    template_choice=${template_choice:-1}
    
    # Valideer en return gekozen template
    if [ "$template_choice" -ge 1 ] && [ "$template_choice" -le ${#templates[@]} ]; then
        echo "local:vztmpl/${templates[$((template_choice-1))]}"
    else
        echo "local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.gz"
    fi
}

# Configuratie variabelen via gebruikersinvoer
echo -e "${YELLOW}Container Configuratie${NC}"
echo "----------------------------------------"

# Container ID
read -p "Container ID [999]: " input_id
CONTAINER_ID=$(validate_input "$input_id" "999")

# Container Naam
read -p "Container Naam [certvault]: " input_name
CONTAINER_NAME=$(validate_input "$input_name" "certvault")

# Container Wachtwoord
read -p "Container Wachtwoord [CertVault@2024]: " input_password
CONTAINER_PASSWORD=$(validate_input "$input_password" "CertVault@2024")

# Container Hostname
read -p "Container Hostname [$CONTAINER_NAME]: " input_hostname
CONTAINER_HOSTNAME=$(validate_input "$input_hostname" "$CONTAINER_NAME")

# IP Configuratie
echo -e "\n${YELLOW}Netwerk Configuratie${NC}"
echo "1) DHCP"
echo "2) Statisch IP"
read -p "Kies netwerk configuratie [1]: " network_choice

if [ "$network_choice" = "2" ]; then
    read -p "IP Adres (bijv. 192.168.1.100/24): " static_ip
    read -p "Gateway (bijv. 192.168.1.1): " gateway
    CONTAINER_IP="$static_ip,gw=$gateway"
else
    CONTAINER_IP="dhcp"
fi

# Hardware Resources
echo -e "\n${YELLOW}Hardware Resources${NC}"
read -p "RAM in MB [1024]: " input_memory
CONTAINER_MEMORY=$(validate_input "$input_memory" "1024")

read -p "SWAP in MB [512]: " input_swap
CONTAINER_SWAP=$(validate_input "$input_swap" "512")

read -p "CPU Cores [2]: " input_cores
CONTAINER_CORES=$(validate_input "$input_cores" "2")

# Storage Configuratie
echo -e "\n${YELLOW}Storage Configuratie${NC}"
get_available_storage
read -p "Voer de naam van de gewenste storage in [local-lvm]: " input_storage
CONTAINER_STORAGE=$(validate_input "$input_storage" "local-lvm")

# Template Configuratie
echo -e "\n${YELLOW}Template Configuratie${NC}"
CONTAINER_TEMPLATE=$(get_available_templates)
echo -e "${BLUE}Geselecteerde template: ${NC}${CONTAINER_TEMPLATE}"

# Configuratie overzicht
echo -e "\n${GREEN}Configuratie Overzicht${NC}"
echo "----------------------------------------"
echo "Container ID: $CONTAINER_ID"
echo "Naam: $CONTAINER_NAME"
echo "Hostname: $CONTAINER_HOSTNAME"
echo "IP Configuratie: $CONTAINER_IP"
echo "RAM: ${CONTAINER_MEMORY}MB"
echo "SWAP: ${CONTAINER_SWAP}MB"
echo "CPU Cores: $CONTAINER_CORES"
echo "Storage: $CONTAINER_STORAGE"
echo "Template: $CONTAINER_TEMPLATE"
echo "----------------------------------------"

# Bevestiging vragen
read -p "Wil je doorgaan met de installatie? (j/n) [j]: " confirm
if [ "$confirm" = "n" ]; then
    echo -e "${RED}Installatie geannuleerd${NC}"
    exit 0
fi

echo -e "\n${GREEN}1. LXC Container aanmaken...${NC}"
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

echo -e "\n${GREEN}2. Container starten...${NC}"
pct start $CONTAINER_ID

# Wacht tot container volledig is opgestart
echo "Wachten tot container is opgestart..."
sleep 10

echo -e "\n${GREEN}3. Basis packages installeren...${NC}"
pct exec $CONTAINER_ID -- bash -c "apt update && apt upgrade -y"
pct exec $CONTAINER_ID -- bash -c "apt install -y python3 python3-pip python3-venv git bc"

echo -e "\n${GREEN}4. CertVault applicatie downloaden...${NC}"
pct exec $CONTAINER_ID -- bash -c "cd /opt && git clone https://github.com/antonov314/Certvault.git"

echo -e "\n${GREEN}5. CertVault installeren...${NC}"
pct exec $CONTAINER_ID -- bash -c "cd /opt/Certvault && chmod +x install.sh && ./install.sh"

echo -e "\n${GREEN}6. Systemd service aanmaken...${NC}"
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

echo -e "\n${GREEN}----------------------------------------${NC}"
echo -e "${GREEN}Installatie voltooid!${NC}"
echo -e "CertVault is geïnstalleerd in container: ${YELLOW}$CONTAINER_ID${NC}"

if [ "$CONTAINER_IP" = "dhcp" ]; then
    echo -e "\nIP-adres van de container ophalen:"
    pct exec $CONTAINER_ID -- ip addr show eth0 | grep "inet "
else
    echo -e "\nJe kunt de applicatie bereiken op: ${YELLOW}http://${static_ip%/*}:5000${NC}"
fi

echo -e "\n${YELLOW}Container informatie:${NC}"
echo "- ID: $CONTAINER_ID"
echo "- Naam: $CONTAINER_NAME"
echo "- Gebruiker: root"
echo "- Wachtwoord: $CONTAINER_PASSWORD"

echo -e "\n${YELLOW}Service status:${NC}"
pct exec $CONTAINER_ID -- systemctl status certvault 