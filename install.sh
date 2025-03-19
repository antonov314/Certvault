#!/bin/bash

echo "CertVault v2.1 - Self Signed SSL Certificaat Generator"
echo "Installatie script"
echo "----------------------------------------"

# Controleer of Python 3.10 of hoger is geïnstalleerd
if command -v python3 >/dev/null 2>&1; then
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if (( $(echo "$python_version >= 3.10" | bc -l) )); then
        echo "✓ Python $python_version gevonden"
    else
        echo "✗ Python 3.10 of hoger is vereist (gevonden: $python_version)"
        exit 1
    fi
else
    echo "✗ Python 3 niet gevonden"
    exit 1
fi

# Maak een virtual environment
echo "Virtual environment aanmaken..."
python3 -m venv venv
source venv/bin/activate

# Installeer dependencies
echo "Dependencies installeren..."
pip install --upgrade pip
pip install -r requirements.txt

# Maak certificaat directory
echo "Certificaat directory aanmaken..."
mkdir -p certificates

# Geef uitvoerrechten aan de applicatie
chmod +x app.py

echo "----------------------------------------"
echo "Installatie voltooid!"
echo ""
echo "Start de applicatie met:"
echo "source venv/bin/activate"
echo "python app.py"
echo ""
echo "Open daarna een browser en ga naar:"
echo "http://localhost:5000" 