# CertVault v2.1

Een gebruiksvriendelijke Self Signed SSL certificaat generator met multi-domein ondersteuning.

## Features

### Nieuwe features in v2.1
- Verbeterd installatie script met Python versie controle
- Automatische virtual environment setup
- Duidelijkere installatie instructies
- Aangepaste naam naar "Self Signed SSL Certificaat Generator"

### Core Features
- Genereer complete Self Signed SSL certificaat hiërarchie
- Root CA certificaten (10 jaar geldig)
- Intermediate CA certificaten (5 jaar geldig)
- Web certificaten (1 jaar geldig)
- Verschillende download formaten (PEM, DER, CRT, P12/PFX)
- Automatische certificaat bundel creatie
- Veilige wachtwoord generatie voor PKCS12/PFX
- Gebruiksvriendelijke web interface

## Systeem Vereisten

- Python 3.10 of hoger
- Flask web framework
- Cryptography bibliotheek
- Bootstrap 5.3
- Font Awesome 6.0

## Installatie

1. Clone de repository:
```bash
git clone https://github.com/yourusername/certvault.git
cd certvault
```

2. Voer het installatie script uit:
```bash
chmod +x install.sh
./install.sh
```

3. Start de applicatie:
```bash
source venv/bin/activate
python app.py
```

4. Open een browser en ga naar:
```
http://localhost:5000
```

## Gebruik

1. Voeg een nieuw domein toe via de hoofdpagina
2. Genereer een Root CA certificaat voor het domein
3. Genereer een Intermediate certificaat
4. Genereer web certificaten naar behoefte
5. Download de certificaten in het gewenste formaat
6. Gebruik de Details knop om certificaat informatie terug te vinden

## Bestandsstructuur

```
certvault/
├── app.py                 # Hoofdapplicatie
├── requirements.txt       # Python dependencies
├── VERSION.txt           # Versie informatie
├── README.md             # Deze documentatie
├── install.sh            # Installatie script
├── certificates/         # Gegenereerde certificaten
│   └── [domein]/
│       ├── root/        # Root CA certificaten
│       ├── intermediate/ # Intermediate certificaten
│       └── web/         # Web certificaten
└── templates/           # HTML templates
    ├── base.html        # Basis template
    ├── index.html       # Hoofdpagina
    ├── domain_certificates.html
    ├── create_root_ca.html
    ├── create_intermediate.html
    ├── generate_web_cert.html
    └── success.html
```

## Beveiliging

- Alle private keys worden veilig opgeslagen
- Wachtwoorden worden veilig gegenereerd
- Certificaten worden per domein gescheiden opgeslagen
- Bevestiging vereist voor verwijderen van certificaten

## Licentie

Dit project is gelicentieerd onder de MIT-licentie.

## Credits

Ontwikkeld door Lars Schretlen 