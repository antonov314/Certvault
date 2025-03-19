from flask import Flask, render_template, request, send_file, redirect, url_for, session, send_from_directory, jsonify, flash
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
import datetime
import os
import json
import zipfile
import tempfile
import secrets
import string
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Voor session management

# Template filter voor datum formatting
@app.template_filter('strftime')
def _jinja2_filter_strftime(date_str, fmt=None):
    if fmt is None:
        return time.strftime(date_str)
    return time.strftime(fmt, time.localtime())

# Configuratie
CERT_DIR = 'certificates'
DOMAINS_FILE = 'domains.json'

# Zorg ervoor dat de benodigde directories bestaan
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(os.path.join(CERT_DIR, 'root'), exist_ok=True)
os.makedirs(os.path.join(CERT_DIR, 'intermediate'), exist_ok=True)
os.makedirs(os.path.join(CERT_DIR, 'web'), exist_ok=True)

def load_domains():
    if os.path.exists(DOMAINS_FILE):
        with open(DOMAINS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_domains(domains):
    with open(DOMAINS_FILE, 'w') as f:
        json.dump(domains, f, indent=4)

def get_domain_path(domain):
    return os.path.join(CERT_DIR, domain)

def create_domain_directories(domain):
    domain_path = get_domain_path(domain)
    os.makedirs(os.path.join(domain_path, 'root'), exist_ok=True)
    os.makedirs(os.path.join(domain_path, 'intermediate'), exist_ok=True)
    os.makedirs(os.path.join(domain_path, 'web'), exist_ok=True)

def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

def save_certificate_and_key(cert, private_key, cert_path, key_path):
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def create_certificate_formats(cert, private_key, password, friendly_name):
    """Genereer verschillende certificaat formaten."""
    # Maak een tijdelijke directory voor de formaten
    temp_dir = tempfile.mkdtemp()
    base_path = os.path.join(temp_dir, friendly_name)
    
    # PEM formaat (standaard)
    pem_path = f"{base_path}.pem"
    with open(pem_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # DER formaat
    der_path = f"{base_path}.der"
    with open(der_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))
    
    # CRT formaat (zelfde als PEM)
    crt_path = f"{base_path}.crt"
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Private key in PEM formaat
    key_path = f"{base_path}.key"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # PKCS12/PFX formaat
    p12_path = f"{base_path}.p12"
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))
    else:
        encryption = serialization.NoEncryption()
        
    pkcs12_data = pkcs12.serialize_key_and_certificates(
        friendly_name.encode('utf-8'),
        private_key,
        cert,
        None,  # geen CA certificaten
        encryption
    )
    with open(p12_path, "wb") as f:
        f.write(pkcs12_data)
    
    # PFX (zelfde als P12)
    pfx_path = f"{base_path}.pfx"
    with open(pfx_path, "wb") as f:
        f.write(pkcs12_data)
    
    return {
        'pem_path': pem_path,
        'der_path': der_path,
        'crt_path': crt_path,
        'key_path': key_path,
        'p12_path': p12_path,
        'pfx_path': pfx_path,
        'password': password
    }

def create_certificate_chain(web_cert_path, intermediate_cert_path, root_cert_path, chain_path):
    """Maak een gecombineerd certificaatbestand met de volledige keten."""
    with open(web_cert_path, 'rb') as f:
        web_cert = f.read()
    with open(intermediate_cert_path, 'rb') as f:
        intermediate_cert = f.read()
    with open(root_cert_path, 'rb') as f:
        root_cert = f.read()
    
    # Combineer de certificaten in de juiste volgorde: web -> intermediate -> root
    with open(chain_path, 'wb') as f:
        f.write(web_cert)
        f.write(intermediate_cert)
        f.write(root_cert)

def create_certificate_bundle(web_cert_path, intermediate_cert_path, root_cert_path, domain):
    """Maak een ZIP bundle met alleen de certificaten."""
    # Maak een tijdelijke directory voor de bundle
    temp_dir = tempfile.mkdtemp()
    bundle_path = os.path.join(temp_dir, f"{domain}_certificates.zip")
    
    with zipfile.ZipFile(bundle_path, 'w') as zipf:
        # Voeg certificaten toe met duidelijke namen
        zipf.write(root_cert_path, 'root-ca.cer')
        zipf.write(intermediate_cert_path, 'intermediate-ca.cer')
        zipf.write(web_cert_path, 'web-cert.cer')
    
    return bundle_path

def generate_secure_password(length=16):
    """Genereer een veilig wachtwoord."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

@app.route('/')
def index():
    domains = load_domains()
    return render_template('index.html', domains=domains)

@app.route('/add_domain', methods=['POST'])
def add_domain():
    domain = request.form.get('domain')
    if not domain:
        flash('Domeinnaam is verplicht', 'error')
        return redirect(url_for('index'))
    
    domains = load_domains()
    if domain in domains:
        flash('Dit domein bestaat al', 'error')
        return redirect(url_for('index'))
    
    domains.append(domain)
    save_domains(domains)
    create_domain_directories(domain)
    
    flash('Domein succesvol toegevoegd', 'success')
    return redirect(url_for('index'))

@app.route('/domain/<domain>')
def domain_certificates(domain):
    domains = load_domains()
    if domain not in domains:
        flash('Domein niet gevonden.', 'error')
        return redirect(url_for('index'))
    
    # Controleer status van Root CA en Intermediate certificaten
    domain_path = get_domain_path(domain)
    root_cert_path = os.path.join(domain_path, 'root', 'root.crt')
    intermediate_cert_path = os.path.join(domain_path, 'intermediate', 'intermediate.crt')
    
    root_ca_status = {
        'exists': os.path.exists(root_cert_path),
        'path': root_cert_path
    }
    
    intermediate_status = {
        'exists': os.path.exists(intermediate_cert_path),
        'path': intermediate_cert_path
    }
    
    # Haal web certificaten op
    web_certs = []
    web_dir = os.path.join(domain_path, 'web')
    if os.path.exists(web_dir):
        for cert_file in os.listdir(web_dir):
            if cert_file.endswith('.crt'):
                cert_path = os.path.join(web_dir, cert_file)
                with open(cert_path, 'rb') as f:
                    cert_data = f.read()
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    web_certs.append({
                        'domain': cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                        'created_at': cert.not_valid_before.strftime('%Y-%m-%d'),
                        'expires_at': cert.not_valid_after.strftime('%Y-%m-%d'),
                        'cert_path': cert_path
                    })
    
    return render_template('domain_certificates.html', 
                         domain=domain, 
                         web_certs=web_certs,
                         root_ca_status=root_ca_status,
                         intermediate_status=intermediate_status)

@app.route('/create_root_ca/<domain>', methods=['GET', 'POST'])
def create_root_ca(domain):
    if request.method == 'POST':
        try:
            # Genereer private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            
            # Genereer public key
            public_key = private_key.public_key()
            
            # Genereer subject
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, request.form['common_name']),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, request.form['organization']),
                x509.NameAttribute(NameOID.COUNTRY_NAME, request.form['country']),
            ])
            
            # Genereer certificaat
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
                critical=False,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Sla certificaat en private key op
            domain_path = get_domain_path(domain)
            cert_path = os.path.join(domain_path, 'root', 'root.crt')
            key_path = os.path.join(domain_path, 'root', 'root.key')
            
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            return redirect(url_for('domain_certificates', domain=domain))
            
        except Exception as e:
            return f"Fout bij het genereren van het Root CA certificaat: {str(e)}", 500
    
    return render_template('create_root_ca.html', domain=domain)

@app.route('/create_intermediate/<domain>', methods=['GET', 'POST'])
def create_intermediate(domain):
    if request.method == 'POST':
        try:
            # Laad Root CA certificaat en private key
            domain_path = get_domain_path(domain)
            root_cert_path = os.path.join(domain_path, 'root', 'root.crt')
            root_key_path = os.path.join(domain_path, 'root', 'root.key')
            
            with open(root_cert_path, 'rb') as f:
                root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            with open(root_key_path, 'rb') as f:
                root_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            
            # Genereer private key voor Intermediate
            intermediate_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            
            # Genereer public key
            intermediate_public_key = intermediate_key.public_key()
            
            # Genereer subject
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, request.form['common_name']),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, request.form['organization']),
                x509.NameAttribute(NameOID.COUNTRY_NAME, request.form['country']),
            ])
            
            # Genereer certificaat
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                root_cert.subject
            ).public_key(
                intermediate_public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=1825)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(intermediate_public_key),
                critical=False,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),
                critical=False,
            ).sign(root_key, hashes.SHA256(), default_backend())
            
            # Sla certificaat en private key op
            cert_path = os.path.join(domain_path, 'intermediate', 'intermediate.crt')
            key_path = os.path.join(domain_path, 'intermediate', 'intermediate.key')
            
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(key_path, 'wb') as f:
                f.write(intermediate_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            return redirect(url_for('domain_certificates', domain=domain))
            
        except Exception as e:
            return f"Fout bij het genereren van het Intermediate certificaat: {str(e)}", 500
    
    return render_template('create_intermediate.html', domain=domain)

@app.route('/generate_web_cert/<domain>', methods=['GET', 'POST'])
def generate_web_cert(domain):
    if request.method == 'POST':
        try:
            # Laad Intermediate certificaat en private key
            domain_path = get_domain_path(domain)
            intermediate_cert_path = os.path.join(domain_path, 'intermediate', 'intermediate.crt')
            intermediate_key_path = os.path.join(domain_path, 'intermediate', 'intermediate.key')
            root_cert_path = os.path.join(domain_path, 'root', 'root.crt')
            
            with open(intermediate_cert_path, 'rb') as f:
                intermediate_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            with open(intermediate_key_path, 'rb') as f:
                intermediate_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            
            # Genereer private key voor web certificaat
            web_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            
            # Genereer public key
            web_public_key = web_key.public_key()
            
            # Genereer subject
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, request.form['domain']),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, request.form['organization']),
                x509.NameAttribute(NameOID.COUNTRY_NAME, request.form['country']),
            ])
            
            # Genereer certificaat
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                intermediate_cert.subject
            ).public_key(
                web_public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(request.form['domain']),
                ]),
                critical=False,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(web_public_key),
                critical=False,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_cert.public_key()),
                critical=False,
            ).sign(intermediate_key, hashes.SHA256(), default_backend())
            
            # Sla certificaat en private key op
            cert_path = os.path.join(domain_path, 'web', f"{request.form['domain']}.crt")
            key_path = os.path.join(domain_path, 'web', f"{request.form['domain']}.key")
            
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(key_path, 'wb') as f:
                f.write(web_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Genereer verschillende formaten
            password = request.form.get('password') or generate_secure_password()
            formats = create_certificate_formats(cert, web_key, password, request.form['domain'])
            
            # Maak certificaat bundle
            bundle_path = create_certificate_bundle(
                cert_path,
                intermediate_cert_path,
                root_cert_path,
                request.form['domain']
            )
            
            return render_template('success.html',
                                 domain=request.form['domain'],
                                 cert_path=cert_path,
                                 key_path=key_path,
                                 pem_path=formats['pem_path'],
                                 der_path=formats['der_path'],
                                 p12_path=formats['p12_path'],
                                 bundle_path=bundle_path,
                                 password=formats['password'])
            
        except Exception as e:
            return f"Fout bij het genereren van het web certificaat: {str(e)}", 500
    
    return render_template('generate_web_cert.html', domain=domain)

@app.route('/generate_password')
def generate_password():
    """Genereer een nieuw wachtwoord."""
    return jsonify({'password': generate_secure_password()})

@app.route('/download/<path:filename>')
def download_file(filename):
    """Download een bestand uit de certificates directory."""
    return send_from_directory('certificates', filename, as_attachment=True)

@app.route('/delete_cert/<domain>/<cert_name>', methods=['POST'])
def delete_cert(domain, cert_name):
    try:
        # Controleer of het domein bestaat
        domains = load_domains()
        if domain not in domains:
            flash('Domein niet gevonden.', 'error')
            return redirect(url_for('index'))
        
        # Verwijder het certificaat en de bijbehorende bestanden
        cert_path = os.path.join(get_domain_path(domain), 'web', f"{cert_name}.crt")
        key_path = os.path.join(get_domain_path(domain), 'web', f"{cert_name}.key")
        
        if os.path.exists(cert_path):
            os.remove(cert_path)
        if os.path.exists(key_path):
            os.remove(key_path)
            
        flash('Certificaat succesvol verwijderd.', 'success')
    except Exception as e:
        flash(f'Fout bij het verwijderen van het certificaat: {str(e)}', 'error')
    
    return redirect(url_for('domain_certificates', domain=domain))

@app.route('/view_cert/<domain>/<cert_name>')
def view_cert(domain, cert_name):
    try:
        # Controleer of het domein bestaat
        domains = load_domains()
        if domain not in domains:
            flash('Domein niet gevonden.', 'error')
            return redirect(url_for('index'))
        
        # Haal certificaat informatie op
        domain_path = get_domain_path(domain)
        cert_path = os.path.join(domain_path, 'web', f"{cert_name}.crt")
        key_path = os.path.join(domain_path, 'web', f"{cert_name}.key")
        
        if not os.path.exists(cert_path):
            flash('Certificaat niet gevonden.', 'error')
            return redirect(url_for('domain_certificates', domain=domain))
        
        # Genereer verschillende formaten
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        with open(key_path, 'rb') as f:
            key_data = f.read()
            private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
        
        # Genereer een nieuw wachtwoord voor PKCS12
        password = generate_secure_password()
        formats = create_certificate_formats(cert, private_key, password, cert_name)
        
        # Maak certificaat bundle
        root_cert_path = os.path.join(domain_path, 'root', 'root.crt')
        intermediate_cert_path = os.path.join(domain_path, 'intermediate', 'intermediate.crt')
        bundle_path = create_certificate_bundle(cert_path, intermediate_cert_path, root_cert_path, cert_name)
        
        return render_template('success.html',
                             domain=domain,
                             cert_path=cert_path,
                             key_path=key_path,
                             pem_path=formats['pem_path'],
                             der_path=formats['der_path'],
                             p12_path=formats['p12_path'],
                             bundle_path=bundle_path,
                             password=formats['password'])
    
    except Exception as e:
        flash(f'Fout bij het ophalen van certificaat details: {str(e)}', 'error')
        return redirect(url_for('domain_certificates', domain=domain))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 