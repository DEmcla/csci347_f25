# Week 3 Tutorial: PKI and X.509 Certificate Management

**Estimated Time**: 4.5-5 hours  
**Prerequisites**: Week 2 completed, understanding of digital signatures and public key cryptography

## 🎯 Tutorial Goals

By the end of this tutorial, you will have:
1. **Part 1** (45 min): Created and analyzed X.509 certificates
2. **Part 2** (60 min): Built a complete Certificate Authority infrastructure  
3. **Part 3** (45 min): Generated Certificate Signing Requests and issued certificates
4. **Part 4** (90 min): Implemented TLS/SSL with proper certificate validation
5. **Part 5** (45 min): Managed certificate lifecycle and revocation

### 📊 Progress Tracking
Complete each module and run its checkpoint before proceeding:
- [ ] Part 1: X.509 Certificate Structure ✅ Checkpoint 1
- [ ] Part 2: Certificate Authority Setup ✅ Checkpoint 2
- [ ] Part 3: Certificate Signing Requests ✅ Checkpoint 3
- [ ] Part 4: TLS/SSL Implementation ✅ Checkpoint 4
- [ ] Part 5: Certificate Lifecycle Management ✅ Checkpoint 5

## 🔧 Setup Check

Before we begin, verify your environment:

```bash
# Check Python version
python --version  # Should be 3.11+

# Check cryptography library
python -c "from cryptography import x509; print('✅ X.509 support ready')"

# Create working directory
mkdir week3-pki
cd week3-pki
```

---

## 📘 Part 1: X.509 Certificate Structure (45 minutes)

**Learning Objective**: Understand certificate format and create basic certificates

**What you'll build**: Certificate generator and parser

### Step 1: Understanding Certificate Structure

Create `certificate_basics.py`:

```python
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import ipaddress

class CertificateManager:
    """X.509 certificate creation and analysis"""
    
    def __init__(self):
        self.certificates = {}
        self.private_keys = {}
    
    def create_self_signed_certificate(self, common_name, country="US", 
                                     organization="Test Corp", days_valid=365):
        """
        Create a self-signed certificate
        
        Args:
            common_name (str): Certificate subject name
            country (str): Country code
            organization (str): Organization name
            days_valid (int): Certificate validity period
            
        Returns:
            tuple: (certificate, private_key)
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Certificate subject (who the certificate is for)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # For self-signed certificates, issuer = subject
        issuer = subject
        
        # Create certificate
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(private_key, hashes.SHA256())
        
        return certificate, private_key
    
    def parse_certificate(self, certificate):
        """Parse certificate and extract key information"""
        info = {
            'version': certificate.version.name,
            'serial_number': str(certificate.serial_number),
            'subject': certificate.subject.rfc4514_string(),
            'issuer': certificate.issuer.rfc4514_string(),
            'not_valid_before': certificate.not_valid_before,
            'not_valid_after': certificate.not_valid_after,
            'signature_algorithm': certificate.signature_algorithm_oid._name,
            'public_key_size': certificate.public_key().key_size,
            'extensions': {}
        }
        
        # Parse extensions
        for extension in certificate.extensions:
            ext_name = extension.oid._name
            if ext_name == 'basicConstraints':
                info['extensions']['basic_constraints'] = {
                    'ca': extension.value.ca,
                    'path_length': extension.value.path_length
                }
            elif ext_name == 'keyUsage':
                ku = extension.value
                info['extensions']['key_usage'] = {
                    'digital_signature': ku.digital_signature,
                    'key_cert_sign': ku.key_cert_sign,
                    'crl_sign': ku.crl_sign
                }
            elif ext_name == 'subjectAlternativeName':
                sans = []
                for name in extension.value:
                    if isinstance(name, x509.DNSName):
                        sans.append(f"DNS:{name.value}")
                    elif isinstance(name, x509.IPAddress):
                        sans.append(f"IP:{name.value}")
                info['extensions']['subject_alternative_name'] = sans
        
        return info
    
    def save_certificate_pem(self, certificate, filename):
        """Save certificate in PEM format"""
        pem_data = certificate.public_bytes(serialization.Encoding.PEM)
        with open(filename, 'wb') as f:
            f.write(pem_data)
        return filename
    
    def save_private_key_pem(self, private_key, filename, password=None):
        """Save private key in PEM format"""
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()
            
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        with open(filename, 'wb') as f:
            f.write(pem_data)
        return filename
    
    def load_certificate_pem(self, filename):
        """Load certificate from PEM file"""
        with open(filename, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read())
    
    def verify_certificate_signature(self, certificate, issuer_public_key):
        """Verify certificate signature"""
        try:
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                certificate.signature_algorithm_oid._name
            )
            return True
        except Exception as e:
            return False

def demo_certificate_basics():
    """Demonstrate basic certificate operations"""
    print("🏆 X.509 Certificate Basics Demo")
    print("="*50)
    
    cm = CertificateManager()
    
    # Create a self-signed certificate
    print("📝 Creating self-signed certificate...")
    cert, private_key = cm.create_self_signed_certificate(
        common_name="test.example.com",
        organization="CSCI347 Test Lab"
    )
    
    print("✅ Certificate created successfully!")
    
    # Parse and display certificate information
    print("\n🔍 Certificate Analysis:")
    cert_info = cm.parse_certificate(cert)
    
    print(f"   Subject: {cert_info['subject']}")
    print(f"   Issuer: {cert_info['issuer']}")
    print(f"   Serial: {cert_info['serial_number']}")
    print(f"   Valid from: {cert_info['not_valid_before']}")
    print(f"   Valid until: {cert_info['not_valid_after']}")
    print(f"   Signature algorithm: {cert_info['signature_algorithm']}")
    print(f"   Public key size: {cert_info['public_key_size']} bits")
    
    # Display extensions
    print(f"\n🔧 Certificate Extensions:")
    for ext_name, ext_value in cert_info['extensions'].items():
        print(f"   {ext_name}: {ext_value}")
    
    # Save certificate and key
    print(f"\n💾 Saving certificate files...")
    cert_file = cm.save_certificate_pem(cert, "test_certificate.pem")
    key_file = cm.save_private_key_pem(private_key, "test_private_key.pem")
    
    print(f"   Certificate: {cert_file}")
    print(f"   Private key: {key_file}")
    
    # Test loading
    print(f"\n📖 Testing certificate loading...")
    loaded_cert = cm.load_certificate_pem(cert_file)
    
    # Verify they match
    original_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    loaded_fingerprint = loaded_cert.fingerprint(hashes.SHA256()).hex()
    
    print(f"   Original fingerprint: {original_fingerprint[:32]}...")
    print(f"   Loaded fingerprint:   {loaded_fingerprint[:32]}...")
    print(f"   Match: {original_fingerprint == loaded_fingerprint}")
    
    # Verify self-signed signature
    print(f"\n✍️  Signature verification:")
    is_valid = cm.verify_certificate_signature(cert, cert.public_key())
    print(f"   Self-signed signature valid: {is_valid}")

if __name__ == "__main__":
    demo_certificate_basics()
```

**Run it:**
```bash
python certificate_basics.py
```

### Step 2: Certificate Validation

Add this to understand certificate validation:

```python
def demo_certificate_validation():
    """Demonstrate certificate validation process"""
    print(f"\n🔒 Certificate Validation Demo")
    print("="*50)
    
    cm = CertificateManager()
    
    # Create a valid certificate
    valid_cert, valid_key = cm.create_self_signed_certificate("valid.test.com")
    
    # Create certificate with future date (not yet valid)
    future_cert, _ = cm.create_self_signed_certificate(
        "future.test.com", 
        organization="Future Corp"
    )
    
    # Manually adjust the certificate to be future-dated
    print("📅 Testing certificate time validity...")
    
    now = datetime.datetime.utcnow()
    
    # Check valid certificate
    is_time_valid = (valid_cert.not_valid_before <= now <= valid_cert.not_valid_after)
    print(f"   Valid certificate time check: {'✅ Valid' if is_time_valid else '❌ Invalid'}")
    
    # Create expired certificate by adjusting dates
    print(f"\n⏰ Simulating expired certificate...")
    print("   (In real scenario, wait for expiration or use past dates)")
    
    # Show certificate chain validation concepts
    print(f"\n🔗 Certificate Chain Validation Concepts:")
    print("   1. Time validity: Check not_before <= now <= not_after")
    print("   2. Signature validity: Verify with issuer's public key") 
    print("   3. Chain of trust: Follow issuer chain to trusted root")
    print("   4. Revocation status: Check CRL or OCSP")
    print("   5. Name validation: Match certificate name to expected name")
    
    # Demonstrate name validation
    print(f"\n📋 Name Validation Examples:")
    test_names = [
        ("valid.test.com", "valid.test.com", True),
        ("valid.test.com", "invalid.test.com", False),
        ("*.example.com", "sub.example.com", True),  # Wildcard
        ("*.example.com", "deep.sub.example.com", False),  # Too deep
    ]
    
    for cert_name, requested_name, expected in test_names:
        # Simple name matching logic (real implementation is more complex)
        if cert_name.startswith("*."):
            # Wildcard matching
            domain = cert_name[2:]
            matches = requested_name.endswith(domain) and requested_name.count('.') == domain.count('.') + 1
        else:
            # Exact matching
            matches = cert_name == requested_name
            
        result = "✅ Match" if matches else "❌ No match"
        expected_result = "✅ Expected" if expected else "❌ Expected"
        status = "✅" if (matches == expected) else "⚠️"
        
        print(f"   {status} '{cert_name}' vs '{requested_name}': {result} ({expected_result})")

def demo_certificate_extensions():
    """Demonstrate important certificate extensions"""
    print(f"\n🔧 Certificate Extensions Demo")
    print("="*50)
    
    # Generate private key for server certificate
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create server certificate with comprehensive extensions
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSCI347 Labs"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT Department"),
        x509.NameAttribute(NameOID.COMMON_NAME, "www.csci347lab.com"),
    ])
    
    # Build certificate with multiple extensions
    server_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject  # Self-signed for demo
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=90)
    ).add_extension(
        # Subject Alternative Names - critical for modern browsers
        x509.SubjectAlternativeName([
            x509.DNSName("www.csci347lab.com"),
            x509.DNSName("csci347lab.com"),
            x509.DNSName("api.csci347lab.com"),
            x509.IPAddress(ipaddress.ip_address("192.168.1.100")),
        ]),
        critical=False,
    ).add_extension(
        # Basic Constraints - not a CA
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        # Key Usage - what the key can be used for
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_encipherment=True,  # For RSA key transport
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).add_extension(
        # Extended Key Usage - specific purposes
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,  # TLS server authentication
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,  # TLS client authentication
        ]),
        critical=True,
    ).sign(server_key, hashes.SHA256())
    
    # Analyze extensions
    print("📋 Server Certificate Extensions Analysis:")
    
    for extension in server_cert.extensions:
        print(f"\n   Extension: {extension.oid._name}")
        print(f"   Critical: {extension.critical}")
        
        if extension.oid._name == 'subjectAlternativeName':
            print("   SANs:")
            for san in extension.value:
                if isinstance(san, x509.DNSName):
                    print(f"     - DNS: {san.value}")
                elif isinstance(san, x509.IPAddress):
                    print(f"     - IP: {san.value}")
        
        elif extension.oid._name == 'keyUsage':
            ku = extension.value
            usages = []
            if ku.digital_signature: usages.append("digital_signature")
            if ku.key_encipherment: usages.append("key_encipherment")
            if ku.key_cert_sign: usages.append("key_cert_sign")
            print(f"   Key Usages: {', '.join(usages)}")
            
        elif extension.oid._name == 'extendedKeyUsage':
            eku_names = []
            for usage in extension.value:
                if usage == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                    eku_names.append("TLS Web Server Authentication")
                elif usage == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                    eku_names.append("TLS Web Client Authentication")
            print(f"   Extended Key Usages: {', '.join(eku_names)}")

# Add to main section
if __name__ == "__main__":
    demo_certificate_basics()
    demo_certificate_validation()
    demo_certificate_extensions()
```

### ✅ Checkpoint 1: Basic Certificate Operations

Verify your understanding:
1. Can you create a self-signed certificate?
2. Do you understand the difference between subject and issuer?
3. Can you explain what certificate extensions are for?

---

## 📘 Part 2: Certificate Authority Setup (60 minutes)

**Learning Objective**: Build a complete Certificate Authority infrastructure

**What you'll build**: Root CA and Intermediate CA with proper certificate chains

### Step 1: Root Certificate Authority

Create `certificate_authority.py`:

```python
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import os
from pathlib import Path
import json

class CertificateAuthority:
    """Complete Certificate Authority implementation"""
    
    def __init__(self, name, base_dir="pki"):
        self.name = name
        self.base_dir = Path(base_dir)
        self.ca_dir = self.base_dir / name
        
        # Create directory structure
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        (self.ca_dir / "certs").mkdir(exist_ok=True)
        (self.ca_dir / "private").mkdir(exist_ok=True)
        (self.ca_dir / "crl").mkdir(exist_ok=True)
        (self.ca_dir / "newcerts").mkdir(exist_ok=True)
        
        self.certificate = None
        self.private_key = None
        self.serial_number = 1
        
        # Initialize serial number tracking
        self.serial_file = self.ca_dir / "serial.txt"
        if self.serial_file.exists():
            with open(self.serial_file, 'r') as f:
                self.serial_number = int(f.read().strip())
        else:
            with open(self.serial_file, 'w') as f:
                f.write(str(self.serial_number))
    
    def create_root_ca(self, common_name, country="US", organization="CSCI347 CA", 
                      key_size=4096, validity_days=3650):
        """
        Create a root Certificate Authority
        
        Args:
            common_name (str): CA common name
            country (str): Country code
            organization (str): Organization name
            key_size (int): RSA key size (use 4096 for root CA)
            validity_days (int): Certificate validity in days
        """
        print(f"🏗️  Creating Root CA: {common_name}")
        
        # Generate strong private key for root CA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Create distinguished name for root CA
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # For root CA, subject = issuer (self-signed)
        issuer = subject
        
        # Create root certificate
        self.certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.private_key.public_key()
        ).serial_number(
            self._get_next_serial()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
        ).add_extension(
            # Root CA basic constraints
            x509.BasicConstraints(ca=True, path_length=1),  # Allow 1 level of intermediate CAs
            critical=True,
        ).add_extension(
            # Key usage for CA
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            # Subject Key Identifier
            x509.SubjectKeyIdentifier.from_public_key(self.private_key.public_key()),
            critical=False,
        ).sign(self.private_key, hashes.SHA256())
        
        # Save certificate and private key
        self._save_ca_certificate()
        self._save_ca_private_key()
        
        print(f"✅ Root CA created successfully")
        print(f"   Certificate: {self.ca_dir / 'certs' / 'ca-cert.pem'}")
        print(f"   Private key: {self.ca_dir / 'private' / 'ca-key.pem'}")
        
        return self.certificate, self.private_key
    
    def create_intermediate_ca(self, common_name, parent_ca, country="US", 
                             organization="CSCI347 Intermediate CA", validity_days=1825):
        """
        Create an intermediate Certificate Authority
        
        Args:
            common_name (str): Intermediate CA name
            parent_ca (CertificateAuthority): Parent CA that will sign this cert
            country (str): Country code
            organization (str): Organization name
            validity_days (int): Certificate validity in days
        """
        print(f"🔗 Creating Intermediate CA: {common_name}")
        
        # Generate private key for intermediate CA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048  # Smaller key for intermediate
        )
        
        # Create CSR for intermediate CA
        csr_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Intermediate Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Create and sign intermediate certificate
        self.certificate = x509.CertificateBuilder().subject_name(
            csr_subject
        ).issuer_name(
            parent_ca.certificate.subject  # Issued by parent CA
        ).public_key(
            self.private_key.public_key()
        ).serial_number(
            parent_ca._get_next_serial()  # Use parent's serial numbering
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
        ).add_extension(
            # Intermediate CA constraints
            x509.BasicConstraints(ca=True, path_length=0),  # Can't create more intermediates
            critical=True,
        ).add_extension(
            # Key usage for intermediate CA
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            # Subject Key Identifier
            x509.SubjectKeyIdentifier.from_public_key(self.private_key.public_key()),
            critical=False,
        ).add_extension(
            # Authority Key Identifier (links to parent)
            x509.AuthorityKeyIdentifier.from_issuer_public_key(parent_ca.certificate.public_key()),
            critical=False,
        ).sign(parent_ca.private_key, hashes.SHA256())  # Signed by parent CA
        
        # Save certificate and private key
        self._save_ca_certificate()
        self._save_ca_private_key()
        
        print(f"✅ Intermediate CA created successfully")
        print(f"   Signed by: {parent_ca.name}")
        
        return self.certificate, self.private_key
    
    def issue_server_certificate(self, common_name, san_list=None, validity_days=365):
        """
        Issue a server certificate
        
        Args:
            common_name (str): Server common name
            san_list (list): Subject Alternative Names
            validity_days (int): Certificate validity
            
        Returns:
            tuple: (certificate, private_key)
        """
        print(f"📜 Issuing server certificate for: {common_name}")
        
        # Generate private key for server
        server_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create server subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSCI347 Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Prepare SAN list
        if san_list is None:
            san_list = [common_name]
        
        sans = []
        for name in san_list:
            sans.append(x509.DNSName(name))
        
        # Create server certificate
        server_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.certificate.subject
        ).public_key(
            server_key.public_key()
        ).serial_number(
            self._get_next_serial()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
        ).add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.certificate.public_key()),
            critical=False,
        ).sign(self.private_key, hashes.SHA256())
        
        # Save server certificate
        cert_filename = f"server-{common_name.replace('.', '-')}.pem"
        key_filename = f"server-{common_name.replace('.', '-')}-key.pem"
        
        self._save_certificate(server_cert, self.ca_dir / "newcerts" / cert_filename)
        self._save_private_key(server_key, self.ca_dir / "private" / key_filename)
        
        print(f"✅ Server certificate issued")
        print(f"   Certificate: {self.ca_dir / 'newcerts' / cert_filename}")
        print(f"   Private key: {self.ca_dir / 'private' / key_filename}")
        
        return server_cert, server_key
    
    def _get_next_serial(self):
        """Get next serial number"""
        current = self.serial_number
        self.serial_number += 1
        
        # Update serial file
        with open(self.serial_file, 'w') as f:
            f.write(str(self.serial_number))
        
        return current
    
    def _save_ca_certificate(self):
        """Save CA certificate"""
        cert_path = self.ca_dir / "certs" / "ca-cert.pem"
        self._save_certificate(self.certificate, cert_path)
    
    def _save_ca_private_key(self):
        """Save CA private key"""
        key_path = self.ca_dir / "private" / "ca-key.pem"
        self._save_private_key(self.private_key, key_path)
    
    def _save_certificate(self, certificate, filepath):
        """Save certificate to file"""
        pem_data = certificate.public_bytes(serialization.Encoding.PEM)
        with open(filepath, 'wb') as f:
            f.write(pem_data)
    
    def _save_private_key(self, private_key, filepath):
        """Save private key to file"""
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(filepath, 'wb') as f:
            f.write(pem_data)

def demo_certificate_authority():
    """Demonstrate complete CA infrastructure"""
    print("🏛️  Certificate Authority Infrastructure Demo")
    print("="*60)
    
    # Create root CA
    print("\n📋 Step 1: Create Root Certificate Authority")
    root_ca = CertificateAuthority("root-ca")
    root_ca.create_root_ca(
        common_name="CSCI347 Root CA",
        organization="CSCI347 University",
        validity_days=7300  # 20 years for root CA
    )
    
    # Create intermediate CA
    print("\n📋 Step 2: Create Intermediate Certificate Authority")
    intermediate_ca = CertificateAuthority("intermediate-ca")
    intermediate_ca.create_intermediate_ca(
        common_name="CSCI347 Intermediate CA",
        parent_ca=root_ca,
        validity_days=3650  # 10 years for intermediate
    )
    
    # Issue server certificates
    print("\n📋 Step 3: Issue Server Certificates")
    
    # Web server certificate
    web_cert, web_key = intermediate_ca.issue_server_certificate(
        common_name="www.csci347lab.com",
        san_list=[
            "www.csci347lab.com",
            "csci347lab.com",
            "api.csci347lab.com"
        ],
        validity_days=365
    )
    
    # Mail server certificate
    mail_cert, mail_key = intermediate_ca.issue_server_certificate(
        common_name="mail.csci347lab.com",
        san_list=[
            "mail.csci347lab.com",
            "smtp.csci347lab.com",
            "imap.csci347lab.com"
        ],
        validity_days=365
    )
    
    # Display certificate chain
    print(f"\n🔗 Certificate Chain Analysis:")
    print(f"   Root CA: {root_ca.certificate.subject.rfc4514_string()}")
    print(f"   ├── Intermediate CA: {intermediate_ca.certificate.subject.rfc4514_string()}")
    print(f"       ├── Web Server: {web_cert.subject.rfc4514_string()}")
    print(f"       └── Mail Server: {mail_cert.subject.rfc4514_string()}")
    
    # Verify certificate chain
    print(f"\n✅ Certificate Chain Verification:")
    
    # Verify intermediate is signed by root
    try:
        root_ca.certificate.public_key().verify(
            intermediate_ca.certificate.signature,
            intermediate_ca.certificate.tbs_certificate_bytes,
            intermediate_ca.certificate.signature_hash_algorithm
        )
        print("   ✅ Intermediate CA signature valid (signed by Root CA)")
    except:
        print("   ❌ Intermediate CA signature invalid")
    
    # Verify web server is signed by intermediate
    try:
        intermediate_ca.certificate.public_key().verify(
            web_cert.signature,
            web_cert.tbs_certificate_bytes,
            web_cert.signature_hash_algorithm
        )
        print("   ✅ Web server signature valid (signed by Intermediate CA)")
    except:
        print("   ❌ Web server signature invalid")
    
    return root_ca, intermediate_ca

if __name__ == "__main__":
    demo_certificate_authority()
```

### Step 2: Certificate Chain Creation

Add this function to create and validate certificate chains:

```python
def create_certificate_chain_file():
    """Create certificate chain bundle file"""
    print(f"\n📦 Creating Certificate Chain Bundle")
    print("="*50)
    
    # Load certificates from our CA demo
    root_ca = CertificateAuthority("root-ca")
    intermediate_ca = CertificateAuthority("intermediate-ca")
    
    try:
        # Load existing certificates
        with open("pki/root-ca/certs/ca-cert.pem", 'rb') as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
        
        with open("pki/intermediate-ca/certs/ca-cert.pem", 'rb') as f:
            intermediate_cert = x509.load_pem_x509_certificate(f.read())
        
        # Create certificate chain (server cert + intermediate + root)
        chain_file = "certificate-chain.pem"
        
        with open(chain_file, 'wb') as f:
            # Server certificate would go first (not included in this demo)
            # f.write(server_cert.public_bytes(serialization.Encoding.PEM))
            
            # Intermediate certificate
            f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
            
            # Root certificate
            f.write(root_cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"✅ Certificate chain created: {chain_file}")
        print("   Chain order:")
        print("   1. [Server Certificate] (would be first)")
        print("   2. Intermediate CA Certificate")
        print("   3. Root CA Certificate")
        
        # Verify chain
        print(f"\n🔍 Chain Verification Process:")
        print("   1. Verify intermediate cert with root CA public key")
        print("   2. Verify server cert with intermediate CA public key")
        print("   3. Check all certificates are within validity period")
        print("   4. Verify certificate purposes match intended use")
        
    except FileNotFoundError as e:
        print(f"❌ Certificate files not found. Run demo_certificate_authority() first.")

# Add to main section
if __name__ == "__main__":
    root_ca, intermediate_ca = demo_certificate_authority()
    create_certificate_chain_file()
```

### ✅ Checkpoint 2: Certificate Authority Infrastructure

Verify your CA setup:
1. Can you create both root and intermediate CAs?
2. Do you understand certificate chain validation?
3. Can you issue server certificates from your intermediate CA?

---

## 📘 Part 3: Certificate Signing Requests (45 minutes)

**Learning Objective**: Generate and process Certificate Signing Requests (CSRs)

**What you'll build**: CSR generator and certificate issuance system

Create `certificate_requests.py`:

```python
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

class CSRManager:
    """Certificate Signing Request management"""
    
    def __init__(self):
        pass
    
    def create_csr(self, common_name, country="US", state="CA", city="San Francisco",
                  organization="CSCI347 Lab", organizational_unit="IT Department",
                  email=None, san_list=None):
        """
        Create a Certificate Signing Request
        
        Args:
            common_name (str): Common name for certificate
            country (str): Country code
            state (str): State or province
            city (str): City or locality
            organization (str): Organization name
            organizational_unit (str): Organizational unit
            email (str): Email address
            san_list (list): Subject Alternative Names
            
        Returns:
            tuple: (csr, private_key)
        """
        print(f"📝 Creating CSR for: {common_name}")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Build subject name
        subject_components = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, city),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
        
        # Add email if provided
        if email:
            subject_components.append(
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)
            )
        
        subject = x509.Name(subject_components)
        
        # Create CSR builder
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        
        # Add Subject Alternative Names if provided
        if san_list:
            sans = []
            for name in san_list:
                if name.startswith("email:"):
                    sans.append(x509.RFC822Name(name[6:]))
                elif name.startswith("ip:"):
                    sans.append(x509.IPAddress(ipaddress.ip_address(name[3:])))
                else:
                    sans.append(x509.DNSName(name))
            
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName(sans),
                critical=False,
            )
        
        # Add key usage extension
        csr_builder = csr_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        )
        
        # Add extended key usage for server authentication
        csr_builder = csr_builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        )
        
        # Sign the CSR
        csr = csr_builder.sign(private_key, hashes.SHA256())
        
        print(f"✅ CSR created successfully")
        return csr, private_key
    
    def save_csr_pem(self, csr, filename):
        """Save CSR in PEM format"""
        pem_data = csr.public_bytes(serialization.Encoding.PEM)
        with open(filename, 'wb') as f:
            f.write(pem_data)
        return filename
    
    def load_csr_pem(self, filename):
        """Load CSR from PEM file"""
        with open(filename, 'rb') as f:
            return x509.load_pem_x509_csr(f.read())
    
    def analyze_csr(self, csr):
        """Analyze CSR contents"""
        info = {
            'subject': csr.subject.rfc4514_string(),
            'public_key_size': csr.public_key().key_size,
            'signature_algorithm': csr.signature_algorithm_oid._name,
            'extensions': {}
        }
        
        # Parse extensions
        for extension in csr.extensions:
            ext_name = extension.oid._name
            if ext_name == 'subjectAlternativeName':
                sans = []
                for name in extension.value:
                    if isinstance(name, x509.DNSName):
                        sans.append(f"DNS:{name.value}")
                    elif isinstance(name, x509.IPAddress):
                        sans.append(f"IP:{name.value}")
                    elif isinstance(name, x509.RFC822Name):
                        sans.append(f"Email:{name.value}")
                info['extensions']['subject_alternative_name'] = sans
            elif ext_name == 'keyUsage':
                ku = extension.value
                usages = []
                if ku.digital_signature: usages.append("digital_signature")
                if ku.key_encipherment: usages.append("key_encipherment")
                info['extensions']['key_usage'] = usages
            elif ext_name == 'extendedKeyUsage':
                eku_names = []
                for usage in extension.value:
                    if usage == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                        eku_names.append("serverAuth")
                    elif usage == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                        eku_names.append("clientAuth")
                info['extensions']['extended_key_usage'] = eku_names
        
        return info
    
    def verify_csr_signature(self, csr):
        """Verify CSR signature"""
        try:
            csr.public_key().verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                csr.signature_hash_algorithm
            )
            return True
        except:
            return False

def demo_csr_workflow():
    """Demonstrate complete CSR workflow"""
    print("📄 Certificate Signing Request Workflow Demo")
    print("="*60)
    
    csr_manager = CSRManager()
    
    # Step 1: Create CSR for web server
    print("\n📋 Step 1: Create CSR for Web Server")
    web_csr, web_private_key = csr_manager.create_csr(
        common_name="secure.csci347lab.com",
        organization="CSCI347 Secure Labs",
        organizational_unit="Web Services",
        email="admin@csci347lab.com",
        san_list=[
            "secure.csci347lab.com",
            "www.secure.csci347lab.com",
            "api.secure.csci347lab.com",
            "email:webmaster@csci347lab.com"
        ]
    )
    
    # Save CSR
    csr_file = csr_manager.save_csr_pem(web_csr, "web-server.csr")
    print(f"   CSR saved to: {csr_file}")
    
    # Step 2: Analyze CSR
    print(f"\n📋 Step 2: Analyze CSR Contents")
    csr_info = csr_manager.analyze_csr(web_csr)
    
    print(f"   Subject: {csr_info['subject']}")
    print(f"   Public Key Size: {csr_info['public_key_size']} bits")
    print(f"   Signature Algorithm: {csr_info['signature_algorithm']}")
    
    for ext_name, ext_value in csr_info['extensions'].items():
        print(f"   {ext_name}: {ext_value}")
    
    # Step 3: Verify CSR signature
    print(f"\n📋 Step 3: Verify CSR Signature")
    signature_valid = csr_manager.verify_csr_signature(web_csr)
    print(f"   CSR signature valid: {'✅ Yes' if signature_valid else '❌ No'}")
    
    # Step 4: Create multiple CSRs for different services
    print(f"\n📋 Step 4: Create Additional Service CSRs")
    
    services = [
        {
            'name': 'Database Server',
            'common_name': 'db.csci347lab.com',
            'sans': ['db.csci347lab.com', 'database.csci347lab.com']
        },
        {
            'name': 'Email Server',
            'common_name': 'mail.csci347lab.com',
            'sans': ['mail.csci347lab.com', 'smtp.csci347lab.com', 'imap.csci347lab.com']
        },
        {
            'name': 'VPN Server',
            'common_name': 'vpn.csci347lab.com',
            'sans': ['vpn.csci347lab.com']
        }
    ]
    
    csrs_created = []
    for service in services:
        csr, private_key = csr_manager.create_csr(
            common_name=service['common_name'],
            organization="CSCI347 Infrastructure",
            organizational_unit=service['name'],
            san_list=service['sans']
        )
        
        csr_filename = f"{service['common_name'].replace('.', '-')}.csr"
        key_filename = f"{service['common_name'].replace('.', '-')}-key.pem"
        
        csr_manager.save_csr_pem(csr, csr_filename)
        
        # Save private key
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(key_filename, 'wb') as f:
            f.write(key_pem)
        
        csrs_created.append({
            'service': service['name'],
            'csr_file': csr_filename,
            'key_file': key_filename,
            'csr': csr,
            'private_key': private_key
        })
        
        print(f"   ✅ {service['name']}: {csr_filename}")
    
    print(f"\n💡 CSR Best Practices Demonstrated:")
    print("   • Proper subject distinguished name structure")
    print("   • Subject Alternative Names for multiple hostnames")
    print("   • Appropriate key usage extensions")
    print("   • Strong RSA key size (2048 bits minimum)")
    print("   • SHA-256 signature algorithm")
    
    return csrs_created

def demo_csr_validation():
    """Demonstrate CSR validation process"""
    print(f"\n🔍 CSR Validation Demo")
    print("="*50)
    
    # This would typically be done by a CA before issuing a certificate
    validation_checks = [
        "Subject distinguished name completeness",
        "Public key strength (minimum 2048 bits for RSA)",
        "Signature algorithm security (SHA-256 or better)",
        "Subject Alternative Names validity",
        "Key usage appropriateness",
        "Organization verification (in real CA)",
        "Domain ownership verification (in real CA)"
    ]
    
    print("📋 Standard CSR Validation Checklist:")
    for i, check in enumerate(validation_checks, 1):
        print(f"   {i}. {check}")
    
    print(f"\n⚠️  Real-World CA Validation:")
    print("   • Domain Validated (DV): Automated domain ownership check")
    print("   • Organization Validated (OV): Manual organization verification") 
    print("   • Extended Validation (EV): Rigorous legal entity verification")

if __name__ == "__main__":
    csrs = demo_csr_workflow()
    demo_csr_validation()
```

### ✅ Checkpoint 3: Certificate Signing Requests

Verify your CSR knowledge:
1. Can you create a CSR with proper subject information?
2. Do you understand Subject Alternative Names?
3. Can you explain the CSR validation process?

---

## 📘 Part 4: TLS/SSL Implementation (90 minutes)

**Learning Objective**: Implement TLS connections with certificate validation

**What you'll build**: TLS server and client with certificate validation

Create `tls_implementation.py`:

```python
import socket
import ssl
import threading
import time
from pathlib import Path
import os

class TLSServer:
    """TLS server with certificate authentication"""
    
    def __init__(self, host="localhost", port=8443):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
    
    def start_server(self, cert_file, key_file, ca_file=None, require_client_cert=False):
        """
        Start TLS server
        
        Args:
            cert_file (str): Server certificate file
            key_file (str): Server private key file
            ca_file (str): CA certificate file for client verification
            require_client_cert (bool): Require client certificates
        """
        print(f"🚀 Starting TLS server on {self.host}:{self.port}")
        
        # Create SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load server certificate and key
        context.load_cert_chain(cert_file, key_file)
        
        # Configure client certificate requirements
        if require_client_cert:
            if ca_file:
                context.load_verify_locations(ca_file)
            context.verify_mode = ssl.CERT_REQUIRED
            print("   ✅ Client certificates required")
        else:
            context.verify_mode = ssl.CERT_NONE
            print("   ℹ️  Client certificates optional")
        
        # Create and bind socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        print(f"   Server certificate: {cert_file}")
        print(f"   Server listening on {self.host}:{self.port}")
        
        self.running = True
        
        try:
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"   📞 Connection from {address}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, context)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error:
                    if self.running:
                        print("   ❌ Socket error occurred")
                    break
                    
        except KeyboardInterrupt:
            print("   🛑 Server shutdown requested")
        finally:
            self.stop_server()
    
    def _handle_client(self, client_socket, ssl_context):
        """Handle individual client connections"""
        try:
            # Wrap socket with TLS
            tls_socket = ssl_context.wrap_socket(client_socket, server_side=True)
            
            # Get client certificate info if available
            client_cert = tls_socket.getpeercert()
            if client_cert:
                print(f"     🔐 Client certificate subject: {client_cert.get('subject', 'Unknown')}")
            
            # Get TLS connection info
            cipher = tls_socket.cipher()
            protocol = tls_socket.version()
            
            print(f"     🔒 TLS version: {protocol}")
            print(f"     🔒 Cipher suite: {cipher[0] if cipher else 'Unknown'}")
            
            # Simple HTTP-like response
            response = f"""HTTP/1.1 200 OK\r
Content-Type: text/html\r
Connection: close\r
\r
<html>
<head><title>CSCI347 TLS Demo</title></head>
<body>
<h1>🔒 Secure TLS Connection Established!</h1>
<p><strong>TLS Version:</strong> {protocol}</p>
<p><strong>Cipher Suite:</strong> {cipher[0] if cipher else 'Unknown'}</p>
<p><strong>Client Certificate:</strong> {'Yes' if client_cert else 'No'}</p>
<p>This connection is secured with TLS encryption.</p>
</body>
</html>"""
            
            tls_socket.send(response.encode())
            
        except ssl.SSLError as e:
            print(f"     ❌ TLS error: {e}")
        except Exception as e:
            print(f"     ❌ Connection error: {e}")
        finally:
            try:
                tls_socket.close()
            except:
                pass
    
    def stop_server(self):
        """Stop the TLS server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("   🛑 TLS server stopped")

class TLSClient:
    """TLS client with certificate validation"""
    
    def __init__(self):
        pass
    
    def connect_to_server(self, host, port, ca_file=None, cert_file=None, 
                         key_file=None, verify_hostname=True):
        """
        Connect to TLS server
        
        Args:
            host (str): Server hostname
            port (int): Server port
            ca_file (str): CA certificate for server verification
            cert_file (str): Client certificate file
            key_file (str): Client private key file
            verify_hostname (bool): Verify server hostname
            
        Returns:
            dict: Connection information
        """
        print(f"🔌 Connecting to TLS server {host}:{port}")
        
        # Create SSL context for client
        if ca_file:
            context = ssl.create_default_context(cafile=ca_file)
            print("   📋 Using custom CA for server verification")
        else:
            context = ssl.create_default_context()
            print("   📋 Using system CA store for server verification")
        
        # Load client certificate if provided
        if cert_file and key_file:
            context.load_cert_chain(cert_file, key_file)
            print("   🔐 Client certificate loaded")
        
        # Configure hostname verification
        if not verify_hostname:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            print("   ⚠️  Hostname verification disabled (not recommended)")
        
        try:
            # Create socket and connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Wrap with TLS
            tls_sock = context.wrap_socket(sock, server_hostname=host)
            tls_sock.connect((host, port))
            
            # Get connection information
            server_cert = tls_sock.getpeercert()
            cipher = tls_sock.cipher()
            protocol = tls_sock.version()
            
            connection_info = {
                'tls_version': protocol,
                'cipher_suite': cipher[0] if cipher else 'Unknown',
                'server_certificate': server_cert,
                'connection_established': True
            }
            
            print(f"   ✅ TLS connection established")
            print(f"   🔒 TLS version: {protocol}")
            print(f"   🔒 Cipher suite: {cipher[0] if cipher else 'Unknown'}")
            
            if server_cert:
                subject = dict(x[0] for x in server_cert['subject'])
                print(f"   📜 Server certificate subject: {subject.get('commonName', 'Unknown')}")
            
            # Send simple HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            tls_sock.send(request.encode())
            
            # Read response
            response = b""
            while True:
                data = tls_sock.recv(4096)
                if not data:
                    break
                response += data
            
            connection_info['response'] = response.decode('utf-8', errors='ignore')
            
            tls_sock.close()
            
            return connection_info
            
        except ssl.SSLError as e:
            print(f"   ❌ TLS error: {e}")
            return {'connection_established': False, 'error': str(e)}
        except Exception as e:
            print(f"   ❌ Connection error: {e}")
            return {'connection_established': False, 'error': str(e)}

def demo_tls_server_client():
    """Demonstrate TLS server and client interaction"""
    print("🔐 TLS Server/Client Demo")
    print("="*50)
    
    # Check if we have certificates from previous demos
    server_cert = "pki/intermediate-ca/newcerts/server-www-csci347lab-com.pem"
    server_key = "pki/intermediate-ca/private/server-www-csci347lab-com-key.pem"
    ca_cert = "pki/root-ca/certs/ca-cert.pem"
    
    # Create simple test certificates if CA demo files don't exist
    if not os.path.exists(server_cert):
        print("📋 Creating test certificates for TLS demo...")
        create_test_certificates()
        server_cert = "test-server.pem"
        server_key = "test-server-key.pem"
        ca_cert = "test-ca.pem"
    
    # Start server in background thread
    server = TLSServer()
    server_thread = threading.Thread(
        target=server.start_server,
        args=(server_cert, server_key, ca_cert, False)
    )
    server_thread.daemon = True
    server_thread.start()
    
    # Give server time to start
    time.sleep(2)
    
    # Test client connections
    print(f"\n📋 Testing TLS Client Connections")
    
    client = TLSClient()
    
    # Test 1: Connection with CA verification
    print(f"\n🔍 Test 1: Connection with CA verification")
    result = client.connect_to_server(
        host="localhost",
        port=8443,
        ca_file=ca_cert,
        verify_hostname=False  # We're using localhost
    )
    
    if result['connection_established']:
        print("   ✅ Connection successful with CA verification")
    else:
        print(f"   ❌ Connection failed: {result.get('error', 'Unknown error')}")
    
    # Test 2: Connection without verification (insecure)
    print(f"\n🔍 Test 2: Connection without certificate verification")
    result = client.connect_to_server(
        host="localhost",
        port=8443,
        verify_hostname=False
    )
    
    if result['connection_established']:
        print("   ⚠️  Connection successful without verification (insecure)")
    else:
        print(f"   ❌ Connection failed: {result.get('error', 'Unknown error')}")
    
    # Stop server
    time.sleep(1)
    server.stop_server()
    
    print(f"\n💡 TLS Security Principles:")
    print("   • Always verify server certificates against trusted CAs")
    print("   • Use strong cipher suites (AES-256, ECDHE)")
    print("   • Verify hostname matches certificate")
    print("   • Use TLS 1.2 or higher")
    print("   • Consider client certificates for mutual authentication")

def create_test_certificates():
    """Create simple test certificates for TLS demo"""
    from certificate_basics import CertificateManager
    
    cm = CertificateManager()
    
    # Create CA certificate
    ca_cert, ca_key = cm.create_self_signed_certificate(
        common_name="Test CA",
        organization="CSCI347 Test"
    )
    
    # Create server certificate
    server_cert, server_key = cm.create_self_signed_certificate(
        common_name="localhost",
        organization="CSCI347 Test Server"
    )
    
    # Save certificates
    cm.save_certificate_pem(ca_cert, "test-ca.pem")
    cm.save_private_key_pem(ca_key, "test-ca-key.pem")
    cm.save_certificate_pem(server_cert, "test-server.pem")
    cm.save_private_key_pem(server_key, "test-server-key.pem")
    
    print("   ✅ Test certificates created")

def demo_certificate_validation():
    """Demonstrate certificate validation in TLS"""
    print(f"\n🔍 Certificate Validation in TLS")
    print("="*50)
    
    validation_steps = [
        "1. Certificate chain validation",
        "   • Verify each certificate in chain with issuer's public key",
        "   • Check chain leads to trusted root CA",
        "",
        "2. Certificate validity period",
        "   • Current time must be between notBefore and notAfter",
        "",
        "3. Hostname verification", 
        "   • Certificate CN or SAN must match server hostname",
        "",
        "4. Certificate purpose validation",
        "   • Extended Key Usage must include serverAuth",
        "",
        "5. Revocation checking",
        "   • Check Certificate Revocation List (CRL)",
        "   • Or use Online Certificate Status Protocol (OCSP)",
        "",
        "6. Cryptographic strength",
        "   • Key size must meet minimum requirements",
        "   • Signature algorithm must be secure (no MD5, SHA-1)"
    ]
    
    for step in validation_steps:
        print(f"   {step}")

if __name__ == "__main__":
    demo_tls_server_client()
    demo_certificate_validation()
```

### ✅ Checkpoint 4: TLS/SSL Implementation

Test your TLS understanding:
1. Can you create a working TLS server?
2. Do you understand certificate validation in TLS?
3. Can you explain the TLS handshake process?

---

## 📘 Part 5: Certificate Lifecycle Management (45 minutes)

**Learning Objective**: Manage certificate lifecycle including renewal and revocation

**What you'll build**: Certificate lifecycle management system

Create `certificate_lifecycle.py`:

```python
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import datetime
import json
from pathlib import Path
import os

class CertificateLifecycleManager:
    """Manage certificate lifecycle operations"""
    
    def __init__(self, config_file="cert_config.json"):
        self.config_file = config_file
        self.certificates = {}
        self.load_configuration()
    
    def load_configuration(self):
        """Load certificate tracking configuration"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.certificates = json.load(f)
        else:
            self.certificates = {}
    
    def save_configuration(self):
        """Save certificate tracking configuration"""
        with open(self.config_file, 'w') as f:
            json.dump(self.certificates, f, indent=2, default=str)
    
    def add_certificate_to_tracking(self, cert_file, key_file, name=None):
        """Add certificate to lifecycle tracking"""
        # Load certificate
        with open(cert_file, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        
        if name is None:
            subject = dict(x[0] for x in cert.subject if len(x) > 0)
            name = subject.get('commonName', f'cert-{len(self.certificates)}')
        
        # Extract certificate information
        cert_info = {
            'certificate_file': cert_file,
            'private_key_file': key_file,
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'serial_number': str(cert.serial_number),
            'not_valid_before': cert.not_valid_before.isoformat(),
            'not_valid_after': cert.not_valid_after.isoformat(),
            'fingerprint': cert.fingerprint(hashes.SHA256()).hex(),
            'added_date': datetime.datetime.now().isoformat(),
            'status': 'active'
        }
        
        self.certificates[name] = cert_info
        self.save_configuration()
        
        print(f"✅ Certificate '{name}' added to tracking")
        return name
    
    def check_certificate_expiry(self, warning_days=30):
        """Check certificates for upcoming expiry"""
        print(f"📅 Checking certificate expiry (warning: {warning_days} days)")
        print("="*50)
        
        now = datetime.datetime.now()
        expiring_soon = []
        expired = []
        
        for name, cert_info in self.certificates.items():
            if cert_info.get('status') != 'active':
                continue
                
            not_after = datetime.datetime.fromisoformat(cert_info['not_valid_after'])
            days_until_expiry = (not_after - now).days
            
            print(f"\n📜 Certificate: {name}")
            print(f"   Subject: {cert_info['subject']}")
            print(f"   Expires: {not_after.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   Days until expiry: {days_until_expiry}")
            
            if days_until_expiry < 0:
                print("   ❌ STATUS: EXPIRED")
                expired.append(name)
            elif days_until_expiry <= warning_days:
                print(f"   ⚠️  STATUS: EXPIRING SOON ({days_until_expiry} days)")
                expiring_soon.append(name)
            else:
                print("   ✅ STATUS: VALID")
        
        return {
            'expiring_soon': expiring_soon,
            'expired': expired,
            'warning_days': warning_days
        }
    
    def generate_renewal_reminder(self, cert_name):
        """Generate renewal reminder information"""
        if cert_name not in self.certificates:
            print(f"❌ Certificate '{cert_name}' not found")
            return None
        
        cert_info = self.certificates[cert_name]
        not_after = datetime.datetime.fromisoformat(cert_info['not_valid_after'])
        
        reminder = f"""
🔔 CERTIFICATE RENEWAL REMINDER
================================

Certificate Name: {cert_name}
Subject: {cert_info['subject']}
Current Expiry: {not_after.strftime('%Y-%m-%d %H:%M:%S')}
Certificate File: {cert_info['certificate_file']}
Private Key File: {cert_info['private_key_file']}

RENEWAL CHECKLIST:
☐ 1. Generate new Certificate Signing Request (CSR)
☐ 2. Submit CSR to Certificate Authority
☐ 3. Download new certificate
☐ 4. Test certificate in staging environment
☐ 5. Deploy certificate to production
☐ 6. Update certificate tracking
☐ 7. Verify services are using new certificate
☐ 8. Schedule next renewal reminder

AUTOMATION RECOMMENDATIONS:
• Use ACME protocol (Let's Encrypt) for automatic renewal
• Set up monitoring alerts 60, 30, and 7 days before expiry
• Implement zero-downtime certificate deployment
• Test certificate renewal process regularly

EMERGENCY CONTACT:
• Certificate Authority: [Contact Information]
• System Administrator: [Contact Information]
• Security Team: [Contact Information]
        """.strip()
        
        print(reminder)
        return reminder
    
    def create_certificate_revocation_list(self, ca_cert_file, ca_key_file, 
                                         revoked_serials):
        """Create Certificate Revocation List (CRL)"""
        print("📋 Creating Certificate Revocation List")
        
        # Load CA certificate and key
        with open(ca_cert_file, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        
        with open(ca_key_file, 'rb') as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        
        # Create CRL builder
        crl_builder = x509.CertificateRevocationListBuilder()
        crl_builder = crl_builder.issuer_name(ca_cert.subject)
        crl_builder = crl_builder.last_update(datetime.datetime.utcnow())
        crl_builder = crl_builder.next_update(
            datetime.datetime.utcnow() + datetime.timedelta(days=7)
        )
        
        # Add revoked certificates
        for serial_info in revoked_serials:
            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                int(serial_info['serial_number'])
            ).revocation_date(
                datetime.datetime.fromisoformat(serial_info['revocation_date'])
            ).add_extension(
                x509.CRLReason(x509.ReasonFlags.key_compromise),  # Example reason
                critical=False
            ).build()
            
            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
        
        # Build and sign CRL
        crl = crl_builder.sign(ca_key, hashes.SHA256())
        
        # Save CRL
        crl_file = "certificate_revocation_list.crl"
        with open(crl_file, 'wb') as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        
        print(f"✅ CRL created: {crl_file}")
        print(f"   Revoked certificates: {len(revoked_serials)}")
        print(f"   Valid until: {crl.next_update}")
        
        return crl_file
    
    def mark_certificate_revoked(self, cert_name, reason="key_compromise"):
        """Mark certificate as revoked in tracking system"""
        if cert_name not in self.certificates:
            print(f"❌ Certificate '{cert_name}' not found")
            return False
        
        self.certificates[cert_name]['status'] = 'revoked'
        self.certificates[cert_name]['revocation_date'] = datetime.datetime.now().isoformat()
        self.certificates[cert_name]['revocation_reason'] = reason
        
        self.save_configuration()
        
        print(f"⚠️  Certificate '{cert_name}' marked as revoked")
        print(f"   Reason: {reason}")
        print(f"   Revocation date: {self.certificates[cert_name]['revocation_date']}")
        
        return True
    
    def generate_lifecycle_report(self):
        """Generate comprehensive certificate lifecycle report"""
        print("📊 Certificate Lifecycle Report")
        print("="*50)
        
        total_certs = len(self.certificates)
        active_certs = sum(1 for cert in self.certificates.values() 
                          if cert.get('status') == 'active')
        revoked_certs = sum(1 for cert in self.certificates.values() 
                           if cert.get('status') == 'revoked')
        
        print(f"\n📈 Summary Statistics:")
        print(f"   Total certificates: {total_certs}")
        print(f"   Active certificates: {active_certs}")
        print(f"   Revoked certificates: {revoked_certs}")
        
        # Check expiry status
        expiry_check = self.check_certificate_expiry(warning_days=30)
        
        print(f"\n📅 Expiry Status:")
        print(f"   Expiring within 30 days: {len(expiry_check['expiring_soon'])}")
        print(f"   Already expired: {len(expiry_check['expired'])}")
        
        # Certificate authorities
        issuers = {}
        for cert_info in self.certificates.values():
            issuer = cert_info.get('issuer', 'Unknown')
            issuers[issuer] = issuers.get(issuer, 0) + 1
        
        print(f"\n🏛️  Certificate Authorities:")
        for issuer, count in issuers.items():
            print(f"   {issuer}: {count} certificate(s)")
        
        return {
            'total': total_certs,
            'active': active_certs,
            'revoked': revoked_certs,
            'expiring_soon': len(expiry_check['expiring_soon']),
            'expired': len(expiry_check['expired']),
            'issuers': issuers
        }

def demo_certificate_lifecycle():
    """Demonstrate certificate lifecycle management"""
    print("♻️  Certificate Lifecycle Management Demo")
    print("="*60)
    
    clm = CertificateLifecycleManager("demo_cert_config.json")
    
    # Add certificates to tracking (using test certificates)
    print("📋 Adding certificates to lifecycle tracking...")
    
    # Check if we have certificates from previous demos
    test_certificates = [
        ("test-server.pem", "test-server-key.pem", "Test Server"),
        ("test-ca.pem", "test-ca-key.pem", "Test CA")
    ]
    
    certificates_added = []
    for cert_file, key_file, name in test_certificates:
        if os.path.exists(cert_file):
            clm.add_certificate_to_tracking(cert_file, key_file, name)
            certificates_added.append(name)
    
    if not certificates_added:
        print("   ℹ️  No test certificates found. Run previous demos first.")
        return
    
    # Check certificate expiry
    print(f"\n📋 Certificate Expiry Check:")
    expiry_results = clm.check_certificate_expiry(warning_days=365)  # 1 year warning
    
    # Generate renewal reminder
    if certificates_added:
        print(f"\n📋 Generating Renewal Reminder:")
        clm.generate_renewal_reminder(certificates_added[0])
    
    # Simulate certificate revocation
    print(f"\n📋 Simulating Certificate Revocation:")
    if len(certificates_added) > 1:
        clm.mark_certificate_revoked(certificates_added[1], "suspected_compromise")
        
        # Create CRL (simplified example)
        revoked_list = [{
            'serial_number': '123456789',
            'revocation_date': datetime.datetime.now().isoformat()
        }]
        
        if os.path.exists("test-ca.pem") and os.path.exists("test-ca-key.pem"):
            clm.create_certificate_revocation_list(
                "test-ca.pem", 
                "test-ca-key.pem", 
                revoked_list
            )
    
    # Generate lifecycle report
    print(f"\n📋 Generating Lifecycle Report:")
    report = clm.generate_lifecycle_report()
    
    # Best practices summary
    print(f"\n💡 Certificate Lifecycle Best Practices:")
    print("   • Monitor certificates for expiry (60, 30, 7 days)")
    print("   • Automate renewal where possible (ACME protocol)")
    print("   • Maintain certificate inventory")
    print("   • Test certificate deployment process")
    print("   • Have emergency renewal procedures")
    print("   • Implement proper key management")
    print("   • Regular security audits of certificate usage")
    
    # Cleanup
    if os.path.exists("demo_cert_config.json"):
        os.remove("demo_cert_config.json")

if __name__ == "__main__":
    demo_certificate_lifecycle()
```

### ✅ Checkpoint 5: Certificate Lifecycle Management

Verify your lifecycle management knowledge:
1. Can you track certificate expiry dates?
2. Do you understand certificate revocation?
3. Can you create a certificate renewal process?

---

## ✅ Tutorial Completion Checklist

After completing all parts, verify your understanding:

- [ ] You can create and analyze X.509 certificates
- [ ] You understand certificate authority hierarchies
- [ ] You can generate and process Certificate Signing Requests
- [ ] You can implement TLS with proper certificate validation
- [ ] You can manage certificate lifecycle and revocation
- [ ] You understand PKI trust models and security considerations

## 🚀 Ready for the Assignment?

Excellent! Now you have all the knowledge to build your Mini Certificate Authority. The assignment will combine these concepts into a complete PKI system.

**Next step**: Review [assignment.md](assignment.md) for detailed requirements.

## 💡 Key Concepts Learned

1. **X.509 certificate structure** and extensions
2. **Certificate Authority hierarchies** (root and intermediate CAs)
3. **Certificate Signing Requests** (CSRs) and issuance process
4. **TLS/SSL implementation** with certificate validation
5. **Certificate lifecycle management** including renewal and revocation
6. **PKI trust models** and security best practices
7. **Certificate chain validation** and verification processes

---

**Questions?** Check the troubleshooting section or ask in Canvas discussions!