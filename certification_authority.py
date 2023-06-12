from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime, subprocess, os

# Code used by Certificate Authority (CA) for creation of X.509 attributes.

# Creates self-signed Certificate Authority (CA).
def generate_ca():
    # Generate private key for CA.
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Export private key in PEM format.
    # NOTE: This file should be well secured. See report for more details.
    ca_private_key_pem = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("ca_private_key.pem", "wb") as ca_private_key_file:
        ca_private_key_file.write(ca_private_key_pem)

    # Create Certificate Signing Request (CSR).
    ca_csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,
                u"Company X Certificate Authority")])).sign(ca_private_key,
                        hashes.SHA256(), default_backend())

    # Export CSR in PEM format.
    ca_csr_pem = ca_csr.public_bytes(serialization.Encoding.PEM)
    with open("ca_csr.pem", "wb") as ca_csr_file:
        ca_csr_file.write(ca_csr_pem)

    # Create and export CA certificate.
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_csr.subject
    ).issuer_name(
        ca_csr.subject
    ).public_key(
        ca_csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_private_key, hashes.SHA256(), default_backend())

    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    with open("ca_cert.pem", "wb") as ca_cert_file:
        ca_cert_file.write(ca_cert_pem)

    print("Certification Authority certificate created and self-signed successfully.")


# Generates user certificate of user using CA information.
# `deactivate_attributes` parameter is used to omit addition of attributes
# to certificate for testing purposes.
def generate_user_certificate(username, deactivate_attributes):
    # Generate and export user private key in PEM format.
    user_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    user_private_key_pem = user_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(username + "_private_key.pem", "wb") as user_private_key_file:
        user_private_key_file.write(user_private_key_pem)

    # Creation and exportation of CSR for user in PEM format.
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])
    )
    csr = csr_builder.sign(user_private_key, hashes.SHA256(), default_backend())
    user_csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    with open(username + "_csr.pem", "wb") as user_csr_file:
        user_csr_file.write(user_csr_pem)

    # Create attributes extension.
    if deactivate_attributes:
        alt_name = x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(u"Invalid attribute")
        ])
    else:
        alt_name = x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(u"https://boblebanquier.fr/transaction")
        ])

    # Signature of user CSR by CA to create certificate attributes.
    with open("ca_private_key.pem", "rb") as ca_private_key_file:
        ca_private_key = serialization.load_pem_private_key(
            ca_private_key_file.read(),
            password=None,
            backend=default_backend()
        )
    with open("ca_cert.pem", "rb") as ca_cert_file:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read(), default_backend())
    user_cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        alt_name,
        critical=False
    ).sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Export user certificate in PEM format.
    with open(username + "_cert.pem", "wb") as user_cert_file:
        user_cert_file.write(user_cert.public_bytes(serialization.Encoding.PEM))

    print("Generated and signed user certificate for " + username)


def revoke_user_certificate(ca_cert_path, ca_key_path, cert_to_revoke_path):
    # Load CA private key and certificate.
    with open(ca_key_path, "rb") as ca_key_file:
        ca_private_key = serialization.load_pem_private_key(
            ca_key_file.read(),
            password=None,
            backend=default_backend())
    with open(ca_cert_path, "rb") as ca_cert_file:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read(),
                default_backend())

    # Load certificate to revoke.
    with open(cert_to_revoke_path, "rb") as cert_file:
        cert_to_revoke = x509.load_pem_x509_certificate(cert_file.read(),
                default_backend())

    # Create or load Certificate Revocation List (CRL).
    # Add certificate to Certificate Revocation List (CRL).
    if os.path.exists("crl.pem"):
        print("Using already present Certificate Revocation List")
        with open("crl.pem", "rb") as crl_file:
            existing_crl = x509.load_pem_x509_crl(crl_file.read(), default_backend())
            crl_builder = x509.CertificateRevocationListBuilder().issuer_name(
                    existing_crl.issuer).last_update(
                existing_crl.last_update).next_update(existing_crl.next_update)
            for revoked_cert in existing_crl:
                crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
            crl_builder = crl_builder.add_revoked_certificate(
                    x509.RevokedCertificateBuilder().serial_number(
                cert_to_revoke.serial_number).revocation_date(
                    datetime.datetime.utcnow()).build())
    else:
        print("Creating Certificate Revocation List")
        crl_builder = x509.CertificateRevocationListBuilder().issuer_name(
                ca_cert.subject).last_update(datetime.
                        datetime.utcnow()).next_update(datetime.
                                datetime.utcnow() + datetime.timedelta(days=30))
        crl_builder = crl_builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder().serial_number(
                    cert_to_revoke.serial_number).revocation_date(
                        datetime.datetime.utcnow()).build())

        # Sign and export CRL.
        crl = crl_builder.sign(private_key=ca_private_key,
                algorithm=hashes.SHA256(), backend=default_backend())
        with open("crl.pem", "wb") as crl_file:
            crl_file.write(crl.public_bytes(serialization.Encoding.PEM))

    print("Certificate has been revoked.")



def main():
    generate_ca()

    # Cas 1: Utilisateur sans access au service.
    generate_user_certificate("sara", 1)
    # Cas 2: Utilisateur avec access au service.
    generate_user_certificate("micka", 0)
    # Cas 3: Utilisateur n'ayant plus d'access.
    generate_user_certificate("robert", 0)
    revoke_user_certificate("ca_cert.pem", "ca_private_key.pem", "robert_cert.pem")


if __name__ == "__main__":
    main()
