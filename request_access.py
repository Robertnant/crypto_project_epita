from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import ExtensionOID
from cryptography import x509
import os

def request_transaction(username):
    # Verification of certificate attributes.
    with open(username + "_cert.pem", "rb") as file:
        cert_data = file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Verification of certificate validity.
        ca_cert_data = open("ca_cert.pem", "rb").read()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)

        # Verification of revocation status.
        if os.path.exists("crl.pem"):
            crl_data = open("crl.pem", "rb").read()
            crl = x509.load_pem_x509_crl(crl_data, default_backend())
            for revoked_certificate in crl:
                if revoked_certificate.serial_number == cert.serial_number:
                    print("Vous n'avez plus access a cette ressource. Essayez une autre page s'il vous plait.")
                    return
        # Verification of access.
        access_uri = ""
        for extension in cert.extensions:
            if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                alt_names = extension.value
                for name in alt_names:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        access_uri = name.value
                        break

        if access_uri == "https://boblebanquier.fr/transaction":
            print("Bienvenue a la page de transaction !")
        else:
            print("Acces refuse. Tentez une autre ressource s'il vous plait.")

def main():
    # Cas 1: Utilisateur sans access au service.
    request_transaction("sara")
    # Cas 2: Utilisateur avec access au service.
    request_transaction("micka")
    # Cas 3: Utilisateur n'ayant plus d'access.
    request_transaction("robert")


if __name__ == "__main__":
    main()

