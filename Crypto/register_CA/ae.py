from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder
from cryptography.x509.oid import NameOID
import datetime
import uuid

from Crypto.generator import generator

#Création de notre autorité d'enregistrement
#Elle aura pour but de génerer les clés privées et publique de l'utilisateur, lui envoyer
#sa clé privé et créer un certificat qui sera signé par la CA.
#Nous tenons a noté que dans le projet il est dit que c'est l'autorité d'enregistrement qui crée les
#certificats et l'autorité racine les signe.
def register_authority(CommonName: str, OrganizationUnitName: str) -> CertificateBuilder:
    path = "../Crypto/user_Key/" + CommonName + "_private.key"
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    with open(path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"openstack-ansible")
        ))

    unsigned_certificate = generator.generate_cert(CommonName,OrganizationUnitName,public_key)

    return  unsigned_certificate

