import os.path
import pathlib

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder
from cryptography.x509.oid import NameOID
import datetime
import uuid

from Crypto.generator import generator

ca_private_key = bytes
ca_public_key = bytes

if os.path.exists("ca_private_key.key"):
    with open("../Crypto/root_CA/ca_private_key.key", "w") as f:
        ca_private_key = f.read()
else:
    # génération de la private key de CA root
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # génération de la public  key de CA root
    ca_public_key = ca_private_key.public_key()

    with open("../Crypto/root_CA/ca_public_key.key", "wb") as f:
        f.write(ca_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def test_Date_Validity():
    name = input("Please enter your organization name: ")
    path = "../Crypto/user_Certificate/" + name + "_certificate.crt"
    # Tout d'abord on verifie qu'il existe un certificat au non de l'organisation de l'utilisateur
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as file:
           cert = x509.load_pem_x509_certificate(str.encode(file.read()))

        # vérification de la validité temporelle du certificat
        print(f"Certificate: {path}\n")
        if datetime.date.today() > cert.not_valid_after:
            print("Certificat  n'est pas valide")
        if datetime.date.today() < cert.not_valid_before:
            print("Certificat est valide")

def sign_certificate(cert: CertificateBuilder, hash_algo: int, name: str):
    path = "../Crypto/" + name + "_certificate.crt"
    match hash_algo:
        case 0:
            h = hashes.SHA256()
        case 1:
            h = hashes.SHA3_384()
        case 2:
            h = hashes.SHA224()
        case 3:
            h = hashes.SHA3_512()
        case 4:
            h = hashes.SHA512_224()
        case 5:
            h = hashes.SHA512_256()
        case 6:
            h = hashes.BLAKE2b()
        case 7:
            h = hashes.BLAKE2s()
        case 8:
            h = hashes.SM3()
        case 9:
            h = hashes.SHA1()
        case 10:
            h = hashes.SHA3_224()
        case 11:
            h = hashes.SHA3_256()
        case 12:
            h = hashes.SHA384()
        case 13:
            h = hashes.SHAKE128()
        case 14:
            h = hashes.MD5()
        case 15:
            h = hashes.SHAKE256()
        case _:
            h = hashes.SHA256()

    certificate_final = cert.sign(
        private_key=ca_private_key, algorithm=h,
        backend=default_backend()
    )


    #ecriture de certificatz en PEM dans un fichier

    with open(path, "wb") as f:
        f.write(certificate_final.public_bytes(
            encoding=serialization.Encoding.PEM,
        ))
    print(isinstance(certificate_final, x509.Certificate))


def authority_root():

    #Nous verifions s'il existe un certificat pour notre auorité racine
    if os.path.exists("ca_certificate.crt"):
        print("Ce certificat existe déjà")
    #S'il n'en possède pas, on le lui génère et on le signe
    else:
        unsigned_ca_certificate = generator.generate_cert("ca", "esiea", ca_public_key)
        sign_certificate(unsigned_ca_certificate, 0, "/root_CA/ca")

    #on enregistre ensuite sa clé privé dans un ficier
    with open("../Crypto/root_CA/ca_private_key.key", "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"openstack-ansible")
        ))


authority_root()
