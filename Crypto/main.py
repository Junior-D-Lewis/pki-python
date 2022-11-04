from OpenSSL import crypto, SSL
from socket import gethostname
from email_validator import validate_email, EmailNotValidError, EmailSyntaxError
import os
from pprint import pprint
from time import gmtime, mktime
import os


def cert_gen(
        emailAddress,
        commonName,
        countryName,
        localityName,
        stateOrProvinceName,
        organizationName,
        organizationUnitName,
        serialNumber=0,
        validityStartInSeconds=0,
        validityEndInSeconds=10 * 365 * 24 * 60 * 60,
        KEY_FILE="private.key",
        CERT_FILE="selfsigned.crt"):
    # can look at generated file using openssl:
    # openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))


# Acquisition des donnees
validation = input("Quel est adresse mail du certificat ? ")
try :
    Address =validate_email(validation, check_deliverability= True)
    emailAddress = Address.email
except EmailNotValidError:
    validation = input("format invalide veuillez. Quel est adresse mail du certificat ? ")
    Address =validate_email(validation, check_deliverability= True)
    emailAddress = Address.email

commonName = input("Quel du certificat ?: ")
countryName = input("Veuillez donner le pays d'identification du certificat :")
localityName = input("Quel est la ville d'identification du certificat ?: ")
stateOrProvinceName = input("Quel est le nom de la province d'identification du certificat ?: ")
organizationName = input("Quel est le nom de l'organisation du certification? : ")
organizationUnitName = input("Quel est le nom de l'organisation ? ")
serialNumber = int(input("Quel est le numero de série ? "))


# Appel du generateur de certicat
cert_gen(emailAddress, commonName, countryName, localityName, stateOrProvinceName,
         organizationName, organizationUnitName, serialNumber)
