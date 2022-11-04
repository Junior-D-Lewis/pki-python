import uuid
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import CertificateBuilder
from cryptography.x509.oid import NameOID
import datetime


def generate_cert(CommonName: str, OrganizationName: str,
                  OrganizationUnitName: str, public_key: RSAPublicKey) -> CertificateBuilder:
    one_day = datetime.timedelta(1, 0, 0)

    builder = x509.CertificateBuilder()

    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CommonName),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, OrganizationName),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, OrganizationUnitName),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CommonName),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime(2023, 8, 2))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )

    return builder
