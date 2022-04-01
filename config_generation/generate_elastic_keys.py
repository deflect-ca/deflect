# https://gist.github.com/major/8ac9f98ae8b07f46b208
# https://cryptography.io/en/latest/x509/reference/
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import ipaddress
import datetime

from util.helpers import path_to_persisted, path_to_containers
import os.path
import os


def gen_key_and_cert(name, alt_name, issuer_name, is_ca, logger):
    logger.info(
        f"generating a new key and cert, subject={name}, issuer={issuer_name}")

    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    pub_key = priv_key.public_key()

    builder = x509.CertificateBuilder()

    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ]))

    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
    ]))

    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.IPv4Address(alt_name))]
        ),
        critical=False
    )

    one_day = datetime.timedelta(days=1)
    one_year = datetime.timedelta(days=365)

    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + one_year)

    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pub_key)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=None), critical=True,
    )
    return priv_key, builder


def sign_cert_with_key(cert, key):
    return cert.sign(private_key=key, algorithm=hashes.SHA256())

# XXX i don't like this flow of outputting keys in the containers/**/ dirs...


def generate_new_elastic_certs(config, logger):
    # XXX config
    ca_subject = "my ca"
    ca_alt_name = config['controller']['ip']

    ins_subject = config['controller']['hostname']
    ins_alt_name = config['controller']['ip']

    ca_key, ca_cert_uns = gen_key_and_cert(
        ca_subject, ca_alt_name, ca_subject, True, logger)
    ca_cert = sign_cert_with_key(ca_cert_uns, ca_key)

    ins_key, ins_cert_uns = gen_key_and_cert(
        ins_subject, ins_alt_name, ca_subject, False, logger)
    ins_cert = sign_cert_with_key(ins_cert_uns, ca_key)

    ca_key_bytes = ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
    )

    ca_cert_bytes = ca_cert.public_bytes(
            encoding=serialization.Encoding.PEM,
    )

    ins_key_bytes = ins_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
    )

    ins_cert_bytes = ins_cert.public_bytes(
        encoding=serialization.Encoding.PEM,
    )

    # now write the bytes all over the place...
    dirs_for_keys = []

    persisted_keys_dir = os.path.join(path_to_persisted(), "elastic_certs")
    if not os.path.isdir(persisted_keys_dir):
        os.mkdir(persisted_keys_dir)

    dirs_for_keys.append(persisted_keys_dir)

    for container in ["elasticsearch", "filebeat", "metricbeat", "kibana"]:
        dirs_for_keys.append(os.path.join(path_to_containers(), container))

    for key_dir in dirs_for_keys:
        logger.info(f"writing new certs under {key_dir}")
        with open(os.path.join(key_dir, "ca.key"), "wb") as f:
            f.write(ca_key_bytes)

        with open(os.path.join(key_dir, "ca.crt"), "wb") as f:
            f.write(ca_cert_bytes)

        with open(os.path.join(key_dir, "instance.key"), "wb") as f:
            f.write(ins_key_bytes)

        with open(os.path.join(key_dir, "instance.crt"), "wb") as f:
            f.write(ins_cert_bytes)
