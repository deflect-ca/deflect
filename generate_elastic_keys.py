# https://gist.github.com/major/8ac9f98ae8b07f46b208
# https://cryptography.io/en/latest/x509/reference/
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

def gen_key_and_cert(name, issuer_name, is_ca):
	priv_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
	)

	pub_key = priv_key.public_key()

	builder = x509.CertificateBuilder()

	builder = builder.subject_name(x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, name),
	]))

	builder = builder.issuer_name(x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
	]))

	one_day = datetime.timedelta(1, 0, 0)
	one_year = datetime.timedelta(0, 0, 1)

	builder = builder.not_valid_before(datetime.datetime.today() - one_day)
	builder = builder.not_valid_after(datetime.datetime.today() + one_year)

	builder = builder.serial_number(x509.random_serial_number())
	builder = builder.public_key(pub_key)

	builder = builder.add_extension(
		x509.SubjectAlternativeName(
			[x509.DNSName(name)]
		),
		critical=False
	)

	builder = builder.add_extension(
		x509.BasicConstraints(ca=is_ca, path_length=None), critical=True,
	)
	return priv_key, builder

def sign_cert_with_key(cert, key):
	return cert.sign(private_key=key, algorithm=hashes.SHA256())

ca_key, ca_cert_uns = gen_key_and_cert("my ca", "my ca", True)
ca_cert = sign_cert_with_key(ca_cert_uns, ca_key)

ins_key, ins_cert_uns = gen_key_and_cert("controller.dflct.xyz", "my ca", False)
ins_cert = sign_cert_with_key(ins_cert_uns, ca_key)

with open("persisted/elastic2/ca.key", "wb") as f:
    f.write(ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))

with open("persisted/elastic2/ca.crt", "wb") as f:
    f.write(ca_cert.public_bytes(
        encoding=serialization.Encoding.PEM,
    ))

with open("persisted/elastic2/instance.key", "wb") as f:
    f.write(ins_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))

with open("persisted/elastic2/instance.crt", "wb") as f:
    f.write(ins_cert.public_bytes(
        encoding=serialization.Encoding.PEM,
    ))
