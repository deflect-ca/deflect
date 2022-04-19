# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.


import logging
import os
import shutil
import gnupg
import certifi
import tarfile

from cryptography.hazmat.primitives import serialization

from itertools import accumulate

import pem
from OpenSSL.crypto import load_certificate, dump_certificate
from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import X509Store, X509StoreContext
from OpenSSL.crypto import X509StoreContextError

from util.helpers import get_logger, FILENAMES_TO_TAIL, path_to_output


# todo: use configuration for the logger
from pyaml_env import parse_config

from util.helpers import get_logger, get_config_yml_path

logger = get_logger(__name__)


def read_encrypted_file(filename):
    """
    Reads an encrypted file and returns decrypted bytes
    """
    gpg_home = os.getcwd() + "/.gnupg"
    logger.debug(gpg_home)
    gpg = gnupg.GPG(gnupghome=gpg_home)  # XXX

    dec_bytes = []
    with open(filename, "rb") as f:
        enc_bytes = f.read()
        dec_bytes = gpg.decrypt(enc_bytes).data

    return dec_bytes


def load_encrypted_cert(filename):
    """
    Reads and loads an encrypted cert
    """
    cert_bytes = read_encrypted_file(filename)
    try:
        cert = load_certificate(FILETYPE_PEM, cert_bytes)
    except:
        import traceback
        traceback.print_exc()
        logger.debug(cert_bytes)
        raise

    return cert, cert_bytes


def load_encrypted_key(filename):
    key_bytes = read_encrypted_file(filename)
    # XXX the 'cryptography' module is better than the 'OpenSSL' module here...
    key = serialization.load_pem_private_key(key_bytes, password=None)
    return key, key_bytes


def serialize_public_key(public_key):
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )


def validate_private_key_matches_leaf_cert(private_key, leaf_cert):
    # XXX switching between the pyopenssl and pyca keys is annoying
    if serialize_public_key(leaf_cert.get_pubkey().to_cryptography_key()) != \
            serialize_public_key(private_key.public_key()):
        return [f"key does not match the one in the certificate"]
    return []


def get_subject_and_alt_names(leaf_cert):
    subject_names = [dict(leaf_cert.get_subject().get_components())[
        b'CN'].decode()]

    alt_names = []
    for i in range(leaf_cert.get_extension_count()):
        extension = leaf_cert.get_extension(i)
        if extension.get_short_name() == b'subjectAltName':
            alt_name_string = extension._subjectAltNameString()
            # "DNS:example.com, DNS:www.example.com"
            alt_names = [x.split("DNS:")[1]
                         for x in alt_name_string.split(", ")]
            # XXX "If multiple entries are processed for the same extension name,
            # later entries override earlier ones with the same name." (google this)

    return subject_names, alt_names


def is_wildcard_match(site, subject_names, alt_names):
    # "a.b.c.d" => ['d', 'c.d', 'b.c.d']
    parent_zones = list(accumulate(
        reversed(site.split(".")),
        lambda x, y: ".".join([y, x])
    ))[:-1]

    # print(f"\tPARENT zones: {parent_zones}")
    # ['d', 'c.d', 'b.c.d'] => ['*.d', '*.c.d', '*.b.c.d']
    wildcard_parent_names = [f"*.{x}" for x in parent_zones]

    wildcard_matches = set(wildcard_parent_names) & set(
        subject_names + alt_names)
    if len(wildcard_matches) > 0:
        logger.info(f"\t{site} has a matching wildcard certificate")
        return True
    else:
        logger.error(
            f"\tNO WILDCARD MATCHES FOR {site}: {wildcard_parent_names}, {subject_names + alt_names}")
        return False


def validate_exact_or_wildcard_match(site, subject_names, alt_names):
    errors = []
    if site in subject_names + alt_names:
        logger.info(f"\t{site} has a matching certificate")
    elif is_wildcard_match(site, subject_names, alt_names):
        logger.info(f"\t{site} has a matching wildcard certificate")
    else:
        logger.error(f"\t{site} does not have a matching certificate")
        errors += [f"cert doesn't match site"]
    return errors


def load_chain_certs(filename):
    errors = []
    chain_certs = []
    try:
        chain, chain_bytes = load_encrypted_cert(
            f"input/config/tls_bundles/{filename}.chain.crt.gpg")

        for pem_cert in pem.parse(chain_bytes):
            try:
                chain_cert = load_certificate(FILETYPE_PEM, str(pem_cert))
            except Exception as e:
                # TODO: ???
                logger.error(
                    f"\tsite: {site}-{timestamp} NOT valid, bad cert in chain file: {e}")
                errors.append(f"bad cert in chain file")
            else:
                chain_certs.append(chain_cert)
    except FileNotFoundError:
        logger.debug(f'File {filename} not found, ignoring')

    return errors, chain_certs


def validate_leaf_cert_against_root_with_intermediates(leaf_cert, chain_certs):
    errors = []
    store = X509Store()
    for root_cert_pem in pem.parse_file(certifi.where()):
        store.add_cert(load_certificate(FILETYPE_PEM, str(root_cert_pem)))

    try:
        store_context = X509StoreContext(store, leaf_cert, chain_certs)
        store_context.verify_certificate()
    except X509StoreContextError as err:
        logger.warning(f"\tverification failed!: {err}")
        errors.append(f"cert chain verification failed: {err}")
    else:
        logger.info("\tverification succeeded")
    return errors


# XXX formatted_timestamp is the version inside sites.yml
def one_site(site, bundle_name, formatted_time):
    errors = []
    # TODO: remove test.me.uk etc when opensourcing
    filename = f"{site}-{bundle_name}".replace(".test.me.uk", "")  # XXX
    logger.info(f"doing {filename}")

    leaf_cert, cert_bytes = load_encrypted_cert(
        f"input/config/tls_bundles/{filename}.cert.crt.gpg")

    private_key, private_key_bytes = load_encrypted_key(
        f"input/config/tls_bundles/{filename}.key.gpg")

    errors += validate_private_key_matches_leaf_cert(private_key, leaf_cert)

    subject_names, alt_names = get_subject_and_alt_names(leaf_cert)

    errors += validate_exact_or_wildcard_match(site, subject_names, alt_names)

    _errors, chain_certs = load_chain_certs(filename)
    errors += _errors

    # XXX really i just wanted to validate the leaf cert against an optional chain
    # of intermediate certs, but there wasn't a clean way to do only that. i'm
    # using the certifi package's cert bundle as the root.
    errors += validate_leaf_cert_against_root_with_intermediates(
        leaf_cert, chain_certs)

    logger.error(f"\t-- {site} errors: {errors}")

    with open(f"./output/{formatted_time}/etc-ssl-uploaded/{site}.cert-and-chain", "wb") as f:
        f.write(dump_certificate(FILETYPE_PEM, leaf_cert))
        for chain_cert in chain_certs:
            f.write(dump_certificate(FILETYPE_PEM, chain_cert))

    with open(f"./output/{formatted_time}/etc-ssl-uploaded/{site}.key", "wb") as f:
        f.write(private_key_bytes)


def main(all_sites, formatted_time):
    # XXX don't delete old stuff, just move symlinks around
    output_dir = f"{path_to_output()}/{formatted_time}/etc-ssl-uploaded"
    output_dir_tar = f"{output_dir}.tar"
    if len(output_dir) == 0: # TODO fixme: did we mean to check if path exists?
        # XXX ...clearly i changed something here
        raise Exception("output_dir cannot be empty")
    if os.path.isdir(output_dir):
        logger.debug(f'Removing output_dir: {output_dir}')
        shutil.rmtree(f"{output_dir}")
    os.mkdir(output_dir)

    for name, site in all_sites['client'].items():
        logger.debug(f'Processing name, site: {name, site}')
        uploaded_cert_bundle_name = site.get("uploaded_cert_bundle_name")
        if uploaded_cert_bundle_name:
            try:
                one_site(
                    name, uploaded_cert_bundle_name, formatted_time
                )
            except FileNotFoundError:
                logger.error(
                    f"!!! BAD uploaded cert bundle not found for site {name}"
                )
                pass

    if os.path.isfile(output_dir_tar):
        logger.debug(f'Removing output_dir_tar: {output_dir_tar}')
        os.remove(output_dir_tar)

    with tarfile.open(output_dir_tar, "x") as tar:
        tar.add(output_dir, arcname=".")


if __name__ == "__main__":
    from config_generation.site_dict import get_all_sites
    config = parse_config(get_config_yml_path())

    all_sites, formatted_time = get_all_sites(config)

    main(all_sites, formatted_time)
