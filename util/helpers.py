# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import os
import logging
import errno
from enum import Enum
from pathlib import Path
from pyaml_env import parse_config
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def get_logger(name, log_level=None):
    return __logger(log_level=log_level).get_logger()


def reset_log_level(log_level):
    return __logger().reset_log_level(log_level)


class SingletonMetaclass(type):
    """
    Singleton metaclass
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]


class __logger(metaclass=SingletonMetaclass):
    """
    Singleton logger class so we
    don't have multiple logger
    """

    logging_level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WANRING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    formatter_str = {
        'DEBUG': '[%(levelname)s] %(asctime)s %(funcName)s:%(lineno)s | %(message)s',
        # without function name for rest of the levels
        '*': '[%(levelname)s] %(asctime)s %(message)s',
    }

    def __init__(self, log_level=None, output_file='deflect-orch.log'):
        """
        Creates a logger that logs to file and console with the same logging level
        :param int logging_level: the logging level
        :param str output_file: the file to save to
        :return: the initialized logger
        """
        self.logger = logging.getLogger()
        self.log_file = output_file

        if log_level:
            logging_level = self.logging_level_map.get(log_level, 'INFO')
            info = f"{log_level} / hard-coded"
        else:
            self.config = parse_config(get_config_yml_path())

            # load log level from config or not
            if self.config.get('debug', {}).get('log_level', None):
                logging_level = self.logging_level_map.get(self.config['debug']['log_level'], 'INFO')
                info = f"{self.config['debug']['log_level']} / global-config"
            else:
                logging_level = self.logging_level_map['INFO']
                info = f"INFO / no-config-default"

            # load log path from config
            if self.config.get('debug', {}).get('orchestration_log', None):
                self.log_file = self.config['debug']['orchestration_log']

        self.logger.setLevel(logging_level)

        if not len(self.logger.handlers):
            self.file_handler = logging.FileHandler(self.log_file)
            self.console_handler = logging.StreamHandler()

            self.file_handler.setLevel(logging_level)
            self.console_handler.setLevel(logging_level)

            # create formatter and add it to the handlers
            self.set_formatter_str(logging_level)

            self.logger.addHandler(self.file_handler)
            self.logger.addHandler(self.console_handler)

        self.logger.debug(f"Logger init, set log level to {info}")

    def get_logger(self):
        return self.logger

    def reset_log_level(self, log_level):
        logging_level = self.logging_level_map.get(log_level)
        if logging_level:
            self.logger.setLevel(logging_level)
            self.file_handler.setLevel(logging_level)
            self.console_handler.setLevel(logging_level)
            self.set_formatter_str(logging_level)
            self.logger.info(f"Reset log level to {log_level}")

    def get_formatter_str(self, logging_level):
        inv_map = {v: k for k, v in self.logging_level_map.items()}
        if inv_map[logging_level] in self.formatter_str:
            return self.formatter_str.get(inv_map[logging_level])
        return self.formatter_str['*']

    def set_formatter_str(self, logging_level):
        formatter = logging.Formatter(self.get_formatter_str(logging_level))
        self.file_handler.setFormatter(formatter)
        self.console_handler.setFormatter(formatter)


def module_root_path():
    return str(Path(__file__).parent.parent)


def path_to_input():
    return os.path.join(
        module_root_path(), 'input'
    )


def path_to_output():
    return os.path.join(
        module_root_path(), 'output'
    )

def path_to_persisted():
    return os.path.join(
        module_root_path(), 'persisted'
    )

def path_to_containers():
    return os.path.join(
        module_root_path(), 'containers'
    )

def get_container_path(container_name):
    return os.path.join(path_to_containers(), container_name)

def get_container_default_config_path(container_name, config_file):
    return os.path.join(get_container_path(container_name),
                        f"default-{config_file}")

def get_config_file_path(config_file):
    return os.path.join(path_to_input(), f'config/{config_file}')

def get_sites_yml_path():
    return os.path.join(path_to_input(), 'config/old_sites.yml')

def get_system_sites_yml_path():
    return os.path.join(path_to_input(), 'config/system_sites.yml')

def get_config_yml_path():
    return os.path.join(path_to_input(), 'config/global_config.yml')

def get_persisted_config_yml_path():
    return os.path.join(path_to_persisted(), 'config.yml')

def get_banjax_config_yml_path():
    return os.path.join(path_to_input(), 'config/banjax_config.yml')

def get_kibana_saved_objects_path():
    return os.path.join(path_to_input(), 'kibana-saved-objects.ndjson')

def symlink_force(target, link_name):
    try:
        os.symlink(target, link_name)
    except OSError as e:
        if e.errno == errno.EEXIST:
            os.remove(link_name)
            os.symlink(target, link_name)
        else:
            raise e

class RoleEnum(Enum):
    edge = 'edge'
    controller = 'controller'
    testing = 'testing'
    none = ''


NAME_TO_ROLE = {
        "nginx": RoleEnum.edge,
        "bind-server": RoleEnum.controller,
        "certbot": RoleEnum.controller,
        "banjax": RoleEnum.edge,
        "origin-server": RoleEnum.none,
        "doh-proxy": RoleEnum.testing,
        "filebeat": RoleEnum.none,
        "elasticsearch": RoleEnum.none,
        "kibana": RoleEnum.none,
        "pebble": RoleEnum.testing,
}

FILENAMES_TO_TAIL = [
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/nginx/system_sites.log"
]
PEMS = ['caroot.pem', 'certificate.pem', 'key.pem']
LIST_NAME_TO_DECISION = {
   'ip_allowlist': 'allow',
   'ip_blocklist': 'block',
   'ip_challengelist': 'challenge',
}


def get_host_by_name(config, name):
    for host in [config['controller']]:
        # handle full and short name
        if host['hostname'] == name or host['hostname'].split('.')[0] == name:
            return host, True

    for host in config['edges']:
        # handle full and short name
        if host['hostname'] == name or host['hostname'].split('.')[0] == name:
            return host, False


def comma_separated_names_to_hosts(config, names):
    names = names.split(",")
    hosts = []
    has_controller = False
    for n in names:
        host, flag = get_host_by_name(config, n)
        hosts.append(host)
        has_controller = flag if flag else False
    return hosts, has_controller


def hosts_arg_to_hosts(config, hosts_arg):
    if hosts_arg == "all":
        return [config['controller']] + config['edges'], True
    elif hosts_arg == "controller":
        return [config['controller']], True
    elif hosts_arg == "edges":
        return config['edges'], False
    else:
        return comma_separated_names_to_hosts(config, hosts_arg)


def generate_selfsigned_cert(hostname, alt_name_arr=[], key=None):
    """Generates self signed certificate for a hostname, and optional IP addresses."""

    if key is None:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])

    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.
    alt_names = [x509.DNSName(hostname)]

    # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios
    if alt_name_arr:
        for a_name in alt_name_arr:
            alt_names.append(x509.DNSName(a_name))

    san = x509.SubjectAlternativeName(alt_names)

    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem


def expire_in_days(not_valid_after):
    now = datetime.utcnow()
    return (not_valid_after - now).days
