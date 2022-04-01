# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import os
import logging
from enum import Enum
from pathlib import Path
from pyaml_env import parse_config


def get_logger(name, log_level=None, output_file='deflect-next.log'):
    """
    Creates a logger that logs to file and console with the same logging level
    :param str name: the logger name
    :param int logging_level: the logging level
    :param str output_file: the file to save to
    :return: the initialized logger
    :rtype: logger
    """
    logging_level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WANRING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    logger = logging.getLogger(name)

    if log_level:
        logging_level = logging_level_map.get(log_level, 'INFO')
        info = f"{log_level} / hard-coded"
    else:
        config = parse_config(get_config_yml_path())
        if config.get('debug', {}).get('log_level', None):
            logging_level = logging_level_map.get(config['debug']['log_level'], 'INFO')
            info = f"{config['debug']['log_level']} / global-config"
        else:
            logging_level = logging_level_map['INFO']
            info = f"INFO / no-config-default"
    logger.setLevel(logging_level)
    if not len(logger.handlers):
        file_handler = logging.FileHandler(output_file)
        console_handler = logging.StreamHandler()

        file_handler.setLevel(logging_level)
        console_handler.setLevel(logging_level)

        # create formatter and add it to the handlers
        formatter = logging.Formatter(
            '[%(levelname)s] %(asctime)s %(name)s.%(funcName)s:%(lineno)s | %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    logger.info(f"Set log level to {info}")
    return logger


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
