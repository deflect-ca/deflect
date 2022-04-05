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


def get_logger(name, log_level=None):
    return __logger(log_level=log_level).get_logger()


def reset_log_level(log_level):
    return __logger().reset_log_level(log_level)


class __singleton(type):
    """
    Singleton metaclass
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        # return instance so we can call Monitor().set()
        return cls._instances[cls]


class __logger(metaclass=__singleton):
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

    def __init__(self, log_level=None, output_file='deflect-next.log'):
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
            if self.config.get('debug', {}).get('log_level', None):
                logging_level = self.logging_level_map.get(self.config['debug']['log_level'], 'INFO')
                info = f"{self.config['debug']['log_level']} / global-config"
            else:
                logging_level = self.logging_level_map['INFO']
                info = f"INFO / no-config-default"

            if self.config.get('debug', {}).get('orchestration_log', None):
                self.log_file = self.config['debug']['orchestration_log']

        self.logger.setLevel(logging_level)

        if not len(self.logger.handlers):
            self.file_handler = logging.FileHandler(self.log_file)
            self.console_handler = logging.StreamHandler()

            self.file_handler.setLevel(logging_level)
            self.console_handler.setLevel(logging_level)

            # create formatter and add it to the handlers
            formatter = logging.Formatter(
                '[%(levelname)s] %(asctime)s %(funcName)s:%(lineno)s | %(message)s')
            self.file_handler.setFormatter(formatter)
            self.console_handler.setFormatter(formatter)

            self.logger.addHandler(self.file_handler)
            self.logger.addHandler(self.console_handler)

        self.logger.info(f"Logger init, set log level to {info}")

    def get_logger(self):
        return self.logger

    def reset_log_level(self, log_level):
        logging_level = self.logging_level_map.get(log_level)
        if logging_level:
            self.logger.setLevel(logging_level)
            self.file_handler.setLevel(logging_level)
            self.console_handler.setLevel(logging_level)
            self.logger.info(f"Reset log level to {log_level}")


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
