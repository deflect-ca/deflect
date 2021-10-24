# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
import logging

from concurrent.futures.thread import ThreadPoolExecutor

import docker
import yaml
from pyaml_env import parse_config

from util.helpers import get_logger, get_config_yml_path, get_persisted_config_yml_path

from orchestration.run_container import (
        Bind,
        Nginx,
        Banjax,
        Filebeat,
        Metricbeat,
        DohProxy,
        Certbot,
        TestOrigin,
        Elasticsearch,
        Kibana,
        Pebble,
)

from datetime import datetime
import time
import tarfile
import io
import subprocess


# todo: use configuration for the logger
logger = get_logger(__name__, logging_level=logging.DEBUG)


def install_edge_components(edge, config, all_sites, config_timestamp):
    logger.debug(f"$$$ starting install_all_edge_components for {edge['hostname']}")
    # XXX very annoyingly you can't specify a specific ssh key here... has to be in a (the?) default
    # location OR the socket / ssh-agent thing.
    client = docker.DockerClient(base_url=f"ssh://root@{edge['ip']}")

    Nginx(         client, config, config_timestamp, find_existing=True).update(config_timestamp)
    Banjax(        client, config, config_timestamp, kill_existing=True).update(config_timestamp)
    Filebeat(      client, config, config_timestamp, find_existing=True).update(config_timestamp)
    Metricbeat(    client, config, config_timestamp, find_existing=True).update(config_timestamp)

    logger.debug(f"$$$ finished install_all_edge_components for {edge}")


def install_controller_components(config, all_sites, config_timestamp):
    logger.debug('Getting a Docker client...')
    # TODO: the base_url needs to be in a config. This is not flexible for debugging
    # TODO: or testing/ staging env
    client = docker.DockerClient(base_url=f"ssh://root@{config['controller']['ip']}")

    Bind(          client, config, config_timestamp, find_existing=True).update(config_timestamp)
    DohProxy(      client, config, config_timestamp, find_existing=True).update(config_timestamp)
    Pebble(        client, config, config_timestamp, find_existing=True).update(config_timestamp)
    # Certbot(       client, config, find_existing=True).update(all_sites, config, config_timestamp)
    TestOrigin(    client, config, config_timestamp, find_existing=True).update(config_timestamp)
    Elasticsearch( client, config, config_timestamp, find_existing=True).update(config_timestamp)
    Kibana(        client, config, config_timestamp, find_existing=True).update(config_timestamp)
    Filebeat(      client, config, config_timestamp, find_existing=True).update(config_timestamp)
    Nginx(         client, config, config_timestamp, find_existing=True).update(config_timestamp)
    Metricbeat(    client, config, config_timestamp, find_existing=True).update(config_timestamp)

def install_everything(config, all_sites, config_timestamp):
    install_controller_components(config, all_sites, config_timestamp)

    for edge in config['edges']:
        install_edge_components(edge, config, all_sites, config_timestamp)

    # XXX check future results for exceptions
    # with ThreadPoolExecutor(max_workers=16) as executor:
    #     for edge in config['edges']:
    #         executor.submit(install_all_edge_components, edge, config, all_sites, config_timestamp)

    logger.info(f"%%%% finished all edges %%%")


if __name__ == "__main__":
    config = parse_config(get_config_yml_path())
    install_everything(
        config=config,
    )
