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
from orchestration.hosts import (
        get_docker_engine_version,
        docker_client_for_host,
        ensure_all_requirements,
)

from datetime import datetime
import time
import tarfile
import io
import subprocess
import random
import string

from functools import partial

# todo: use configuration for the logger
logger = get_logger(__name__, logging_level=logging.DEBUG)

from io import StringIO


# XXX probably a better way
def new_logger_and_stream():
    name = ''.join(random.choice(string.ascii_lowercase) for _ in range(16))
    log_stream = StringIO()
    log_handler = logging.StreamHandler(log_stream)
    logger = logging.getLogger(name)
    logger.addHandler(log_handler)
    logger.setLevel(logging.DEBUG)
    return logger, log_stream


def run_on_threadpool(h_to_fs):
    futures = {}
    with ThreadPoolExecutor(max_workers=16) as executor:
        for hostname, func in h_to_fs.items():
            logger, log_stream = new_logger_and_stream()
            futures[hostname] = {
                    'future': executor.submit(func, logger=logger),
                    'log_stream': log_stream
            }

    results = {}
    for hostname, future in futures.items():
        result = future["future"].exception()
        if not result:
            result = future["future"].result()
        results[hostname] = {
                "result": result,
                "logs": future["log_stream"].getvalue()
        }

    return results


def gather_info(config, hosts):
    results = run_on_threadpool({
            host['hostname']: partial(get_docker_engine_version, config, host)
            for host in hosts
    })

    for hostname, result in results.items():
        logger.info(f"host: {hostname}, docker version: {result['result']}")
        for line in result["logs"].splitlines():
            logger.info(f"\t {line}")


def install_base(config, hosts, logger):
    logger.info(f"running ensure_all_requirements on {hosts}")
    results = run_on_threadpool({
            host['hostname']: partial(ensure_all_requirements, config, host)
            for host in hosts
    })

    for hostname, result in results.items():
        logger.info(f"host: {hostname}, ensure_all_requirements result: {result['result']}")
        for line in result["logs"].splitlines():
            logger.info(f"\t {line}")



def install_edge_components(edge, config, all_sites, timestamp, logger):
    logger.debug(f"$$$ starting install_all_edge_components for {edge['hostname']}")
    # XXX very annoyingly you can't specify a specific ssh key here... has to be in a (the?) default
    # location OR the socket / ssh-agent thing.
    client = docker_client_for_host(edge)
    hostname = f"{client.info().get('Name')}"
    logger.debug(f"docker things this host is called {hostname}")

    Nginx(         client, config, find_existing=True, logger=logger).update(timestamp)
    Banjax(        client, config, kill_existing=True, logger=logger).update(timestamp)
    Filebeat(      client, config, find_existing=True, logger=logger).update(timestamp)
    Metricbeat(    client, config, find_existing=True, logger=logger).update(timestamp)

    logger.debug(f"$$$ finished install_all_edge_components for {edge}")


def install_controller_components(config, all_sites, timestamp, logger):
    logger.debug('Getting a Docker client...')
    client = docker_client_for_host(config['controller'])

    Bind(          client, config, find_existing=True, logger=logger).update(timestamp)
    DohProxy(      client, config, find_existing=True, logger=logger).update(timestamp)
    Pebble(        client, config, find_existing=True, logger=logger).update(timestamp)
    Certbot(       client, config, find_existing=True, logger=logger).update(all_sites, config, timestamp)
    TestOrigin(    client, config, find_existing=True, logger=logger).update(timestamp)
    Elasticsearch( client, config, find_existing=True, logger=logger).update(timestamp)
    Kibana(        client, config, find_existing=True, logger=logger).update(timestamp)
    Filebeat(      client, config, find_existing=True, logger=logger).update(timestamp)
    Nginx(         client, config, find_existing=True, logger=logger).update(timestamp)
    Metricbeat(    client, config, find_existing=True, logger=logger).update(timestamp)


def install_everything(config, all_sites, timestamp):
    # need to install controller before we install any edges. (ES creds)
    logger.info(f"running install_controller_components()...")
    temp_logger, log_stream = new_logger_and_stream()
    res = install_controller_components(config, all_sites, timestamp, temp_logger)

    logger.info(f"install_everything host: {config['controller']}, result: {res}")
    for line in log_stream.getvalue().splitlines():
        logger.info(f"\t {line}")

    # now we can install all the edges in parallel
    logger.info(f"running install_edge_components()...")
    results = run_on_threadpool({
            edge['hostname']: partial(install_edge_components, edge, config, all_sites, timestamp)
            for edge in config['edges']
    })

    for hostname, result in results.items():
        logger.info(f"host: {hostname}, install_edge_components result: {result['result']}")
        for line in result["logs"].splitlines():
            logger.info(f"\t {line}")


if __name__ == "__main__":
    config = parse_config(get_config_yml_path())
    install_everything(
        config=config,
    )
