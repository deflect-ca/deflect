# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
import logging

from concurrent.futures.thread import ThreadPoolExecutor

from pyaml_env import parse_config
import traceback
import sys

from util.helpers import get_config_yml_path, get_logger

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

import random
import string

from functools import partial
from io import StringIO

# todo: use configuration for the logger
logger = get_logger(__name__, logging_level=logging.DEBUG)


# XXX probably a better way
def new_logger_and_stream():
    name = ''.join(random.choice(string.ascii_lowercase) for _ in range(16))
    log_stream = StringIO()
    log_handler = logging.StreamHandler(log_stream)
    logger = logging.getLogger(name)
    logger.addHandler(log_handler)
    logger.setLevel(logging.DEBUG)
    return logger, log_stream


# copied from https://stackoverflow.com/a/24457608
class ThreadPoolExecutorStackTraced(ThreadPoolExecutor):
    def submit(self, fn, *args, **kwargs):
        """Submits the wrapped function instead of `fn`"""

        return super(ThreadPoolExecutorStackTraced, self).submit(self._function_wrapper, fn, *args, **kwargs)

    def _function_wrapper(self, fn, *args, **kwargs):
        """Wraps `fn` in order to preserve the traceback of any kind of
        raised exception

        """
        try:
            return fn(*args, **kwargs)
        except Exception:
            # Creates an exception of the same type with the traceback as message
            raise sys.exc_info()[0](traceback.format_exc())


# XXX using functools.partial *and* a wrapper class feels complicated?...
def run_on_threadpool(h_to_fs):
    futures = {}
    with ThreadPoolExecutorStackTraced(max_workers=16) as executor:
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
    client = docker_client_for_host(edge, config=config)
    hostname = f"{client.info().get('Name')}"
    logger.debug(f"docker things this host is called {hostname}")

    Nginx(         client, config, find_existing=True, logger=logger).update(timestamp)
    Banjax(        client, config, kill_existing=True, logger=logger).update(timestamp)
    Filebeat(      client, config, find_existing=True, logger=logger).update(timestamp)
    Metricbeat(    client, config, find_existing=True, logger=logger).update(timestamp)

    logger.debug(f"$$$ finished install_all_edge_components for {edge}")


def install_controller_components(config, all_sites, timestamp, logger):
    logger.debug('Getting a Docker client...')
    client = docker_client_for_host(config['controller'], config=config)

    Bind(          client, config, find_existing=True, logger=logger).update(timestamp)

    if config['server_env'] == 'staging':
        DohProxy(      client, config, find_existing=True, logger=logger).update(timestamp)
        Pebble(        client, config, find_existing=True, logger=logger).update(timestamp)
    else:
        logger.debug('skipping DohProxy and Pebble in production')

    Certbot(       client, config, find_existing=True, logger=logger).update(all_sites, config, timestamp)
    TestOrigin(    client, config, find_existing=True, logger=logger).update(timestamp)

    if config['logging']['built_in_elk']:
        Elasticsearch( client, config, find_existing=True, logger=logger).update(timestamp)
        Kibana(        client, config, find_existing=True, logger=logger).update(timestamp)
    else:
        logger.debug('skipping Elasticsearch and Kibana for not using built_in_elk')

    if client.info()["Name"] == "docker-desktop":
        logger.debug("detected Docker Desktop, not installing controller's Nginx, Filebeat, or Metricbeat")
        return

    Filebeat(      client, config, find_existing=True, logger=logger).update(timestamp)
    Nginx(         client, config, find_existing=True, logger=logger).update(timestamp)
    Metricbeat(    client, config, find_existing=True, logger=logger).update(timestamp)


def install_everything(config, all_sites, timestamp):
    # need to install controller before we install any edges. (ES creds)
    logger.info("running install_controller_components()...")
    res = install_controller_components(config, all_sites, timestamp, logger)
    logger.info(f"install_everything host: {config['controller']}, result: {res}")

    # now we can install all the edges in parallel
    logger.info("running install_edge_components()...")
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
