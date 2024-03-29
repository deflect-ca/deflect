# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
import logging
import random
import string
import sys
import traceback
from concurrent.futures.thread import ThreadPoolExecutor
from functools import partial
from io import StringIO

from pyaml_env import parse_config
from util.helpers import get_config_yml_path, get_logger

from orchestration.hosts import (docker_client_for_host,
                                 ensure_all_requirements,
                                 get_docker_engine_version)
from orchestration.run_container import (Banjax, Bind, Certbot, DohProxy,
                                         EdgeManage, Elasticsearch, Filebeat,
                                         Kibana, LegacyFilebeat, Metricbeat,
                                         Nginx, Pebble, TestOrigin, Logrotate,
                                         KafkaFilebeat)

logger = get_logger(__name__)


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
        # XXX you might break thread pool if you don't call
        # exception() / result() in the following order
        ex = future["future"].exception()
        results[hostname] = {
            "result": ex if ex else future["future"].result(),
            "error": (ex != None),
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


def install_edge_components(edge, config, all_sites, timestamp, logger, update_banjax=False):
    logger.info(f"$$$ starting install_all_edge_components for {edge['hostname']}")
    # XXX very annoyingly you can't specify a specific ssh key here... has to be in a (the?) default
    # location OR the socket / ssh-agent thing.
    client = docker_client_for_host(edge, config=config)
    hostname = f"{client.info().get('Name')}"
    logger.info(f"docker things this host is called {hostname}")

    Nginx(client, config, find_existing=True, logger=logger).update(timestamp)
    if update_banjax:
        logger.info('Update banjax mode, force restarting banjax, legacy-filebeat, kafka-filebeat and logrotate')
        Banjax(client, config, kill_existing=True, logger=logger, timestamp=timestamp).update(timestamp)
    else:
        Banjax(client, config, find_existing=True, logger=logger, timestamp=timestamp).update(timestamp)

    logger.info(f"Logging mode is: {config['logging']['mode']}")
    if config['logging']['mode'] == 'logstash_external':
        if update_banjax:
            LegacyFilebeat(client, config, kill_existing=True, logger=logger).update(timestamp)
        else:
            LegacyFilebeat(client, config, find_existing=True, logger=logger).update(timestamp)
        if config['logging'].get('extra_output_kafka'):
            if update_banjax:
                KafkaFilebeat(client, config, kill_existing=True, logger=logger).update(timestamp)
            else:
                KafkaFilebeat(client, config, find_existing=True, logger=logger).update(timestamp)
    else:
        Filebeat(      client, config, find_existing=True, logger=logger).update(timestamp)
        Metricbeat(    client, config, find_existing=True, logger=logger).update(timestamp)

    if update_banjax:
        Logrotate(client, config, kill_existing=True, logger=logger).update(timestamp)
    else:
        Logrotate(client, config, find_existing=True, logger=logger).update(timestamp)

    logger.info(f"$$$ finished install_all_edge_components for {edge}")
    return True


def install_controller_components(config, all_sites, timestamp, logger):
    logger.info('Getting a Docker client...')
    client = docker_client_for_host(config['controller'], config=config)

    Bind(          client, config, find_existing=True, logger=logger).update(timestamp)
    EdgeManage(    client, config, find_existing=True, logger=logger, timestamp=timestamp).update(timestamp)

    if config['server_env'] == 'staging':
        DohProxy(      client, config, find_existing=True, logger=logger).update(timestamp)
        Pebble(        client, config, find_existing=True, logger=logger).update(timestamp)
    else:
        logger.info('skipping DohProxy and Pebble in production')

    Certbot(       client, config, find_existing=True, logger=logger).update(all_sites, config, timestamp)
    TestOrigin(    client, config, find_existing=True, logger=logger).update(timestamp)

    if config['logging']['mode'] == 'elk_internal':
        Elasticsearch( client, config, find_existing=True, logger=logger).update(timestamp)
        Kibana(        client, config, find_existing=True, logger=logger).update(timestamp)
    else:
        logger.info('skipping Elasticsearch and Kibana for not using elk_internal')

    if client.info()["Name"] == "docker-desktop":
        logger.debug("detected Docker Desktop, not installing controller's Nginx, Filebeat, or Metricbeat")
        return

    Nginx(client, config, find_existing=True, logger=logger).update(timestamp)

    logger.info(f"Logging mode is: {config['logging']['mode']}")
    if config['logging']['mode'] == 'logstash_external':
        pass
    else:
        Filebeat(      client, config, find_existing=True, logger=logger).update(timestamp)
        Metricbeat(    client, config, find_existing=True, logger=logger).update(timestamp)
    return True


def install_controller(config, all_sites, timestamp):
    logger.info("running install_controller_components()...")
    res = install_controller_components(config, all_sites, timestamp, logger)
    logger.info(f"install_controller host: {config['controller']}, result: {res}")


def install_edges(config, edges, all_sites, timestamp, sync=False, update_banjax=False):
    """Install to edges, either in sync or parallel"""
    if sync:
        for edge in edges:
            logger.info(f"running install_edge_components() in sync on {edge['hostname']}")
            res = install_edge_components(edge, config, all_sites, timestamp, logger, update_banjax=update_banjax)
            logger.info(f"install_edge host: {edge['hostname']}, result: {res}")
        return

    # now we can install all the edges in parallel
    logger.info(f"running install_edge_components() in parallel for {len(config['edges'])} edges")
    results = run_on_threadpool({
        edge['hostname']: partial(install_edge_components, edge, config, all_sites, timestamp, update_banjax=update_banjax)
        for edge in edges
    })

    raise_error = False
    for hostname, result in results.items():
        logger.info(f"install_edges: {hostname}")
        if result['error']:
            raise_error = True
            logger.warn(f"\t Error (raise later):\n {result['result']}")
        else:
            # When there is no error, this is usually None
            logger.info(f"\t Result: {result['result']}")

        # detail runtime logs are here
        for line in result["logs"].splitlines():
            logger.info(f"\t {line}")

    if raise_error:
        raise Exception("Error installing edges in ThreadPoolExecutorStackTraced. "
                        "Raise error at end to fail CI/CD")
