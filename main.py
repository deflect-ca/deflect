# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

from pyaml_env import parse_config

from config_generation.site_dict import get_all_sites

import argparse
import os

from config_generation import (
    generate_bind_config,
    generate_nginx_config,
    generate_banjax_config,
    generate_edgemanage_config,
    generate_legacy_filebeat_config,
)
from config_generation.generate_elastic_keys import generate_new_elastic_certs

from orchestration.everything import (
        install_everything,
        install_controller,
        install_edges,
        gather_info,
        install_base,
)
from orchestration.run_container.base_class import find_existing_container
from orchestration.run_container.base_class import get_persisted_config

from orchestration.run_container.elasticsearch import Elasticsearch, attempt_to_authenticate
from orchestration.run_container.banjax import Banjax
from orchestration.hosts import docker_client_for_host, run_local_or_remote_noraise, host_to_role

import logging
from util.helpers import get_logger, get_config_yml_path, path_to_output
from util.fetch_site_yml import fetch_site_yml
from util.decrypt_and_verify_cert_bundles import main as decrypt_and_verify_cert_bundles
logger = get_logger(__name__, logging_level=logging.DEBUG)


def get_host_by_name(config, name):
    for host in [config['controller']] + config['edges']:
        if host['hostname'] == name:
            return host


def comma_separated_names_to_hosts(config, names):
    names = names.split(",")
    return [get_host_by_name(n) for n in names]


def hosts_arg_to_hosts(config, hosts_arg):
    if hosts_arg == "all":
        return [config['controller']] + config['edges']
    elif hosts_arg == "controller":
        return [config['controller']]
    elif hosts_arg == "edges":
        return config['edges']
    else:
        return comma_separated_names_to_hosts(config, hosts_arg)


def gen_config(config, all_sites, timestamp):
    logger.info('>>> Generating bind config...')
    generate_bind_config(config, all_sites, timestamp)

    logger.info('>>> Generating nginx config...')
    generate_nginx_config(all_sites, config, timestamp)

    logger.info('>>> Generating banjax-next config...')
    generate_banjax_config(config, all_sites, timestamp)

    logger.info('>>> Generating edgemanage config...')
    generate_edgemanage_config(config, all_sites, timestamp)

    if config['logging']['mode'] == 'logstash_external':
        logger.info('>>> Generating legacy-filebeat config...')
        generate_legacy_filebeat_config(config, all_sites, timestamp)


if __name__ == '__main__':
    # todo: many things to be fleshed out to deflect-next config
    config = parse_config(get_config_yml_path())

    argparser = argparse.ArgumentParser()

    argparser.add_argument(
        "--hosts", dest="hosts_arg", default="all",
        help="comma-separated hostnames OR 'controller' OR 'edges' OR 'all'"
    )
    argparser.add_argument(
        "-a", "--action", dest="action", required=True,
        choices=[
            "info",
            "install-base",
            "gen-config",
            "install-config",
            "install-controller",
            "install-edges",
            "test-es-auth",
            "install-es",
            "install-banjax",
            "kill-all-containers",
            "gen-new-elastic-certs",
            "get-nginx-errors",
            "show-useful-curl-commands",
            "get-banjax-decision-lists",
            "get-banjax-rate-limit-states",
            "get-nginx-and-banjax-config-versions",
            "check-cert-expiry",
            "fetch-site-yml",
            "decrypt_and_verify_cert_bundles"
        ],
        help="what to do to the hosts"
    )

    args = argparser.parse_args()

    hosts = hosts_arg_to_hosts(config, args.hosts_arg)

    if args.action == "info":
        gather_info(config, hosts)

    elif args.action == "install-base":
        install_base(config, hosts, logger)

    elif args.action == "gen-config":
        all_sites, timestamp = get_all_sites(config)
        gen_config(config, all_sites, timestamp)

    elif args.action == "install-config":
        all_sites, timestamp = get_all_sites(config)
        install_everything(config, all_sites, timestamp)

    elif args.action == "install-controller":
        all_sites, timestamp = get_all_sites(config)
        install_controller(config, all_sites, timestamp)

    elif args.action == "install-edges":
        all_sites, timestamp = get_all_sites(config)
        install_edges(config, all_sites, timestamp)

    elif args.action == "install-es":
        all_sites, timestamp = get_all_sites(config)
        client = docker_client_for_host(config['controller'], config=config)
        es = Elasticsearch(client, config, find_existing=True, logger=logger)
        es.update(timestamp)

    elif args.action == "install-banjax":
        all_sites, timestamp = get_all_sites(config)
        for host in hosts:
            client = docker_client_for_host(host, config=config)
            banjax = Banjax(client, config, kill_existing=True, logger=logger)
            banjax.update(timestamp)

    elif args.action == "test-es-auth":
        attempt_to_authenticate(config['controller']['ip'], logger)

    elif args.action == "kill-all-containers":
        command = "docker kill $(docker ps -q)"
        for host in hosts:
            proc = run_local_or_remote_noraise(config, host, command, logger)

    elif args.action == "gen-new-elastic-certs":
        generate_new_elastic_certs(config, logger)

    elif args.action == "get-nginx-errors":
        for host in hosts:
            client = docker_client_for_host(host, config=config)
            extra_label = "ngx_log_file=error-log"
            container = find_existing_container(client, "nginx-log-tailer", extra_label, config, logger)
            if not container:
                logger.info(f"===== nginx error log tailer not found on {host['hostname']}")
                continue

            logger.info(f"===== nginx error logs from {host['hostname']} =====")
            for line in container.logs().splitlines():
                logger.info(f"\t {line.decode()}")

    elif args.action == "show-useful-curl-commands":
        p_conf = get_persisted_config()
        elastic_password = p_conf.get('elastic_password', "<doesn't exist yet>")

        print("# test the ES certs + creds:\n"
              f"curl -v --resolve {config['controller']['hostname']}:9200:{config['controller']['ip']} --cacert persisted/elastic_certs/ca.crt https://{config['controller']['hostname']}:9200 --user 'elastic:{elastic_password}'")

        print("\n# test a site through a specific edge:")
        for edge in config['edges']:
            print(f"curl --resolve test-origin.{config['system_root_zone']}:443:{edge['ip']} --cacert persisted/pebble_ca.crt https://test-origin.{config['system_root_zone']}")
        for edge in config['edges']:
            print(f"curl -vI --resolve example.com:443:{edge['ip']} --cacert persisted/pebble_ca.crt https://example.com")

    # XXX duplication
    elif args.action == "get-banjax-decision-lists":
        logger.setLevel(logging.INFO)
        command = "curl --silent --header 'Host: banjax' 127.0.0.1/decision_lists"
        for host in hosts:
            if host_to_role(config, host) == "controller":
                continue  # controller doesn't have banjax

            proc = run_local_or_remote_noraise(config, host, command, logger)

            logger.info(f"===== decision lists on {host['hostname']}")
            for line in proc.stdout.decode().splitlines():
                print(line)

    # XXX duplication
    elif args.action == "get-banjax-rate-limit-states":
        logger.setLevel(logging.INFO)
        command = "curl --silent --header 'Host: banjax' 127.0.0.1/rate_limit_states"
        for host in hosts:
            if host_to_role(config, host) == "controller":
                continue  # controller doesn't have banjax

            proc = run_local_or_remote_noraise(config, host, command, logger)

            logger.info(f"===== rate limit states on {host['hostname']}")
            for line in proc.stdout.decode().splitlines():
                print(line)

    # XXX duplication
    elif args.action == "get-nginx-and-banjax-config-versions":
        logger.setLevel(logging.INFO)
        # XXX this should require a good host header like the banjax one does
        nginx_command = "curl --silent 127.0.0.1/info"
        banjax_command = "curl --silent --header 'Host: banjax' 127.0.0.1/info"
        nginx_proc, banjax_proc = None, None
        for host in hosts:
            nginx_proc = run_local_or_remote_noraise(config, host, nginx_command, logger)
            if host_to_role(config, host) == "edge":
                banjax_proc = run_local_or_remote_noraise(config, host, banjax_command, logger)

            logger.info(f"===== nginx and banjax versions on {host['hostname']}")
            for line in nginx_proc.stdout.decode().splitlines():
                print(f"\t nginx: {line}")
            if banjax_proc:
                for line in banjax_proc.stdout.decode().splitlines():
                    print(f"\t banjax: {line}")

    elif args.action == "check-cert-expiry":
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        all_sites, timestamp = get_all_sites(config)
        # flatten...
        sites = {**all_sites['client'], **all_sites['system']}

        latest_cert_dir = os.path.join(path_to_output(), timestamp, "archive")
        for hostname, site in sites.items():
            site_dir = os.path.join(latest_cert_dir, hostname)
            if not os.path.isdir(site_dir):
                logger.info(f"site: {hostname} not found under output/archive")
                continue
            cert_bytes = None
            with open(os.path.join(site_dir, "cert1.pem"), "rb") as f:
                cert_bytes = f.read()
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            logger.info(f"subject: {cert.subject}, issuer: {cert.issuer}, expires: {cert.not_valid_after}")

    elif args.action == "fetch-site-yml":
        fetch_site_yml(config['fetch_site_yml'], logger)

    elif args.action == "decrypt_and_verify_cert_bundles":
        all_sites, timestamp = get_all_sites(config)
        decrypt_and_verify_cert_bundles(all_sites, timestamp)
