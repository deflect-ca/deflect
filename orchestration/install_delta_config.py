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

import orchestration.shared as shared
from orchestration.helpers import get_logger
from orchestration.shared import (
    find_existing_or_start_new_container, kill_containers_with_label)
from datetime import datetime
import time
import tarfile
import io
import subprocess

from orchestration import generate_bind_config, \
    generate_nginx_config, generate_banjax_next_config, \
    decrypt_and_verify_cert_bundles, cert_converter

# XXX the zero-downtime upgrade version i want to work on more later
# from start_or_upgrade_nginx_image import install_nginx_config


# todo: use configuration for the logger
logger = get_logger(__name__, logging_level=logging.DEBUG)


def kill_build_and_start_container(client, image_name, image_build_timestamp, config):
    kill_containers_with_label(client, image_name)
    (new_image, new_image_logs) = shared.build_new_image(
        image_name, client, image_build_timestamp)
    return shared.start_new_container(client, image_name, new_image, image_build_timestamp, config)


def install_bind_config(client, config, all_sites, config_timestamp, image_build_timestamp):
    logger.debug("$$$$ starting install_bind_config")
    # bind_container = kill_build_and_start_container(client, "bind-server")
    bind_container = find_existing_or_start_new_container(
        client, "bind-server", image_build_timestamp, config)
    logger.debug("have bind container")

    with open(f"output/{config_timestamp}/etc-bind.tar", "rb") as f:
        bind_container.put_archive("/etc/bind", f.read())
    bind_container.kill(signal="SIGHUP")

    logger.debug("sent new config to bind container")


def install_doh_proxy_config(client, config, all_sites, config_timestamp, image_build_timestamp):
    logger.debug("$$$$ starting install_doh_proxy_config")
    # doh_proxy_container = kill_build_and_start_container(client, "doh-proxy", image_build_timestamp)
    doh_proxy_container = find_existing_or_start_new_container(
        client, "doh-proxy", image_build_timestamp, config)
    logger.debug("started doh-proxy container")


def run_certbot_and_get_certs(client, config, all_sites, config_timestamp, image_build_timestamp):
    # certbot_container = kill_build_and_start_container(client, "certbot")
    certbot_container = find_existing_or_start_new_container(
        client, "certbot", image_build_timestamp, config)
    logger.debug("have certbot container")
    # pebble_container = kill_build_and_start_container(client, "pebble")
    pebble_container = find_existing_or_start_new_container(
        client, "pebble", image_build_timestamp, config)
    logger.debug("have pebble container")

    # XXX this is another place where certbot might try to connect to pebble before pebble
    # is accepting connections.
    # XXX should i be removing this directory? do i need to worry about
    # stale certs being here?
    (exit_code, output) = certbot_container.exec_run("rm -rf /etc/letsencrypt/archive")
    (exit_code, output) = certbot_container.exec_run("rm -rf /etc/letsencrypt/live")
    (exit_code, output) = certbot_container.exec_run("rm -rf /etc/letsencrypt/renewal")
    (exit_code, output) = certbot_container.exec_run(
        "mkdir -p /etc/letsencrypt/archive")

    with open(f"./input/certs/{config_timestamp}.tar", "rb") as f:
        certbot_container.put_archive("/etc/letsencrypt/", f.read())

    (exit_code, output) = certbot_container.exec_run(
        f"certbot register {config['production_certbot_options']} --agree-tos --non-interactive"
    )
    logger.debug(output)
    logger.debug("registered")

    # (exit_code, output) = certbot_container.exec_run(
    #     f"certbot renew {config['certbot_options']}"
    # )

    # XXX should be handled by the 'renew' command instead of doing it manually like this
    (exit_code, output) = certbot_container.exec_run(
        "ls /etc/letsencrypt/archive")
    sites_with_certs = output.decode().splitlines()

    # client_and_system_sites = {**all_sites['client'], **all_sites['system']}
    # XXX always get a real non-staging cert for sites in the system list?
    client_and_system_sites = {**all_sites['system']}

    for domain, site in client_and_system_sites.items():
        # the autodeflect-formatted ones...
        if f"{domain}.le.key" in sites_with_certs:
            continue
        # the letsencrypt / deflect-next formatted ones...
        if domain in sites_with_certs:
            continue
        logger.debug(f"trying to get a cert for {site['server_names']}")
        domains_args = "-d " + " -d ".join(site['server_names'])
        logger.debug(domains_args)
        (exit_code, output) = certbot_container.exec_run(
            f"certbot certonly {config['staging_certbot_options']} --non-interactive --agree-tos"
            # f"certbot certonly {config['production_certbot_options']} --non-interactive --agree-tos"
            f" --preferred-challenges dns --cert-name {domain}"
            " --authenticator certbot-dns-standalone:dns-standalone"
            " --certbot-dns-standalone:dns-standalone-address=127.0.0.1"
            f" --certbot-dns-standalone:dns-standalone-port=5053 {domains_args}"
        )
        logger.debug(output.decode())

    logger.debug("ran certbot certonly")

    with open(f"output/{config_timestamp}/etc-ssl-sites.tar", "wb") as tar_file:
        (chunks, stat) = certbot_container.get_archive(
            "/etc/letsencrypt/archive")
        for chunk in chunks:
            tar_file.write(chunk)

    etc_ssl_sites_tarfile_name = f"./output/{config_timestamp}/etc-ssl-sites.tar"
    # Never extract archives from untrusted sources without prior inspection. It is
    # possible that files are created outside of path, e.g. members that have
    # absolute filenames starting with "/" or filenames with two dots "..".
    with tarfile.open(etc_ssl_sites_tarfile_name, "r") as tar_file:
        tar_file.extractall(path=f"./output/{config_timestamp}/")

    # XXX might be worth it to compress this before we send it (later)
    gzip_proc = subprocess.run(["gzip", "--keep", "--force", etc_ssl_sites_tarfile_name],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if gzip_proc.returncode != 0:
        logger.debug(gzip_proc.stdout)
        logger.debug(gzip_proc.stderr)
        raise Exception("gzipping etc-ssl-sites.tar got non-zero exit code")

    # XXX put_archive() only accepts a tar, so...
    with tarfile.open(etc_ssl_sites_tarfile_name + ".gz.tar", "w") as tar_file:
        tar_file.add(etc_ssl_sites_tarfile_name + ".gz")

    logger.debug("got certs from certbot")


def install_banjax_next_config(client, config, dnet, all_sites, config_timestamp, image_build_timestamp):
    # XXX i think my config reload code needs to be more thorough, so for now i'm just restarting every time
    banjax_next_container = kill_build_and_start_container(client, "banjax-next", image_build_timestamp, config)
    # XXX building + starting this container involves downloading go dependencies, so it might
    # be a while before the program actually starts.
    # banjax_next_container = find_existing_or_start_new_container(
    #     client, "banjax-next", image_build_timestamp, config)
    logger.debug("have banjax-next container")

    with open(f"output/{config_timestamp}/etc-banjax-next.tar", "rb") as f:
        banjax_next_container.put_archive("/etc/banjax-next", f.read())

    # XXX config reload not implemented yet
    #  banjax_next_container.kill(signal="SIGHUP")

    logger.debug("Sent new config to banjax-next")


# XXX duplication from start_or_upgrade_nginx_image.py
def install_nginx_config(client, config, dnet, all_sites, config_timestamp, image_build_timestamp):
    # nginx_container = kill_build_and_start_container(client, "nginx", image_build_timestamp)
    nginx_container = find_existing_or_start_new_container(
        client, "nginx", image_build_timestamp, config)
    logger.debug("have nginx container")

    nginx_container.exec_run("rm -rf /etc/nginx")
    nginx_container.exec_run("mkdir -p /etc/nginx")

    with open(f"output/{config_timestamp}/etc-nginx-{dnet}.tar", "rb") as f:
        nginx_container.put_archive("/etc/nginx", f.read())

    # XXX should i do this? stale certs?
    nginx_container.exec_run("rm -rf /etc/ssl/sites")

    # XXX currently all the certs are on every edge. we should make it so each edge
    # only has the certs for the dnet it belongs to.
    with open(f"./output/{config_timestamp}/etc-ssl-sites.tar.gz.tar", "rb") as f:
        nginx_container.put_archive("/etc/ssl/", f.read())

    # # XXX is this right? what about the live directory?
    # nginx_container.exec_run("mv /etc/ssl/archive /etc/ssl/sites")

    nginx_container.exec_run(f"tar xzf /etc/ssl/output/{config_timestamp}/etc-ssl-sites.tar.gz --directory /etc/ssl")
    nginx_container.exec_run("mv /etc/ssl/archive /etc/ssl/sites")

    with open(f"./output/{config_timestamp}/etc-ssl-uploaded.tar", "rb") as f:
        nginx_container.put_archive("/etc/ssl-uploaded/", f.read())

    # XXX note that sending this signal does not guarantee the new config is actually loaded.
    # the config might be invalid.
    nginx_container.kill(signal="SIGHUP")

    logger.debug("installed new config + certs on nginx container")

    # >>> d["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
    # '172.17.0.5'
    resp = client.api.inspect_container(nginx_container.id)
    logger.info(
        f" !!! nginx container ip is "
        f"{resp['NetworkSettings']['Networks']['bridge']['IPAddress']}"
    )


def install_test_origin_config(client, config, all_sites, config_timestamp, image_build_timestamp):
    origin_server_container = kill_build_and_start_container(client, "origin-server", image_build_timestamp, config)
    # origin_server_container = find_existing_or_start_new_container(
    #     client, "origin-server", image_build_timestamp, config)
    logger.debug("have origin-server container")

    logger.debug("origin-server started")


# XXX eventually this function should probably be a coroutine alonside a bunch of other
# concurrent coroutines. it happens to be the first one i'm writing, so the event loop stuff looks funny.
def import_kibana_saved_objects(config):
    import aiohttp
    import asyncio

    async def main():
        async with aiohttp.ClientSession() as session:
            with open("kibana-saved-objects.ndjson", "r") as f:
                url = f"https://kibana.{config['controller_domain']}/api/saved_objects/_import?overwrite=true"
                headers = {"kbn-xsrf": "true"}
                data = aiohttp.FormData()
                data.add_field("file", f)
                async with session.post(url, data=data, headers=headers) as resp:
                    logger.debug(
                        f"posted saved objects to kibana, response: {resp.status}")
                    logger.debug(await resp.text())

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

# TODO: remove all passwords from comments or code for opensourcing - use config
# looks like:
# Changed password for user remote_monitoring_user
# PASSWORD remote_monitoring_user = ${REMOTE_MONITORING_USER}
#
# Changed password for user elastic
# PASSWORD elastic = ${ELASTICSEARCH_PASSWORD}
# etc.
# i don't like screen-scraping CLIs, but my understanding of the documentation
# is that this does a lot that would be annoying to do with the http rest api.
def get_elastic_password_from_command_output(output):
    logger.debug(output)
    lines = output.decode().splitlines()
    for line in lines:
        if line.startswith("PASSWORD elastic"):
            return line.split(" ")[-1]
    else:
        raise Exception("!!! did not find elastic password")


def install_elasticsearch_kibana(client, config, all_sites, config_timestamp, image_build_timestamp):
    kill_containers_with_label(client, "elasticsearch")
    kill_containers_with_label(client, "kibana")

    elasticsearch_container = find_existing_or_start_new_container(
        client, "elasticsearch", image_build_timestamp, config)
    print("have elasticsearch container")
    for _ in range(0, 5):
        (exit_code, output) = elasticsearch_container.exec_run(
            "elasticsearch-setup-passwords auto --batch "
            "-E 'xpack.security.transport.ssl.certificate_authorities=/usr/share/elasticsearch/config/ca.crt' "
            "-E 'xpack.security.transport.ssl.verification_mode=certificate' "
            "-E 'xpack.security.http.ssl.certificate_authorities=/usr/share/elasticsearch/config/ca.crt' "
            "-E 'xpack.security.http.ssl.verification_mode=certificate' "
        )
        try:
            elastic_password = get_elastic_password_from_command_output(output)
            break
        except:
            print("waiting for /usr/share/elasticsearch/config/elasticsearch.keystore to appear...")
            time.sleep(5)
            continue
    else:
        raise Exception("!!! did not find elastic password 5 times !!!")
    config['elastic_password'] = elastic_password  # XXX is this the best way to save it for later? (kibana, filebeat)

    kibana_container = find_existing_or_start_new_container(
        client, "kibana", image_build_timestamp, config)
    logger.debug("have kibana container")

    # XXX another place where we need to wait until kibana is actually receiving connections
    # import_kibana_saved_objects(config)


def install_filebeat(client, config, dnet, all_sites, config_timestamp, image_build_timestamp):
    # kill_containers_with_label(client, "filebeat")

    filebeat_container = find_existing_or_start_new_container(
        client, "filebeat", image_build_timestamp, config)
    logger.debug("have filebeat container")


def install_legacy_filebeat(client, config, dnet, all_sites, config_timestamp, image_build_timestamp):
    # kill_containers_with_label(client, "legacy-filebeat")

    legacy_filebeat_container = find_existing_or_start_new_container(
        client, "legacy-filebeat", image_build_timestamp, config)
    logger.debug("have legacy-filebeat container")


def install_legacy_logstash(client, config, all_sites, config_timestamp, image_build_timestamp):
    kill_containers_with_label(client, "legacy-logstash")

    legacy_logstash_container = find_existing_or_start_new_container(
        client, "legacy-logstash", image_build_timestamp, config)
    logger.debug("have legacy-logstash container")



def install_metricbeat(client, config, dnet, all_sites, config_timestamp, image_build_timestamp):
    # kill_containers_with_label(client, "metricbeat")

    metricbeat_container = find_existing_or_start_new_container(
        client, "metricbeat", image_build_timestamp, config)
    print("have metricbeat container")


def install_all_edge_components(edge_name, config, dnet, all_sites, config_timestamp, image_build_timestamp):
    logger.debug(f"$$$ starting install_all_edge_components for {edge_name}")
    edge_client = docker.DockerClient(base_url=f"ssh://{config['edge_username']}@{config['edge_names_to_ips'][edge_name]}")

    logger.debug(f'Installing nginx config')
    install_nginx_config(      edge_client, config, dnet, all_sites, config_timestamp, image_build_timestamp)
    logger.debug(f'Installing banjax next config')
    install_banjax_next_config(edge_client, config, dnet, all_sites, config_timestamp, image_build_timestamp)
    logger.debug(f'Installing filebeat')
    install_filebeat(          edge_client, config, dnet, all_sites, config_timestamp, image_build_timestamp)
    # logger.debug(f'Installing legacy filebeat')
    # install_legacy_filebeat(   edge_client, config, dnet, all_sites, config_timestamp, image_build_timestamp)
    logger.debug(f'Installing metricbeat')
    install_metricbeat(        edge_client, config, dnet, all_sites, config_timestamp, image_build_timestamp)
    logger.debug(f"$$$ finished install_all_edge_components for {edge_name}")


def main(config, all_sites, config_timestamp, image_build_timestamp, orchestration_config=None):
    # XXX should be called something else now that i'm not building new images every time
    image_build_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    logger.debug('Getting a Docker client...')
    # TODO: the base_url needs to be in a config. This is not flexible for debugging
    # TODO: or testing/ staging env
    controller_client = docker.DockerClient(base_url=f"ssh://root@{config['controller_ip']}")
    logger.debug('Installing bind config...')
    install_bind_config(controller_client, config, all_sites, config_timestamp, image_build_timestamp)
    logger.debug('Installing DOH proxy config...')
    install_doh_proxy_config(controller_client, config, all_sites, config_timestamp, image_build_timestamp)
    logger.debug('Running certbot and getting certs...')
    run_certbot_and_get_certs(controller_client, config, all_sites, config_timestamp, image_build_timestamp)
    logger.debug('Installing test origin config...')
    install_test_origin_config(controller_client, config, all_sites, config_timestamp, image_build_timestamp)

    # TODO: fixme use a config for this
    elastic = orchestration_config.get('elastic') if orchestration_config else None
    if elastic:
        config['elastic_password'] = elastic['password']
    else:
        raise ValueError('Could not find elastic configuration')

    # install_elasticsearch_kibana(controller_client, config, all_sites, config_timestamp, image_build_timestamp)
    # install_filebeat(controller_client, config, "controller", all_sites, config_timestamp, image_build_timestamp)
    # install_legacy_logstash(controller_client, config, all_sites, config_timestamp, image_build_timestamp)
    # install_metricbeat(controller_client, config, "controller", all_sites, config_timestamp, image_build_timestamp)
    # install_nginx_config(controller_client, config, "controller", all_sites, config_timestamp, image_build_timestamp)

    # TODO: fixme use a config for this - is there a reason for duplication?
    config['elastic_password'] = elastic['password']

    for dnet, edge_names in config['dnets_to_edges'].items():
        if dnet == "controller":
            continue
        for edge_name in edge_names:
            install_all_edge_components(edge_name, config, dnet, all_sites, config_timestamp, image_build_timestamp)

    # XXX check future results for exceptions
    # with ThreadPoolExecutor(max_workers=16) as executor:
    #     for dnet, edge_names in config['dnets_to_edges'].items():
    #         if dnet == "controller":
    #             continue
    #         for edge_name in edge_names:
    #             executor.submit(install_all_edge_components, edge_name, config, dnet, all_sites, config_timestamp, image_build_timestamp)

    logger.info(f"%%%% finished all edges %%%")


def install_delta_config(config=None, orchestration_config=None):
    # TODO: moved these for convenience
    # TODO: configurable paths - would be more easy for deployment
    logger.info('Getting all sites from config...')
    all_sites, formatted_time = shared.get_all_sites()

    # XXX maybe reconsider this all_sites = {'client': ..., 'system': ... } pattern.
    # generate_bind_config() treats both roles identically (flattens the dict).
    # generate_nginx_config() has its own treatment of kibana and doh (doesn't use the system sites list).
    # the rest only care about client sites.
    logger.info('>>> Running decrypt_and_verify_cert_bundlesg...')
    decrypt_and_verify_cert_bundles.main(all_sites, formatted_time)
    logger.info('>>> Cert Converter...')
    cert_converter.main(formatted_time)
    logger.info('>>> Generating bind config...')
    generate_bind_config.main(config, all_sites, formatted_time)
    logger.info('>>> Generating nginx config...')
    generate_nginx_config.main(all_sites, config, formatted_time)
    logger.info('>>> Generating banjax-next config...')
    generate_banjax_next_config.main(config, all_sites, formatted_time)

    main(
        config,
        all_sites,
        formatted_time,
        formatted_time,
        orchestration_config=orchestration_config
    )


if __name__ == "__main__":
    orchestration_config = parse_config('input/deflect-next_config.yaml')
    config = parse_config('input/current/config.yml')
    install_delta_config(
        config=config,
        orchestration_config=orchestration_config
    )
