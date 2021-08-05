# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
import logging

import docker
import time
from datetime import datetime
import shared
import requests

from orchestration.helpers import get_logger

EDGE_IP = "0.0.0.0"
# EDGE_IP="127.0.0.1"
# todo: use configuration for the logger
logger = get_logger(__name__, logging_level=logging.DEBUG)


def install_nginx_config(client, config, all_sites, config_timestamp, image_build_timestamp):
    print(f"building and tagging {image_build_timestamp}")
    (nginx_image, nginx_image_logs) = shared.build_new_image(
        "nginx", client, image_build_timestamp)

    print(f"built and tagged {image_build_timestamp}, now running it")
    new_nginx_container = shared.start_new_nginx_container(
        client, nginx_image.id, image_build_timestamp)

    print(f"started {image_build_timestamp}")

    new_nginx_container.exec_run("rm -rf /etc/nginx")

    new_etc_nginx_bytes = open(
        f"./output/{config_timestamp}/etc-nginx.tar", "rb").read()
    new_nginx_container.put_archive("/etc/nginx", new_etc_nginx_bytes)

    new_etc_ssl_sites_bytes = open(
        f"./output/{config_timestamp}/etc-ssl-sites.tar", "rb").read()
    new_nginx_container.put_archive("/etc/ssl/", new_etc_ssl_sites_bytes)

    new_etc_ssl_uploaded_sites_bytes = open(
        f"./output/{config_timestamp}/etc-ssl-uploaded.tar", "rb").read()
    new_nginx_container.put_archive(
        "/etc/ssl-uploaded/", new_etc_ssl_uploaded_sites_bytes)

    # XXX what is this
    new_nginx_container.exec_run("rm -rf /etc/ssl/sites")  # XXX volumes
    new_nginx_container.exec_run("mv /etc/ssl/archive /etc/ssl/sites")

    # XXX note that sending this signal does not guarantee the new config is actually loaded.
    # the config might be invalid.
    new_nginx_container.kill(signal="SIGHUP")

    print("installed new config + certs on nginx container")

    new_nginx_container.reload()  # ask daemon again for the current attributes
    new_nginx_container_ports = new_nginx_container.attrs['NetworkSettings']['Ports']
    print(new_nginx_container_ports)
    # {'443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '32769'}], '80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '32770'}]}
    new_private_https_ports = new_nginx_container_ports["443/tcp"]
    new_private_http_ports = new_nginx_container_ports["80/tcp"]

    if (len(new_private_https_ports) != 1) or (len(new_private_http_ports) != 1):
        print(
            f"XXX unexpected! more than one host port mapping: {new_nginx_container_ports}")

    new_private_https_port = new_private_https_ports[0]['HostPort']
    new_private_http_port = new_private_http_ports[0]['HostPort']

    def try_http_request_on_port(port):
        try:
            hs = {'Host': "nginx"}
            r = requests.get(
                f"http://{EDGE_IP}:{new_private_http_port}/stub_status", timeout=5, headers=hs)
        except requests.exceptions.ConnectionError as e:
            print(f"could not connect over port {new_private_http_port}!")
            print(e)
        except requests.exceptions.Timeout as e:
            print(f"timed out connecting over port {new_private_http_port}!")
            print(e)
        else:
            if r.status_code == 200:
                print(f"got an HTTP 200 over port {new_private_http_port}")
            else:
                print(
                    f"connected but got HTTP {r.status_code} over port {new_private_http_port}")

    time.sleep(2)
    try_http_request_on_port(new_private_http_port)

    print(f"building and tagging nat manager image")
    (nat_manager_image, nat_manager_logs) = client.images.build(
        path="../../../containers/edge/nat-manager",
        tag=f"deflect-nat-manager-{image_build_timestamp}"
    )

    print(
        f"built and tagged nat manager {image_build_timestamp}, now running it")
    nat_manager_logs = client.containers.run(
        nat_manager_image.id,
        command=["/usr/bin/python3", "map_port.py", "--public-port",
                 "80", "--add-private-port", new_private_http_port],
        detach=False,
        network="host",
        cap_add=["NET_ADMIN"]
    )
    # XXX
    nat_manager_logs = client.containers.run(
        nat_manager_image.id,
        command=["/usr/bin/python3", "map_port.py", "--public-port",
                 "443", "--add-private-port", new_private_https_port],
        detach=False,
        network="host",
        cap_add=["NET_ADMIN"]
    )
    print(nat_manager_logs.decode())

    # this won't work from macos
    # try_http_request_on_port(80)

    while True:
        running_nginx_containers = client.containers.list(
            filters={'label': 'name=nginx'}
        )
        print(
            f"there are now {len(running_nginx_containers)} total running nginx containers")
        if len(running_nginx_containers) < 1:
            print(f"and that's not enough! bad!")
            break
        if len(running_nginx_containers) == 1:
            print(f"good. finishing.")
            break

        print(f"now looping over all the containers to remove old and inactive ones")
        for container in running_nginx_containers:
            if container.attrs['Config']['Labels']['version'] == image_build_timestamp:
                print("found the container we just started, leaving it alone")
                continue
            print("found a previously-running container")
            ports = container.attrs['NetworkSettings']['Ports']
            print(ports)
            # XXX this was an empty dict once
            # {'443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '32769'}], '80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '32770'}]}
            # XXX i think i get an empty dict here if i kill the container in a shell around here. so i should catch that
            # exception here and just kill the thing if it's not already dead.
            try:
                https_ports = ports["443/tcp"]
                http_ports = ports["80/tcp"]
            except KeyError:
                continue  # XXX maybe try again? container probably gone from the list next time around

            if (len(https_ports) != 1) or (len(http_ports) != 1):
                print(
                    f"XXX unexpected! more than one host port mapping: {new_nginx_container_ports}")

            https_port = https_ports[0]['HostPort']
            http_port = http_ports[0]['HostPort']

            try:
                hs = {'Host': "nginx"}
                r = requests.get(
                    f"http://{EDGE_IP}:{http_port}/stub_status", timeout=5, headers=hs)
            except requests.exceptions.ConnectionError as e:
                print(f"could not connect over port {http_port}!")
                print(e)
            except requests.exceptions.Timeout as e:
                print(f"timed out connecting over port {http_port}!")
                print(e)
            else:
                if r.status_code == 200:
                    print(f"got an HTTP 200 over port {http_port}")
                    first_line = r.text.splitlines()[0]
                    if first_line.startswith("Active connections:"):
                        active_connections = int(first_line.split(" ")[2])
                        print(
                            f"this nginx container has {active_connections} active connections")
                        if active_connections < 2:
                            container.kill()
                            nat_manager_logs = client.containers.run(
                                nat_manager_image.id,
                                command=["/usr/bin/python3", "map_port.py", "--public-port",
                                         "80", "--remove-private-port", http_port],
                                detach=False,
                                network="host",
                                cap_add=["NET_ADMIN"]
                            )
                            print(nat_manager_logs.decode())
                            print("killed container and removed NAT rule for it")

                else:
                    print(
                        f"connected but got HTTP {r.status_code} over port {http_port}")
        time.sleep(1)


if __name__ == "__main__":
    client = docker.DockerClient(base_url="ssh://root@0.0.0.0")
    # client = docker.DockerClient()

    # colons have a reserved meaning in docker tags...
    image_build_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    install_nginx_config(client, config, all_sites,
                         config_timestamp, image_build_timestamp)
