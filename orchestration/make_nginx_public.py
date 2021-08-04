# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
import logging

from concurrent.futures.thread import ThreadPoolExecutor

import docker
import yaml
import subprocess

# todo: use configuration for the logger
from orchestration.helpers import get_logger

logger = get_logger(__name__, logging_level=logging.DEBUG)


def curl_and_expect_return_code_or_exit(dnet, edge_name, site, expected_return_code):
    # todo: refactor ports
    curl_proc = subprocess.run(["ssh",
                                f"deflect@{edge_name}",
                                f"curl -I --resolve \"{site}:10443:127.0.0.1\" \"https://{site}:10443\""],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return_code = curl_proc.returncode
    if expected_return_code != return_code:
            print(f"FAIL: curled {site} on {dnet} {edge_name}, expected {expected_return_code} but got {return_code}, exiting")
            #exit()
    else:
        print(f"SUCCESS: curled {site} on {dnet} {edge_name}, expected {expected_return_code} and got {return_code}")


def main(config):
    new_probability = 0
    for dnet, edge_names in config['dnets_to_edges'].items():
        # todo: why do we check for dnet1 here? if we skip here we will never reach
        # the check afrterwards
        if dnet == "dnet1":
            continue
        for edge_name in edge_names:
            client = docker.DockerClient(base_url=f"ssh://deflect@{edge_name}")
            nginx_containers = client.containers.list(filters={"label": f"name=nginx"})
            if len(nginx_containers) != 1:
                raise Exception(f"expected one container, found: {nginx_containers}")
            nginx_container = nginx_containers[0]
            inspect_d = client.api.inspect_container(nginx_container.id)
            private_ip = inspect_d["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
            print(f"\ndnet: {dnet}, edge_name: {edge_name}, nginx private_ip: {private_ip}")

            # todo: remove sites
            if dnet == "dnet1":
                curl_and_expect_return_code_or_exit(dnet, edge_name, "accesoalajusticia.org", 60)
                curl_and_expect_return_code_or_exit(dnet, edge_name, "no-such-website.com", 35)
                curl_and_expect_return_code_or_exit(dnet, edge_name, "radiozamaneh.com", 0)
                curl_and_expect_return_code_or_exit(dnet, edge_name, "deflect.ca", 0)
            elif dnet == "dnet2":
                curl_and_expect_return_code_or_exit(dnet, edge_name, "kaktus.media", 60)
                curl_and_expect_return_code_or_exit(dnet, edge_name, "no-such-website.com", 35)
                curl_and_expect_return_code_or_exit(dnet, edge_name, "farmal.in", 0)
            else:
                print("have not got sites for that dnet yet")
                exit()


def do_edge(config, new_probability, dnet, edge_name):
    # XXX
    if dnet == "controller":
        user = "root"
        edge_name = config['controller_ip'] # XXX ugh
    else:
        user = "deflect"

    client = docker.DockerClient(base_url=f"ssh://{user}@{edge_name}")
    print(f"doing {dnet}: {edge_name}")
    nginx_containers = client.containers.list(filters={"label": f"name=nginx"})
    if len(nginx_containers) != 1:
        raise Exception(f"expected one container, found: {nginx_containers}")
    nginx_container = nginx_containers[0]
    inspect_d = client.api.inspect_container(nginx_container.id)
    private_ip = inspect_d["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
    print(f"\ndnet: {dnet}, edge_name: {edge_name}, nginx private_ip: {private_ip}")

    if dnet == "dnet1":
        curl_and_expect_return_code_or_exit(dnet, edge_name, "accesoalajusticia.org", 60)
        curl_and_expect_return_code_or_exit(dnet, edge_name, "no-such-website.com", 35)
        curl_and_expect_return_code_or_exit(dnet, edge_name, "radiozamaneh.com", 0)
        curl_and_expect_return_code_or_exit(dnet, edge_name, "deflect.ca", 0)
    elif dnet == "dnet2":
        curl_and_expect_return_code_or_exit(dnet, edge_name, "kaktus.media", 60)
        curl_and_expect_return_code_or_exit(dnet, edge_name, "no-such-website.com", 35)
        curl_and_expect_return_code_or_exit(dnet, edge_name, "farmal.in", 0)
    elif dnet == "controller":
        print("not doing any checks for controller")
        pass
    else:
        print("have not got sites for that dnet yet")
        exit()

    # continue

    list_proc = subprocess.run(["ssh", f"{user}@{edge_name}", "sudo iptables -t nat -S"], stdout=subprocess.PIPE, check=True)
    # XXX will need to be more careful about the ordering when ATS isn't there
    for rule_line in list_proc.stdout.splitlines():
        if " -m statistic " in rule_line.decode():
            del_rule = "iptables -t nat " + rule_line.decode().replace("-A ", "-D ")
            print(f"running {del_rule}")
            del_proc = subprocess.run(["ssh", f"{user}@{edge_name}", f"sudo {del_rule}"], stdout=subprocess.PIPE, check=True)
    if new_probability > 0.0:
        for port in ["80", "443"]:
            ins_rule = f"iptables -I DOCKER -t nat ! -i docker0 -p tcp -m tcp --dport {port} -j DNAT --to-destination {private_ip}:{port} -m statistic --mode random --probability {new_probability}"
            ins_proc = subprocess.run(["ssh", f"{user}@{edge_name}", f"sudo {ins_rule}"], stdout=subprocess.PIPE, check=True)

    list_proc2 = subprocess.run(["ssh", f"{user}@{edge_name}", "sudo iptables -t nat -S"], stdout=subprocess.PIPE, check=True)
    print(f"final rules for {edge_name}: {list_proc2.stdout.decode()}")


def main(config):
    new_probability = 0.99
    with ThreadPoolExecutor(max_workers=16) as executor:
        for dnet, edge_names in config['dnets_to_edges'].items():
            if dnet != "dnet1":
                continue
            print(f"doing {dnet}")
            for edge_name in edge_names:
                if edge_name != "lime20.prod.deflect.ca":
                    continue
                print(f"doing0 {dnet}: {edge_name}")
                executor.submit(do_edge, config, new_probability, dnet, edge_name)


if __name__ == "__main__":
    config = {}
    with open('input/current/config.yml', 'r') as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)

    main(config)
