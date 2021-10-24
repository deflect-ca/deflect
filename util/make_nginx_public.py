# Copyright (c) 2021, eQualit.ie inc.
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
from pyaml_env import parse_config

from orchestration.helpers import get_logger, get_config_yml_path

logger = get_logger(__name__, logging_level=logging.DEBUG)


def curl_and_expect_return_code_or_exit(host, site, expected_return_code):
    # todo: refactor ports
    user = host.get('user', "root")
    curl_proc = subprocess.run(["ssh",
                                f"{user}@{host['ip']}",
                                f"curl -I --resolve \"{site}:10443:127.0.0.1\" \"https://{site}:10443\""],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return_code = curl_proc.returncode
    if expected_return_code != return_code:
            print(f"FAIL: curled {site} on {host}, expected {expected_return_code} but got {return_code}, exiting")
            #exit()
    else:
        print(f"SUCCESS: curled {site} on {host}, expected {expected_return_code} and got {return_code}")


def do_edge(config, new_probability, host):
    user = host.get('user', "root")
    client = docker.DockerClient(base_url=f"ssh://{user}@{host['ip']}")
    print(f"doing {host['hostname']}")
    nginx_containers = client.containers.list(filters={"label": f"name=nginx"})
    if len(nginx_containers) != 1:
        raise Exception(f"expected one container, found: {nginx_containers}")
    nginx_container = nginx_containers[0]
    inspect_d = client.api.inspect_container(nginx_container.id)
    private_ip = inspect_d["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
    print(f"\nhost: {host}, nginx private_ip: {private_ip}")

    if host['dnet'] == "dnet1":
        # curl_and_expect_return_code_or_exit(host, "example.ca", 0)
        pass
    elif host['dnet'] == "dnet2":
        # curl_and_expect_return_code_or_exit(host, "example.ca", 0)
        pass
    elif host['dnet'] == "controller":
        print("not doing any checks for controller")
        pass
    else:
        print("have not got sites for that dnet yet")
        exit()

    list_proc = subprocess.run(["ssh", f"{user}@{host['ip']}", "sudo iptables -t nat -S"], stdout=subprocess.PIPE, check=True)
    # XXX will need to be more careful about the ordering when ATS isn't there
    for rule_line in list_proc.stdout.splitlines():
        if " -m statistic " in rule_line.decode():
            del_rule = "iptables -t nat " + rule_line.decode().replace("-A ", "-D ")
            print(f"running {del_rule}")
            del_proc = subprocess.run(["ssh", f"{user}@{host['ip']}", f"sudo {del_rule}"], stdout=subprocess.PIPE, check=True)
    if new_probability > 0.0:
        for port in ["80", "443"]:
            ins_rule = f"iptables -I DOCKER -t nat ! -i docker0 -p tcp -m tcp --dport {port} -j DNAT --to-destination {private_ip}:{port} -m statistic --mode random --probability {new_probability}"
            ins_proc = subprocess.run(["ssh", f"{user}@{host['ip']}", f"sudo {ins_rule}"], stdout=subprocess.PIPE, check=True)

    list_proc2 = subprocess.run(["ssh", f"{user}@{host['ip']}", "sudo iptables -t nat -S"], stdout=subprocess.PIPE, check=True)
    print(f"final rules for {host}: {list_proc2.stdout.decode()}")


def main(config):
    new_probability = 0.99
    with ThreadPoolExecutor(max_workers=16) as executor:
        for host in [config['controller']] + config['edges']:
            print(f"doing {host}")
            executor.submit(do_edge, config, new_probability, host)


if __name__ == "__main__":
    config = parse_config(get_config_yml_path())
    main(config)
