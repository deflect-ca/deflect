# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# controller
# - DNS query <timestamp>.test.me.uk
#   - verify bind is working
#   - maybe also query through our DNS mirror?
# - HTTPS connect <timestamp>.test.me.uk
#   - verify we can get new LE certs?

# edge
# - get Host: {nginx, banjax_next} test.me.uk/info through nginx
#   - return a json response with config_version: <timestamp>
# - get <timestamp>.test.me.uk/no-cache through nginx
# - get <timestamp>.test.me.uk/yes-cache through nginx
# - get <timestamp>.test.me.uk/challenge-me through nginx
# - get <timestamp>.test.me.uk/ban-me through nginx (?)
import socket

import dns.resolver
import requests

# stealing this from deflect-web (thanks, donncha)
import yaml
from pyaml_env import parse_config

from orchestration.helpers import get_sites_yml_path, get_config_yml_path


class override_dns(object):
    """
    Context manager to temporaily override the resolution of DNS
    """

    def __init__(self, hostname, ip_address):
        self.hostname = hostname
        self.ip_address = ip_address

    def getaddrinfo(self, *args):
        if args[0] == self.hostname:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (self.ip_address, args[1]))]
        else:
            return self.orig_getaddrinfo(*args)

    def __enter__(self):
        self.orig_getaddrinfo = socket.getaddrinfo
        socket.getaddrinfo = self.getaddrinfo

    def __exit__(self, *args):
        socket.getaddrinfo = self.orig_getaddrinfo


def correct_dns_for_new_site(hostname):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [config['controller']['ip']]

    a = resolver.query(hostname, "A")
    ips = list(map(lambda x: x.address, a))

    if set(ips) != set(config['dnet_to_edge_ips']['dnet']):
        print(f"expected ips: {config['edge_ips']}, but got ips: {ips}")
        return False
    else:
        return True


def can_https_connect_to_new_site(hostname, edge_ip):
    with override_dns(hostname, edge_ip):
        try:
            requests.get(f"https://{hostname}")
        except requests.exceptions.SSLError:
            pass
        else:
            print(
                f"did not expect to connect to https://{hostname} without the fakelerootx1.pem cert")
            return False

        res = requests.get(f"https://{hostname}",
                           verify="input/fakelerootx1.pem")
        if res.status_code != 200:
            print(
                f"expected status code 200 for https://{hostname}, but got {res.status_code}")
            return False
        else:
            return True


def nginx_config_versions_are_expected(timestamp):
    # XXX confusing how this works. also needs https.
    with override_dns("nginx", edge_ip):
        res = requests.get("http://nginx/info")
        if res.status_code != 200:
            print(f"expected status code 200 for nginx info query")
            return False

        res_d = res.json()
        if res_d.get("config_version") != str(timestamp):
            print(
                f"expected config_version: {timestamp}, but response was: {res_d}")
        else:
            return True


def banjax_next_config_versions_are_expected(timestamp):
    # XXX confusing how this works. also needs https.
    with override_dns("banjax", edge_ip):
        res = requests.get("http://banjax")
        if res.status_code != 200:
            print(f"expected status code 200 for banjax info query")
            return False

        res_d = res.json()
        if res_d.get("config_version") != str(timestamp):
            print(
                f"expected config_version: {timestamp}, but response was: {res_d}")
        else:
            return True


if __name__ == "__main__":
    config = parse_config(get_config_yml_path())
    all_sites = []
    with open(get_sites_yml_path(), 'r') as f:
        all_sites = yaml.load(f, Loader=yaml.SafeLoader)

    if not correct_dns_for_new_site('hostname'):
        print("bad 1")

    for edge_ip in config["edge_ips"]:
        if not can_https_connect_to_new_site('hostname', edge_ip):
            print("bad 2")

    for edge_ip in config["edge_ips"]:
        if not nginx_config_versions_are_expected('timestamp', edge_ip):
            print("bad 3")

    for edge_ip in config["edge_ips"]:
        if not banjax_next_config_versions_are_expected('timestamp', edge_ip):
            print("bad 4")
