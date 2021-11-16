# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.


import subprocess
import yaml
import json
import docker

from pyaml_env import parse_config

from util.helpers import get_config_yml_path

USER = "root"

# needed for apt-add-repository
reqs_for_apt = " ".join([
    "apt-transport-https",
    "ca-certificates",
    "curl",
    "gnupg2",
    "software-properties-common",
])

other_packages = " ".join([
    "software-properties-common",
    "apt-transport-https",
    "vim",
    "screen",
    "tmux",
    "haveged",
    "tzdata",
    "unzip",
    "zip",
    "bzip2",
    "locales",
    "acl",
    "sudo",
    "ufw",
    "iptables",
    "iproute2",
    "python3-aiohttp",
    "python3-openssl",
    "python3-pem",
    "python3-dnspython",
    "python3-gnupg",
    "python3-docker",
    "python3-paramiko",
    "python3-jinja2",
    "python3-yaml",
])

# XXX sudo not needed here if we're running as root
controller_and_edge_commands = [
    f"sudo apt-get update && sudo apt-get -yq install {reqs_for_apt} {other_packages}",
    "sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -",
    "sudo add-apt-repository \"deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable\"",
    "sudo apt-get -yq update",
    "sudo apt-cache policy docker-ce",
    "sudo apt-get -yq install docker-ce",
    "sudo timedatectl set-timezone UTC",
    "sudo useradd --create-home deflect",
    "sudo usermod --append --groups docker deflect", # installing docker above added the 'docker' group
]

# TODO: the base_url needs to be in a config. This is not flexible for debugging
# TODO: or testing/ staging env
def docker_client_for_host(host):
    if host['ip'] == "127.0.0.1":
        return docker.DockerClient()
    else:
        return docker.DockerClient(base_url=f"ssh://root@{host['ip']}")


def run_local_or_remote_noraise(config, host, command, logger):
    logger.debug(f"===== running \"{command}\" on {host['hostname']} ({host['ip']}) =====")

    shell_prefix = []
    if host['ip'] != "127.0.0.1":
        # XXX not allowing the key file to be configured because docker-py doesn't, atm
        shell_prefix = ["ssh", "-i", "~/.ssh/id_rsa", f"root@{host['ip']}"]
    else:
        shell_prefix = ["bash", "-c"]

    proc = subprocess.run(
            shell_prefix + [command],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    for line in proc.stdout.splitlines():
        logger.debug(f"    {line.decode()}")

    return proc


def run_local_or_remote_raise(config, host, command, logger):
    proc = run_local_or_remote_noraise(config, host, command, logger)
    if proc.returncode != 0:
        logger.debug(f"command '{command}' returned non-zero code: {proc.returncode}")
        raise Exception(f"command '{command}' returned non-zero code: {proc.returncode}")
    return proc


def get_docker_engine_version(config, host, logger):
    command = "docker version --format '{{json .}}'"
    proc = run_local_or_remote_noraise(config, host, command, logger)
    if proc.returncode == 127:  # this means command not found
        return None
    if proc.returncode != 0:    # let's raise on unexpected return code to be safe
        raise Exception(f"ran command `{command}` on host `{host}` and got unexpected return code")

    lines = proc.stdout.splitlines()
    if len(lines) != 1:
        raise Exception(f"ran command `{command}` on host `{host}` and got unexpected output")
    d = json.loads(lines[0])
    s = d.get("Server")
    if not s:
        raise Exception(f"ran command `{command}` on host `{host}` and got unexpected output")
    for c in s.get("Components"):
        if c.get("Name"):
            version = c.get("Version")
            if not version:
                raise Exception(f"ran command `{command}` on host `{host}` and got unexpected output")
            return version
    

def ensure_generic_requirements(config, host, logger):
    version = get_docker_engine_version(config, host, logger)
    if version:
        logger.debug(f"docker found, skipping the rest of install for {host['ip']}")
        return True

    logger.debug(f"installing requirements on {host['ip']}...")

    # these commands need variables from this inner scope
    commands = controller_and_edge_commands + [
        f"sudo hostnamectl set-hostname {host['hostname']}",
    ]

    for command in commands:
        proc = run_local_or_remote_raise(config, host, command, logger)

    return True


def host_to_role(config, host):
    if host == config['controller']:
        return "controller"
    for edge in config['edges']:
        if host == edge:
            return "edge"
    raise RuntimeError(f"could not find host ({host}) in config")


def ensure_all_requirements(config, host, logger):
    res = ensure_generic_requirements(config, host, logger)

    role = host_to_role(config, host)
    if role == "edge":
        logger.debug(f"installing edge requirements on {host['hostname']}...")
        return ensure_edge_requirements(config, host, logger)
    elif role == "controller":
        logger.debug(f"installing controller requirements on {host['hostname']}...")
        return ensure_controller_requirements(config, host, logger)
    else:
        raise RuntimeError(f"unknown role ({role}) for hose ({host})")


def ensure_controller_requirements(config, controller, logger):
    controller_commands = [
        # XXX not doing the ufw stuff for now
        # f"sudo ufw allow from any to any port 22 proto tcp",
        # "sudo ufw --force enable",
        # XXX i'm not sure how to generally bootstrap the controller having creds for everywhere else
        # f"ssh-keygen -t rsa -f {config['ssh_key_file']} -N {config['ssh_key_pass']} -q -C edgeKey -b 4096",
        "sudo systemctl disable systemd-resolved", # we run our own dns server
        "sudo systemctl stop systemd-resolved",
        "rm /etc/resolv.conf",
        "echo 'nameserver 1.1.1.1' > /etc/resolv.conf",
    ]
    for command in controller_commands:
        proc = run_local_or_remote_raise(config, controller, command, logger)

    return True


def ensure_edge_requirements(config, edge, logger):
    edge_commands = [
        # XXX not doing the ufw stuff for now
        # f"sudo ufw allow from {config['controller']['ip']} to any port 22 proto tcp",
        # "sudo ufw --force enable",
    ]
    for command in edge_commands:
        proc = run_local_or_remote_raise(config, edge, command, logger)

    return True


