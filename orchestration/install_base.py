# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.


import subprocess
import yaml

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

def run_remote_noraise(config, host, command):
    print(f"\n===== running \"{command}\" on {host['hostname']} ({host['ip']}) =====")
    proc = subprocess.run(
            ["ssh", "-i", config['ssh_key_file'], f"root@{host['ip']}", command],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    for line in proc.stdout.splitlines():
        print(f"\t{line.decode()}")
    return proc

def run_remote_raise(config, host, command):
    proc = run_remote_noraise(config, host, command)
    if proc.returncode != 0:
        raise Exception(f"command '{command}' returned non-zero code: {proc.returncode}")

if __name__ == "__main__":
    config = parse_config(get_config_yml_path())

    # install the stuff that's common to the controller and edges
    for host in [config['controller']] + config['edges']:
        try:
            run_remote_raise(config, host, "docker ps")
        except Exception:
            print(f"docker not found")
        else:
            print(f"docker found, skipping the rest of install for {host['ip']}")
            continue

        print(f"installing requirements on {host['ip']}...")

        # these commands need variables from this inner scope
        controller_and_edge_commands.extend([
            f"sudo hostnamectl set-hostname {host['hostname']}",
        ])

        for command in controller_and_edge_commands:
            run_remote_raise(config, host, command)


    # run the stuff that only makes sense on the controller
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
    for host in [config['controller']]:
        for command in controller_commands:
            run_remote_raise(config, host, command)


    # run the stuff that only makes sense on the edges
    edge_commands = [
        # XXX not doing the ufw stuff for now
        # f"sudo ufw allow from {config['controller']['ip']} to any port 22 proto tcp",
        # "sudo ufw --force enable",
    ]
    for host in config['edges']:
        for command in edge_commands:
            run_remote_raise(config, host, command)


