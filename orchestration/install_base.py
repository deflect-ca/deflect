# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.


import subprocess
import yaml

from pyaml_env import parse_config

from orchestration.helpers import get_config_yml_path

USER = "root"

# needed for apt-add-repository
reqs_for_apt = [
	"apt-transport-https",
	"ca-certificates",
	"curl",
	"gnupg2",
	"software-properties-common",
].join(" ")

other_packages = [
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
].join(" ")

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

def run_remote(user_at_ip, command):
    proc = subprocess.run(["ssh", user_at_ip, command])
    if proc.returncode != 0:
        raise Exception(f"command '{command}' returned non-zero code: {proc.returncode}")

if __name__ == "__main__":
    config = parse_config(get_config_yml_path())

	# install the stuff that's common to the controller and edges
	controller_and_edges = config['edge_names_to_ips'].update(
	        {config['controller_hostname'], config['controller_ip']}
    )
    for hostname, ip in controller_and_edges.items():
        user_at_ip = f"{USER}@{ip}"

        print("running `hostname` on %s" % ip)
        subprocess.run(["ssh", user_at_ip, "hostname"])

        docker_ps_proc = subprocess.run(["ssh", user_at_ip, "docker ps"])
        if docker_ps_proc.returncode == 0:
            print(f"found docker on {ip}, skipping")
            continue

        print(f"installing requirements on {ip}...")

        # these commands need variables from this inner scope
        controller_and_edge_commands.extend([
            f"sudo hostnamectl set-hostname {hostname}",
        ])

        for command in controller_and_edge_commands:
            run_remote(user_at_ip, command)


    # run the stuff that only makes sense on the controller
    controller_commands = [
        "sudo ufw enable",
        f"sudo ufw allow from any to any port 22 proto tcp",
        # XXX i don't get why/when we would be generating a new key here?
        # surely our hosting providers put some existing public key under ~/.ssh/authorized_keys ?
        # f"ssh-keygen -t rsa -f {config['edge_key_file']} -N {config['edge_key_pass']} -q -C edgeKey -b 4096",
    ]
    for hostname, ip in {config['controller_hostname'], config['controller_ip']}.items():
        for command in controller_commands:
            run_remote(user_at_ip, command)


    # run the stuff that only makes sense on the edges
    edge_commands = [
        "sudo ufw enable",
        f"sudo ufw allow from {config['controller_ip']} to any port 22 proto tcp",
    ]
    for hostname, ip in config['edge_names_to_ips'].items():
        for command in edge_commands:
            run_remote(user_at_ip, command)


