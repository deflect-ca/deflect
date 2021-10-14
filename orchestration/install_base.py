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

if __name__ == "__main__":
    config = parse_config(get_config_yml_path())

    for edge_name, ip in config['edge_names_to_ips'].items():
        user_at_ip = f"{USER}@{ip}"

        print("running `hostname` on %s" % ip)
        subprocess.run(["ssh", user_at_ip, "hostname"])

        docker_ps_proc = subprocess.run(["ssh", user_at_ip, "docker ps"])
        docker_ps_return_code = docker_ps_proc.returncode

        if docker_ps_return_code == 0:
            print(f"found docker on {ip}, skipping")
            continue
        elif docker_ps_return_code == 127:
            print(f"installing docker on {ip}...")
        else:
            print(f"unexpected return code on {ip}: {docker_ps_return_code}")

        subprocess.run(["ssh", user_at_ip, "sudo apt-get update && sudo apt-get -yq install apt-transport-https ca-certificates curl gnupg2 software-properties-common"])
        subprocess.run(["ssh", user_at_ip, "sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -"])
        subprocess.run(["ssh", user_at_ip, "sudo add-apt-repository \"deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable\""])
        subprocess.run(["ssh", user_at_ip, "sudo apt-get -yq update"])
        subprocess.run(["ssh", user_at_ip, "sudo apt-cache policy docker-ce"])
        subprocess.run(["ssh", user_at_ip, "sudo apt-get -yq install docker-ce"])
        # XXX only on our existing debian edges
        # subprocess.run(["ssh", user_at_ip, "sudo usermod -aG docker deflect"])
