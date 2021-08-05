# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.


import subprocess
import yaml


#  iptables \
#    -A PREROUTING    # Append a rule to the PREROUTING chain
#    -t nat           # The PREROUTING chain is in the nat table
#    -p tcp           # Apply this rules only to tcp packets
#    -d 192.168.1.1   # and only if the destination IP is 192.168.1.1
#    --dport 27017    # and only if the destination port is 27017
#    -j DNAT          # Use the DNAT target
#    --to-destination # Change the TCP and IP destination header
#       10.0.0.2:1234 # to 10.0.0.2:1234

# iptables -I OUTPUT -t nat -p tcp -m addrtype --dst-type LOCAL --dport 443 -j REDIRECT --to-ports 10443 -m statistic --mode random --probability 1.0
# iptables -I OUTPUT -t nat -p tcp -m addrtype --dst-type LOCAL --dport 80 -j REDIRECT --to-ports 10080 -m statistic --mode random --probability 0.5
#
# iptables -I DOCKER -t nat ! -i docker0 -p tcp -m tcp --dport 443 -j DNAT --to-destination edge_ip:443 -m statistic --mode random --probability 1.0
# iptables -I DOCKER -t nat ! -i docker0 -p tcp -m tcp --dport 80 -j DNAT --to-destination edge_ip:80 -m statistic --mode random --probability 1.0

if __name__ == "__main__":
    config = {}
    with open('input/current/config.yml', 'r') as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)

    all_names = []
    for dnet, edge_names in config["dnets_to_edges"].items():
        for name in edge_names:
            print("running `hostname` on %s" % name)
            subprocess.run(["ssh", "deflect@%s" % name, "docker stop $(docker ps -aq)"])
            subprocess.run(["ssh", "deflect@%s" % name, "docker ps"])
            continue
            subprocess.run(["ssh", "deflect@%s" % name, "hostname"])
            docker_ps_proc = subprocess.run(["ssh", "deflect@%s" % name, "docker ps"])
            docker_ps_return_code = docker_ps_proc.returncode
            if docker_ps_return_code == 0:
                print(f"found docker on {name}, skipping")
                continue
            elif docker_ps_return_code == 127:
                print(f"installing docker on {name}...")
            else:
                print(f"unexpected return code on {name}: {docker_ps_return_code}")
            subprocess.run(["ssh", "deflect@%s" % name, "sudo apt-get update && sudo apt-get -yq install apt-transport-https ca-certificates curl gnupg2 software-properties-common"])
            subprocess.run(["ssh", "deflect@%s" % name, "sudo curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -"])
            subprocess.run(["ssh", "deflect@%s" % name, "sudo add-apt-repository \"deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable\""])
            subprocess.run(["ssh", "deflect@%s" % name, "sudo apt-get -yq update"])
            subprocess.run(["ssh", "deflect@%s" % name, "sudo apt-cache policy docker-ce"])
            subprocess.run(["ssh", "deflect@%s" % name, "sudo apt-get -yq install docker-ce"])
            subprocess.run(["ssh", "deflect@%s" % name, "sudo usermod -aG docker deflect"])
