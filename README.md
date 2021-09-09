# Deflect-next Orchestration

This repo contains the orchestration scripts and Docker images that make up the
Deflect service.

![How it works](https://raw.githubusercontent.com/equalitie/banjax-next/master/edge-diagram.svg)

## Installation
```bash
git clone https://github.com/equalitie/deflect-next-orchestration.git
cd deflect-next-orchestration
pip install -e .
```
`-e` is if you need it to be editable, you can skip it.

## How to run
The main configuration files are:
- `orchestration/input/config.yml`
- `orchestration/input/old-sites.yml`
- `orchestration/system-sites.yml`
- `orchestration/deflect-next_config.yml`

There are example yamls in the respective directories for all the above.

Before running Deflect-next, you need to have the correct values in the above configuration files.

`orchestration/install_base.py` will install docker on each edge defined in `orchestration/input/config.yaml` under `dnets_to_edges`.

```bash
cd orchestration
python3 install_base.py
```

Under `orchestration` there is a `main.py` file.
This will run the three main steps for deflect-next and it should be ran on the controller:
- [optional] cert_converter_main
- install_delta_config
- make_nginx_public_main

In short, to run deflect-next:
```bash
python3 main.py
```


### Orchestration scripts

The orchestration scripts can be used for the following functionality:
  * install the prerequisites on a newly-provisioned remote server.
    * `install_base.py` - this just ssh-es in and installs Docker.
  * given a `sites.yml` dump from the `deflect-web` dashboard, generate and
    install a new set of config files for `nginx`, `bind-server`, `certbot`,
    and `banjax-next`. (`install_delta_config.py` and `start_or_upgrade_nginx_image.py`)


Not checked into the repo:
  * `orchestration/input/etc-ssl-sites.tar`
  * `orchestration/input/tls_bundles/`
    * encrypted files from `deflect-web`
  * `orchestration/.gnupg/`
    * `GPGHOME` with a key to decrypt the `tls_bundles`

### Docker images

An edge server runs two Docker containers: `nginx` proxies traffic between
clients and origin servers, and `banjax-next` is our supporting service (in Go)
that does a handful of things:
  * hosts a couple http endpoints that nginx talks to for access control
    decisions. `nginx` then responds with a 403 "you are blocked", a 401 "solve
    this captcha or javascript proof-of-work challenge", or proxies the request
    to the origin server. `banjax-next` generates the challenge pages and manages
    the related cookies.
  * tails the `nginx` logs and matches regex rules to make blocking/challenging
    decisions (like fail2ban)
  * creates and expires iptables ban rules.
  * talks to our machine learning bot classification service called `baskerville`
    over a `kafka` bus.

There is also expected to be some kind of central controller server that hosts
the `bind-server` and `certbot` containers defined in this repo. Probably this
could be the same server that hosts the `deflect-core` API and the
orchestration scripts.


