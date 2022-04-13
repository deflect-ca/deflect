## Table of Contents

- [What is Deflect?](#what-is-deflect-)
  * [Overview](#overview)
  * [Technology](#technology)
- [Basic Component Overview](#basic-component-overview)
- [Request Lifecycle](#request-lifecycle)
- [Components &amp; Concepts](#components--amp--concepts)
  * [Controller](#controller)
  * [Edge](#edge)
  * [Baskerville](#baskerville)
  * [Dnets](#dnets)
  * [Edge Rotation/Management](#edge-rotation-management)
  * [ELK Stack](#elk-stack)
  * [Other logging options](#other-logging-options)
  * [DNS Load Balancing](#dns-load-balancing)
- [DNS](#dns)
- [Hardware Considerations](#hardware-considerations)
  * [Controller](#controller-1)
  * [Edges](#edges)
- [Installation](#installation)
  * [input/config](#input-config)
    + [global_config.yml](#global-configyml)
    + [old-sites.yml](#old-sitesyml)
    + [system-sites.yml](#system-sitesyml)
    + [banjax_config.yml](#banjax-configyml)
    + [edgemanage_config.yml](#edgemanage-configyml)
    + [rndc.conf / rncd.key](#rndcconf---rncdkey)
  * [input/banjax (optional)](#input-banjax--optional-)
  * [input/legacy-filebeat (optional)](#input-legacy-filebeat--optional-)
  * [Generate and install config](#generate-and-install-config)
  * [CLI (General)](#cli--general-)
    + [certs](#certs)
    + [gen](#gen)
    + [get](#get)
    + [install](#install)
    + [util](#util)
  * [CLI (Banjax)](#cli--banjax-)
  * [CLI (Edgemanage)](#cli--edgemanage-)
    + [Query edges](#query-edges)
    + [Config edges](#config-edges)
    + [Force update](#force-update)
  * [Where you'll want to start looking when things don't work](#where-you-ll-want-to-start-looking-when-things-don-t-work)


# What is Deflect?

## Overview

Deflect has specialized in defending high-profile human rights and independent media websites since 2010, serving millions of readers the world over and confounding the aims of state-sponsored hacking teams trying to silence them. We release our time tested tooling for standing up an entire DDoS mitigation infrastructure, including our machine learning anomaly detection system, as FOSS - to ensure that these protections are afforded to everyone and DDoS attacks cannot prevent freedom of expression and association on the Internet. We also tackle the problem of censorship from the user's perspective - looking to circumvent website censorship in their locale - in another one of our [projects.](https://censorship.no/)

This repository allows any individual or organization to set up their own DDoS mitigation service. It contains all necessary components to set up your network controller and edge servers - essentially acting as a reverse proxy to you or your clients' origin web servers. Nginx carries our edge server traffic, and our sidecar service Banjax helps it with access control decisions. Optionally, you can also install an instance of [Baskerville](https://github.com/deflect-ca/baskerville) - an anomaly detection system using machine learning to detect malicious network behavior. Baskerville can be deployed as a module on your edge servers, communicating with our clearinghouse for predictions, or in its entirety with a base model.

## Technology

- [Docker](https://www.docker.com/)
- [Nginx](https://www.nginx.com/)
- [Certbot](https://certbot.eff.org/)
- [Bind9](https://hub.docker.com/r/internetsystemsconsortium/bind9)
- [Kafka](https://hub.docker.com/r/wurstmeister/kafka/)
- [ELK Stack](https://www.elastic.co/what-is/elk-stack) (for request logging and system metrics)
- [Banjax](https://github.com/deflect-ca/banjax) (our sidecar for Nginx written in Go)
- [Baskerville](https://github.com/deflect-ca/baskerville) (optional, can be used together with Deflect to detect anomalous traffic and with Banjax to challenge and ban anomalous behavior)
- [Edgemanage](https://github.com/deflect-ca/edgemanage)


# Basic Component Overview

The diagram below visualizes the basic configuration of different Deflect components.

![](docs/basic.jpg)

**Client Origins:** One or more web servers that host website platforms. They are protected from direct access to the outside world by having incoming connections proxied through one or more edges. All requests to your website(s) will come from these edges.

# Request Lifecycle

The diagram below highlights the request lifecycle inside a fully deployed Deflect DDoS mitigation infrastructure.

![](docs/request.png)

# Components &amp; Concepts

## Controller

We put our central services on a host called the controller. The most important parts are Bind9 and Certbot, for pointing DNS names at healthy edges and getting HTTPS certificates from LetsEncrypt. For demonstration purposes here, we have Elasticsearch and Kibana on the controller, though you might want to do that differently. And we have some services which help with end-to-end testing: a dns-over-https proxy (for setting up a browser that points to a staging environment), a pebble service (a fake LetsEncrypt backend), and a test origin server with some helper endpoints. The orchestration scripts in this repo can live anywhere, but the controller might be a natural place (a sysadmin's laptop would be the other obvious place, since the scripts don't need to run continuously).

That's a lot of important services, so you should take care to keep this server safe and online. We use a third-party DNS provider that sends zone transfers to our Bind server so that we can keep the IP hidden and reduce the attack surface.

## Edge

The edge server acts as a reverse proxy to the origin web servers. You can set up one or more edges in your network. And you can organize sets of edges into what we call Dnets (see below). Edges run two services: Nginx and [Banjax](https://github.com/deflect-ca/banjax). Nginx is well known, and it carries our traffic and caches content. Nginx talks to Banjax for access control help:

- Nginx asks Banjax whether requests it sees should be allowed, challenged (the familiar "checking your browser" page), or blocked. These decisions are cached so you don't pay the ~500us penalty every time.
- Banjax tails the Nginx access logs and matches regex rules to make blocking/challenging decisions (like fail2ban).
- Banjax creates and expires iptables ban rules.
- Banjax optionally talks to Baskerville (our machine learning bot classification service) over a Kafka bus.

## Baskerville

[Baskerville](https://github.com/deflect-ca/baskerville) is our ML-powered anomaly detection system. It's not included in this repo, but it analyzes access logs from the Elasticsearch cluster and communicates with Banjax over a Kafka bus. Anomalous-seeming IPs can be served challenge pages by Banjax, and bots that fail many challenge pages can be banned at the HTTP or IP levels.

## Dnets

In our experience protecting hundreds of websites with dozens of edges, we've found it useful to assign each website to a subset of the total edges. This has been useful for putting edges closer to a website's visitors, for allocating hardware resources fairly, and for quarantining the effects of internet censorship.

## Edge Rotation/Management

It's a service of ours called [edgemanage](https://github.com/deflect-ca/edgemanage). Edgemanage performs end-to-end health checks against edge servers and fills in Bind9 zone file templates with the healthiest ones.

## ELK Stack

Single-node Elasticsearch clusters are easy to set up, and multi-node ones have a reputation as being a bit tough. We include a single-node ES cluster, a Kibana frontend, and a dashboard of handy queries, histograms, and plots.

[Screenshot of the Kibana dashboard](docs/big-dash.png)

## Other logging options

If you already have an existing ELK stack, deflect gives you the option to point filebeat to it. Simply edit the `logging` section in `global_config.yml`.

## DNS Load Balancing

DNS round robin is a decades-old technique for balancing load across many servers. A widely-implemented IETF proposal called [Happy Eyeballs](https://en.wikipedia.org/wiki/Happy_Eyeballs) makes it even better. Instead of picking an essentially random IP from the set returned by a DNS server, clients will begin connections to many IPs at once, keep the winner, and close the rest. CDNs often use GeoIP databases to get closer to users, but this could be even better.

# DNS

If you want to protect example.com with Deflect, you just need to point the NS record at the Bind9 server included here (or if you're like us, you point it at at a third-party DNS host which in turn points at this one). That makes this Bind9 server authoritative, and our configuration generation here will serve A records pointing at the edge servers. Edgemanage, that's now included in this repo, is the component we use in production to direct traffic at our healthiest edge servers.

# Hardware Considerations

## Controller

By far the most resource-intensive service we run on the controller is Elasticsearch. There are two things you might want to benchmark here: the indexing speed (documents per second) and the querying speed (how fast your Kibana dashboard renders). It's going to depend a lot on your traffic, but a $40 VPS has sufficed for us in production.

## Edges

Nginx is going to be the resource-hungry one here, and you're going to have to benchmark it yourself.

# Installation

You can run the orchestration scripts from anywhere. They can be on the controller, or on your laptop. The following commands install the Python dependencies and make the scripts ready to run.

You can install all of the controller and edge containers locally (under Docker Desktop) on your workstation with the following snippet in `global_config.yml`:

```yaml
controller:
  hostname: docker-desktop
  ip: 127.0.0.1
  dnet: controller  # XXX fix this
edges:
  - hostname: docker-desktop
    ip: 127.0.0.1
    dnet: dnet_a
```
(More precisely, it won't install the controller's version of Nginx, Filebeat, or Metricbeat, but it will install everything else.)

If you are installing on a remote server, you need to edit the `global_config.yml` file.

## input/config

```
# Copy the sample config file
cp -r input/config{-example/,}
```

### global_config.yml

This is the most important config file to setup deflect, here you will define:

- system_root_zone: Usually the root_zone of the controller and edges
- login_user: The SSH user to login to the controller and edges
- server_env: staging / production
  - In staging deflect will install Pebble and test certbot in staging mode.
- debug: Setting `log_level`, enable `docker_build_log`, or change the path of `orchestration_log`
- dnets
  - dnet contains a group of edges, one site could only live on one dnet. (controller has its own dnet)
- controller and edges: Define the hostname, IP and dnet of the controller and edges
- logging: Define how deflect handles site access log
  - elk_internal: Stand up built in ELK, no settings required
  - elk_external: Connect to an external ELK via filebeat (elasticsearch server as target)
  - logstash_external: Connect to an external ELK via legacy-filebeat (logstash server as target)
- fetch_site_yml: Define where to copy `site.yml` file into `input/config/old_sites.yml`
- dns: Bind server zone file settings, set `also-notify` and `allow-transfer` if you have an upstream DNS server. Also set `default_ns`, `soa_nameserver` and `soa_mailbox` according to your DNS provider
- root_zone_extra: Extra record to add under `system_root_zone`, this is used if you have other subdomains that isn't part of the deflect system
- nginx: Modify `ssl_ciphers` or allow more IP to access nginx control endpoints

### old-sites.yml

This config defines what sites are protected by deflect. It's a list of dictionaries, each of which defines a site. Usually this is generated by a dashboard system, later fetched by `fetch-site-yml` command.

### system-sites.yml

This config defines the dns-over-https-proxy, kibina and test-origin. You can remove all of them if you don't want to use them, just leave test-origin there as it is used by edgemanage to evaluate the health of the edge servers.

### banjax_config.yml

This config defines the banjax configuration. Usually you don't need to modify it unless you want to change the banjax banning rules.

### edgemanage_config.yml

Since edgemanage modifies the DNS zone file, you must set the `dns` section with the correct `SOA` and `NS` info. If you want to modify the edge count, you could do it in `dnet_edge_count`. Last you must set the `testobject` section correct with your root domain name, so it points to the correct test-origin.

### rndc.conf / rncd.key

Run bind utility `rndc-confgen` to generate your `rndc.key` and `rndc.conf`.

## input/banjax (optional)

If you are connecting to Kafka using banjax, place the `caroot.pem`, `certificate.pem`, and `key.pem` file under `input/banjax`.

## input/legacy-filebeat (optional)

If you are connecting to an external ELK via legacy-filebeat, place the `edgecert.key`, `edgecert.pem` and  `rootca.pem` file under `input/legacy-filebeat`. This is required when you set `logging.mode` as `logstash_external` in `global_config.yml`.

## Generate and install config

```bash
git clone https://github.com/deflect-ca/deflect.git --recursive
cd deflect
pip install -e . # -e to make the scripts editable in place

python main.py gen config
python main.py install config
```

Keep in mind that `gen config` and `install config` are always required when you modify any settings under the `input/` folder. `gen config` writes to `output/` and `install config` takes the file in `output/` and install it on the target remote machine. It also start/stop/reload containers with the latest config.

## CLI (General)

Deflect CLI contains five commands and its sub-command.

```
Usage: main.py [OPTIONS] COMMAND [ARGS]...

  Welcome to deflect orchestration script

Options:
  --debug            Override log_level in global_config to DEBUG
  -h, --host TEXT    "all", "controller", "edges" or comma separated
                     hostnames. For example: "edge1,edge2,edge3" (subdomain
                     name) or full hostname "edge1.dev.deflect.network"
  -a, --action TEXT  DEPRECATED. Forward only
  --help             Show this message and exit.

Commands:
  certs    SSL certs related utility
  gen      Generate stuff like config or certs
  get      Getting information from remote host
  install  Install config or service
  util     Utility for admin
```

### certs

```
Commands:
  check-cert-expiry    Loop through all our certs and print the...
  decrypt-verify-cert  Decrypt and verify cert bundles
```

### gen

```
Commands:
  config             Generate config from input dir
  new-elastic-certs  Generate new ES certs
```

### get

```
Commands:
  banjax-decision-lists       Call banjax control endpoint
  banjax-rate-limit-states    Call banjax control endpoint for rate limit...
  nginx-banjax-conf-versions  See the config version (from site dict)...
  nginx-errors                Get nginx errors
  site-yml                    Fetch site.yml file from dashboard
```

`get site-yml` connects to the remote server defined in `global_config.yml` and fetches the site.yml file to `input/config/old_sites.yml` like this:

```
mkdir -p input/config/clients.yml-revisions
mkdir -p input/config/tld_bundles
python3 main.py --action fetch-site-yml
```


### install

```
Commands:
  banjax    Install and update banjax
  base      Install required package on target
  config    Install config to target
  es        Install Elasticsearch
  selected  Install config to selected target
```

`install base` installs docker and the required package on the remote target.

You can specific a `--host` option to specify which host should be installed. For example:

```
# Install to all (default = all)
python main.py install config

# Install to controller
python main.py --host controller install config

# Install to edges
python main.py --host edges install config

# Install to selected edges (using subdomain)
python main.py --host edge1,edge2 install config

# Install to selected edges and controller (using subdomain)
python main.py --host edge1,edge2,controller install config

# Install to selected edges and controller (using full domain)
python main.py --host edge1.dev.deflect.network install config
```

Note that `install selected` works the same as `install config`, the only difference is that it gives a prompt for you to confirm the target host before doing install. You can override this by using `python main.py --host edge1,edge2,controller install config --yes`.

Both `install config` and `install selected` support `--sync` options, adding this will change the edge install from parallel (default behavior) to one by one.

### util

```
Commands:
  info                       Fetch docker version via SSH for testing
  kill-all-containers        Run docker kill $(docker ps -q) on target
  show-useful-curl-commands  Print curl commands for ES and edge testing
  test-es-auth               Attempt to authenticate with saved ES auth
```

`util info` is useful for testing connection to the remote host. 

## CLI (Banjax)

```# trigger the challenge page. Repeat it (failing it) until you get blocked.
curl -v -k --resolve example.com:443:<edge_ip> "https://example.com?challengeme"

# then run this. and see your IP gets an expiring IptablesBlock.
python3 main.py --action get-banjax-decision-lists

# see your IP under the rate limit states.
python3 main.py --action get-banjax-rate-limit-states

# see the config version (from the site dict) that nginx and banjax are running.
python3 main.py --action get-nginx-banjax-conf-versions
```

## CLI (Edgemanage)

In deflect, we have a dockerize version of edgemanage, here we only list a few common commands, for details please refer to edgemanage repo.

### Query edges

```
$ docker exec -it edgemanage edge_query --dnet dnext1 -v | sort
available in    pass_threshold    edge2.dev.deflect  -1
available in    pass_threshold    edge3.dev.deflect  -1
available out   pass_threshold    edge1.dev.deflect  -1
```

### Config edges

```
$ docker exec -it edgemanage edge_conf --dnet dnext1 --mode unavailable edge2.dev.deflect --comment "fixing"
Set mode for edge2.dev.deflect to unavailable
```

### Force update

```
docker exec -it edgemanage edge_manage --dnet dnext1 --force --force-update -v
```

## Where you'll want to start looking when things don't work

A good starting point would be querying the Bind9 server for your website. Run `dig @127.0.0.1 example.com` on the controller. Maybe run it from a different vantage point.

You can force curl to connect through a specific edge like this:
```
curl --resolve example.com:443:127.0.0.1 https://example.com
```

A common problem is Nginx not being able to find certificates that you told it to look for. On any edge server, run
```
docker logs nginx-error-log-tailer-<timestamp>
```
and you'll see Nginx's error.log.

If you want to look at the output of the configuration generation code, you can look under `orchestration/output/<timestamp>/`.

You can get a shell into a Docker container with:
```
docker exec -it <container name> /bin/bash
```

---

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/">
<img alt="Creative Commons Licence" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/80x15.png" /></a><br />
This work is copyright (c) 2020, eQualit.ie inc., and is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
