This repo contains the orchestration scripts and Docker images that make up the
Deflect service.

##### Orchestration scripts

The orchestration scripts are under `orchestration/` and the outside world will
probably mostly ask them to do two things:
  * install the prerequisites on a newly-provisioned remote server.
    * `install_base.sh` - this just sshes in and installs Docker.
  * given a `sites.yml` dump from the `deflect-web` dashboard, generate and
    install a new set of config files for `nginx`, `bind-server`, `certbot`,
    and `banjax-next`.
    * `install_delta_config.py` and `start_or_upgrade_nginx_image.py` - these
      need to be renamed and combined.

The scripts are plain Python. So far, I've been running them manually from my
shell on my laptop. In production, they will probably mostly be called into by
the `deflect-core` API as a result of a customer making a change in
`deflect-web`.

Not checked into the repo:
  * `orchestration/input/current/old-sites.yml`
    * the `clients.yml` from `deflect-web`
  * `orchestration/input/etc-ssl-sites.tar-good-24-mar-4`
    * yes, this should be renamed. we don't want to request 700 certs every time
      we run the script. this holds the existing ones.
  * `orchestration/input/tls_bundles/`
    * encrypted files from `deflect-web`
  * `orchestration/.gnupg/`
    * `GPGHOME` with a key to decrypt the `tls_bundles`

##### Docker images

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

##### Things to think about (XXX: lots more)
* the `install_delta_config.py` starts a `certbot` container and copies new
  Let's Encrypt certs to the edges. so in addition to this task being called on
  dashboard changes, it should probably be run as a scheduled task as well, or
  when a certificate is close to expiring.
