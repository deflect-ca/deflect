*Deprecated document*

We should probably rename and organize these files better. And the code should
definitely be prettied up now it's mostly working.

```
l@tp ~/code/equalitie/deflect/orchestration [main] $ wc -l *.py
       0 __init__.py
     111 build.py
     146 cert_converter.py
     258 decrypt_and_verify_cert_bundles.py
      52 dns_checker.py
     130 generate_banjax_next_config.py
     312 generate_bind_config.py
     511 generate_nginx_config.py
     106 helpers.py
      79 http_checker.py
      57 install_base.py
     447 install_delta_config.py
     142 integration_tests.py
      24 main.py
     126 make_nginx_public.py
     141 old_to_new_site_dict.py
     630 shared.py
     206 start_or_upgrade_nginx_image.py
    3478 total
```
* `cert_converter.py`
    * this only exists during the autodeflect -> deflect-next transition period.
    * it's gross and should go away.

* `decrypt_and_verify_cert_bundles.py`
    * "bundles" are what we call the key/cert/chains that users upload in deflect-web
      if they don't want us to use LetsEncrypt on their behalf.
    * Previously we had a Bash script, the openssl CLI, and the GPG CLI. It was a
      goal of mine to replace these Bash scripts with Python. Screen-scraping CLIs
      with awk/sed pipelines is fun for one-offs, but it usually gets cumbsersome
      if you do all the error checking correctly.
    * The "verify" part of this script should probably be run in deflect-web so we
      can tell users they uploaded a mismatched cert and key, for example.

* `dns_checker.py`
    * this is just for checking whether the autodeflect Bind9 and deflect-next Bind9
      agree with each other.

* `generate_banjax_next_config.py`
    * could use cleanup

* `generate_bind_config.py`
    * could use cleanup
    * dnspython is quite hard to use, but zone files are actually quite simple to
      template. might not be worth the complexity of the library?
    * should we run it with the "acme-challenge" stuff only while we're
      running certbot? and then run it without that stuff after?
    * edgemanage takes the output of this script and adds the A and SOA records.
      so the zone files that come out of this script are incomplete.

* `generate_nginx_config.py`
    * Our Jinja2 templates in autodeflect were Not Good. There was a lot of complex
      logic and nested loops/conditionals *and* these blocks were not indented. Also,
      since templating is just string interpolation, it was possible to generate
      syntactically invalid config files. I thought it would be better to use a Python
      library that understood the Nginx config file syntax. I definitely wouldn't
      claim my code couldn't benefit from refactoring (all of this code grew organically
      while running and debugging things *in situ* and there has definitely been no
      code review or refactoring done to it). But also I wonder now whether this
      would look nicer (and be more accessible to non-Pythonistas) as a Jinja2 template.
      Probably worth trying at some point.
    * It might be nice to run this in deflect-web to show (technical) users what
      the dashboard buttons actually do?

* `http_checker.py`
    * this is just to curl some URLs against ATS and Nginx to see if they disagree.

* `install_base.py`
    * this might be ugly at the moment. the name indicates its original use: to install
      prerequisites on remote base systems. but i have been using it to run other
      commands on remote servers as well, so it's worth reading it over to see if
      i've hacked it to do something else.
    * it does show how minimal our prerequisites are: just Docker.

* `install_delta_config.py`
    * This is the top level of deflect-next. you call it, it generates all the config
      (using stuff under `orchestration/input/` as input, and outputting under
      `orchestration/output/<timestamp>/`), runs the docker build/start/stop
      stuff (using docker-py, which talks to the remote Docker APIs over SSH), copies
      files around, runs commands, and sends reload signals.
    * Initially in this project I was using Docker Compose. Then I tried
      Docker Swarm. Kubernetes was also a candidate. It would be nice if one of these
      systems let me write all of what I needed as declarative configuration
      (eg. a docker-compose.yml file or Kubernetes manifests) rather than imperative
      Python code. But there were plently of cases where I needed more control than
      Compose and Swarm gave me (running commands, copying files, making/attaching volumes, etc.)

      Other people might have reached for Ansible or Bash, but I don't
      find Ansible's abstractions (playbooks, roles, inventories) to be very useful
      (other than being uniform across other Ansible playbooks). The fake-declarative
      syntax makes simple things (apt installing a list of packages) verbose and
      harder things (nested for loops) nearly impossible. So I ruled out using
      Ansible and Bash because Python can do everything they can do, but better.

      The question remains whether Kubernetes would be a good fit. The part I'm concerned
      about is: Kubernetes expects containers to be immutable. We generate new config
      every time someone clicks a button in the dashboard, and we send that config to
      already-running containers (ie. we treat them as mutable). I think constant image
      rebuilds and container redeploys would be too wasteful/slow for us (or would be
      in the future), so I've spent a bit of time looking to see how other people have
      done this with Kubernetes (https://github.com/kubernetes/kubernetes/issues/24957).

* `integration_tests.py`
    * a husk of what it should be

* `make_nginx_public.py`
    * this sets the iptables port forwarding on remote edges. Does a little sanity check
      first by querying sites through the 10443/10080 ports to see that Nginx is working.
    * i'm running this manually at the moment. unclear where it will eventually go.
      maybe it's just useful during the ATS -> Nginx migration? maybe something similar
      will be useful for Nginx upgrades in the future?

* `old_to_new_site_dict.py`
    * the `clients.yml` that `gen_site_config()` writes and autodeflect reads is
      not great. i didn't want to bake to bad format into my code here, so this turns
      it into a more sane thing before my code sees it.

* `shared.py`
    * this has some helper functions that do stuff like "find a running container with
      name X or start a new one". that code definitely needs a refactor now that it's
      working.
    * the bulk of the file is configuration for the `container.run()` commands -- there's
      a nearly one-to-one correspondence with these big Python dicts and the YAML you
      would see in a docker-compose.yml file. it *might* be nice exploring if we could
      port it to a Docker Compose compatible format? there are some imperative bits,
      but maybe it could look like running `docker-compose up --build X` many times,
      passing environment variables to control the non-static parts?

* `start_or_upgrade_nginx_image.py`
    * i haven't touched this in a while, so it's probably not working, but it contains
      the code that does a zero-downtime upgrade of an Nginx image. it starts the
      new image alongside the old one, switches the port forwarding to the new one,
      polls the old Nginx's number of active connections until existing requests are
      done, then stops the old Nginx. we rarely need to upgrade the base image, so
      i stopped paying attention to it (and during the transition period, I can let
      ATS take over when I'm doing an image upgrade), but i think it will be useful/necessary
      in the future (unless we can get something like Swarm or Kubernetes to do it for us).

