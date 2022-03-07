Here are the containers running on the controller at the moment:
```
root@debian-s-4vcpu-8gb-intel-fra1-01:~# docker ps
CONTAINER ID        IMAGE                COMMAND                  CREATED             STATUS              PORTS                                                                                    NAMES
d3d73e50166e        0b60f3cdf995         "go run hello-world.…"   59 minutes ago      Up 59 minutes       0.0.0.0:8080->8080/tcp                                                                   origin-server
b28dfaf2d5c5        847a9f6af81f         "sleep infinity"         59 minutes ago      Up 59 minutes                                                                                                certbot
fd1036f4790a        2eda51d10c97         "/usr/bin/tini -- /u…"   3 weeks ago         Up 3 weeks                                                                                                   metricbeat
ca92f0e9e600        b5ea440fb59d         "/usr/bin/tini -- /u…"   3 weeks ago         Up 3 weeks                                                                                                   filebeat
140624e3f952        e046b07b5d02         "/bin/tini -- /usr/l…"   3 weeks ago         Up 3 weeks          0.0.0.0:5601->5601/tcp                                                                   kibana
b48df2723533        5073f85ae8e3         "/bin/tini -- /usr/l…"   3 weeks ago         Up 3 weeks          0.0.0.0:9200->9200/tcp, 9300/tcp                                                         elasticsearch
d8526172efec        8f944328f984         "/usr/sbin/named -g …"   3 weeks ago         Up 3 weeks          0.0.0.0:53->53/tcp, 0.0.0.0:8085->8085/tcp, 0.0.0.0:53->53/udp, 127.0.0.1:953->953/tcp   bind-server
cf1d3f6166fa        7213864a87a0         "pebble -config /tes…"   3 weeks ago         Up 3 weeks                                                                                                   pebble
d971124f0acc        bb5a4102b369         "/docker-entrypoint.…"   3 weeks ago         Up 3 weeks          0.0.0.0:10080->80/tcp, 0.0.0.0:10443->443/tcp                                            nginx-2021-09-20_12-50-45
6953c3395d75        debian:buster-slim   "tail --retry --foll…"   3 weeks ago         Up 3 weeks                                                                                                   nginx-system_sites-log-tailer-2021-09-20_12-50-45
37d56e3ac2c0        debian:buster-slim   "tail --retry --foll…"   3 weeks ago         Up 3 weeks                                                                                                   nginx-error-log-tailer-2021-09-20_12-50-45
aea296888dde        debian:buster-slim   "tail --retry --foll…"   3 weeks ago         Up 3 weeks                                                                                                   nginx-access-log-tailer-2021-09-20_12-50-45
dc01aeca793a        ecc6661e980a         "/bin/sh -c 'doh-htt…"   3 weeks ago         Up 3 weeks                                                                                                   doh-proxy
5d4a204710a3        16632b32bd1e         "/bin/sh -c '/usr/lo…"   3 hours ago         Up 3 hours        edgemanage
```
* origin-server
    * this is just some little Go http server with some endpoints that facilitate e2e
      tests.

* certbot
    * this shares a network namespace with bind-server.
    * bind is configured to forward the LE DNS-01 requests to certbot's dns-helper plugin.
    * certbot isn't running as a daemon or on a cron schedule. `install_delta_config.py`
      copies existing certificates into this container, then runs `certbot renew`, then
      copies certificates out of this container. so, while this container is running, the
      process inside is just the `sleep` command.

* metricbeat
    * this mounts some paths from the host (see `start_new_metricbeat_container()`)
      and sends metrics to ES.

* filebeat
    * similar to the metricbeat container.
    * one notable thing is that it's configured to watch `/var/lib/docker/containers/`
      on the host, so it picks up the output of all running containers without us having
      to list them.
    * the docker plugin and json decoder are useful in that we don't have to specify a
      schema up front, *but* this can get annoying later when ES/Kibana don't auto-map
      your documents as you expected. i'm not really sure where this should be fixed:
      i think ES should enforce a schema (rather than trust all of its clients), but
      filebeat has to know it as well.

* kibana
    * i've been treating my ES and Kibana as disposable, but you'll definitely want to
      persist Kibana's "saved objects" between redeploys. if i make a new query or plot,
      i'll "export all saved objects" from the web interface. you can then later "import
      saved objects" by uploading the json file. see `import_kibana_saved_objects()` for
      where i'm doing the import bit after we start a new Kibana instance.

* elasticsearch
    * i'm running my own Elasticsearch because:
        * we don't know how to not break the existing one (a bad auto-mapping breaks
          subsequent indexing).
        * i want to send lots of debug logs and metrics to it without impacting opsdash.
        * it's very easy to run a one node cluster on a $30 VPS (and it kept up when my
          Nginxes were handling 90% of production traffic).
    * opsdash only has deflect.log and banjax.log. my thing takes all the logs from all
      of my containers, and lots of system metrics. i guess most of this could be deleted
      automatically after a week, but i've just been deleting the indices by hand from Kibana.
    * one gross part of `install_delta_config.py` is building/starting a new ES instance.
      see `install_elasticsearch_kibana()`: it does the usual image build + container run(),
      but then it has to run a command to set up non-default credentials. and it has to
      save the credentials returned by that command so we can use them in the other parts
      that need these credentials. my very expedient way of persisting that password for
      the next run has been to copy/paste it out of the output on the screen and into the
      python source code. this is definitely one of the places i've punted on coming up
      with a better solution (probably i have to add a folder like `persisted-between-runs/`
      to my `input/` and `output/` folders).

* bind-server
    * i hate bind9. if you look at the config in `container/controller/bind-server/`,
      you'll see some of what i had to do to get useful logs.
    * from what i've read, i understand that much of bind9's complexity comes from it being
      both a recursive resolver and an authoritative nameserver. we only need the latter
      part. we should probably investigate using something simpler *or* (since we're
      using a third party dns host anyway) a third party host that we post records to over
      http.

* edgemanage
    * this is a container to run the latest version of the edgemanage package stored in
      github: deflect-ca/edgemanage.
    * edgemanage is running as a daemon and tailing its logs from /var/log
    * the config generators are automatically creating /etc/edgemanage/edges/dnext1 based on
      the values set in global_config.yml
    * this container is sharing a volume with `bind-server` in order to simplify the update of
      DNS zone files and achieve edge rotation

* pebble
    * certbot is an acme/LetsEncrypt frontend, this is the backend. it's only for
      generating fake certs in testing/staging environments.
    * IIRC one inconvenient thing was that (as an anti-footgun measure), when you deploy
      a new instance of this, you can't give it an existing private key to use -- it always
      generates a new one. so you have to reconfigure your staging browser to trust the
      new key when that happens.

* nginx-2021-09-20_12-50-45
    * this is where Nginx lives.
    * note that the Nginx instance on the controller only proxies "system sites" (Kibana,
      doh-proxy, test-origin, and prod.deflect.ca).
    * the timestamps in the name are because, during a zero-downtime upgrade
      (`start_or_upgrade_nginx_image.py`), we can't stop the old container until the new one
      is running. so two (or more?) containers are running at the same time and they need
      unique names. image upgrades are rare, and we're not even using this zero-downtime upgrade
      code at the moment because we don't need to (we can let ATS take over while we redeploy,
      or we could redeploy on out-of-rotation edges). but i think eventually it will need to
      be working.

* nginx-system_sites-log-tailer-2021-09-20_12-50-45
    * it's convenient to have Nginx writing out a few diferent kinds of log file. but the docker
      idiom is to have one stdout/stderr stream per container. so we need multiple containers
      sharing `/var/log/nginx/` and doing `tail -f` of each log file type.

* nginx-error-log-tailer-2021-09-20_12-50-45
    * same ^

* nginx-access-log-tailer-2021-09-20_12-50-45
    * same ^

* doh-proxy
    * it's very useful during staging/testing to be able to hit real websites through staging/testing
      edges. that means your browser needs to think `example-client.com` resolves to one of your
      fake edges. `/etc/hosts` doesn't work everywhere (see also why we prefer `curl --resolve`). it
      would be nice if firefox/chrome let you specify your own DNS server. turns out they do, but
      only dns-over-https. so you point your browser at doh-proxy, and it points to your staging
      bind-server.

And here's what's running on one of the edges:
```
deflect@ovh22:~$ docker ps
CONTAINER ID        IMAGE                COMMAND                  CREATED             STATUS              PORTS                                           NAMES
01c3b3f8ab90        9d6f89c933bf         "/usr/bin/tini -- /u…"   49 minutes ago      Up 49 minutes                                                       metricbeat
a425a21b48ce        e7f2ad397f74         "/usr/local/bin/dock…"   50 minutes ago      Up 49 minutes                                                       legacy-filebeat-opsdashca
f77e9bc77cf6        e7f2ad397f74         "/usr/local/bin/dock…"   50 minutes ago      Up 50 minutes                                                       legacy-filebeat-opsdash
3f3f756aec6a        9254f3b0f64f         "/usr/bin/tini -- /u…"   50 minutes ago      Up 50 minutes                                                       filebeat
eda38a5b2060        4bcf008e2fcf         "go run banjax-next.…"   50 minutes ago      Up 50 minutes                                                       banjax-next
c6bbe044b9c6        debian:buster-slim   "tail --retry --foll…"   50 minutes ago      Up 50 minutes                                                       banjax-next-log-metrics-log
596baf5b8ee3        debian:buster-slim   "tail --retry --foll…"   50 minutes ago      Up 50 minutes                                                       banjax-next-log-gin-log
98e4ecbc4c47        f47ca777087b         "/docker-entrypoint.…"   6 weeks ago         Up 6 weeks          0.0.0.0:10080->80/tcp, 0.0.0.0:10443->443/tcp   nginx-2021-08-30_13-35-35
03d7c746f379        debian:buster-slim   "tail --retry --foll…"   6 weeks ago         Up 6 weeks                                                          nginx-system_sites-log-tailer-2021-08-30_13-35-35
ed2783fe4c33        debian:buster-slim   "tail --retry --foll…"   6 weeks ago         Up 6 weeks                                                          nginx-error-log-tailer-2021-08-30_13-35-35
052120b7c794        debian:buster-slim   "tail --retry --foll…"   6 weeks ago         Up 6 weeks                                                          nginx-access-log-tailer-2021-08-30_13-35-35
```

* metricbeat
    * same as above

* legacy-filebeat-opsdashca
    * each filebeat instance can only write to one output. here, we're pointing to
      a logstash instance on the opsdashca host.

* legacy-filebeat-opsdash
    * and here, we're writing to a logstash instance on the opsdash host. i don't know why we
      have two, or why the names are so non-descriptive.

* filebeat
    * same as above

* banjax-next
    * this is where Banjax lives.
    * it shares a filesystem mount with Nginx to tail the access log.
    * and it also shares a network namespace with Nginx so `iptables` works.
    * in the zero-downtime upgrade future, it might need timestamped unique naming like the
      Nginx containers have. but Banjax should be able to go offline a bit while Nginx does
      the appropriate thing (see the `@fail_open` and `@fail_closed` location blocks in the
      Nginx configuration).

* banjax-next-log-metrics-log
    * this `tail -f`s a log of metrics from Banjax.

* banjax-next-log-gin-log
    * this tails the log of http requests Banjax is getting from Nginx.

* nginx-2021-08-30_13-35-35
    * this is where Nginx lives.
    * note that Nginx on the edges only proxies traffic for sites in the Dnet that edge
      belongs to.

* nginx-system_sites-log-tailer-2021-08-30_13-35-35
    * log tailer.

* nginx-error-log-tailer-2021-08-30_13-35-35
    * log tailer.

* nginx-access-log-tailer-2021-08-30_13-35-35
    * log tailer.

