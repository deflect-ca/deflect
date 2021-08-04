Banjax-next is one component extracted from our deflect-next system.

deflect-next repo:
  * python configuration generation and orchestration scripts
    * these can be run from a developer's computer to target a remote
      production or staging environment. or they can live on the same host
      as deflect-core, which will call into them as a result of API requests.
    * the input is a sites.yml from deflect-web or deflect-core,
      the scripts generate bind9, nginx, etc. config files, start
      docker containers, and send the new config over.
  * docker images

singleton containers (one instance of each of these is running somewhere):
  * authoritative DNS server (bind9)
  * certbot (with the dns-standalone plugin handling the dns-01 challenge)
  * test origin (simple web app designed to make testing deflect-next easy)
  * elasticsearch (filebeat sends logs here)
  * kibana (`kibana-saved-objects.ndjson` gets POSTed to it and contains some
    useful visualizations)

edge containers:
  * nginx
  * banjax-next
  * nat-manager (to facilitate zero-downtime upgrades of the nginx container, we
    use iptables to forward new connections to the new container while the old
    container continues to service existing connections).

For logging + metrics, we have a filebeat container on every host sending the
host's docker daemon logs to the central elasticsearch instance.

### banjax-next

The first line of defense in our DDOS mitigation strategy is the Nginx cache. Most
of the websites we protect are news websites that serve identical pages to every
visitor (the homepage might update a dozen times per day, and published articles
rarely get updated). Nginx is efficient at serving static resources from its cache,
and this is a sufficient defense against traffic surges or unsophisticated attackers.

Our second line of defense is a curated list of regex patterns with associated
rate limits [\*]. This allows us, for example, to instantly block IPs sending requests
with user agents from a list of vulnerability scanners. Or we could block IPs
that request an expensive `/search/` endpoint too often.

[\*]Our third line of defense is Baskerville, documented elsewhere.

In addition to blocking requests (at the HTTP level) or blocking IPs (at the iptables/
netfilter level), we also support sending a "challenger" HTML page which contains either
a basic password challenge (useful as an extra line of defense in front of admin sections)
or a proof-of-work challenge (useful for blocking bots that don't execute javascript, while
allowing web browsers through).

So the list of decisions banjax-next can make are: Allow, Block, or Challenge. The decision
lists are populated from the config file (useful for allowlisting or blocklisting known good
or bad IPs), from the results of the regex rate limit rules (so breaking a rule can result
in a Block or a Challenge, or even an Allow), and from messages received on a Kafka topic
(this is how Baskerville talks to banjax-next).
