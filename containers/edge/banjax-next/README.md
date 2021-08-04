# Banjax-go
 
<p align="center">
    <img src="https://github.com/equalitie/banjax-next/blob/master/edge-diagram.svg" alt="edge diagram">
</p>

Our edge architecture at Deflect for many years was Apache Trafficserver and a custom plugin called Banjax. This plugin did some basic rate-limiting on incoming requests according to a configurable set of regex patterns. If a rate-limit was exceeded, we could block further requests from that IP address, or we could serve a challenge-response page (JS-based proof-of-work, or password-based authentication).

Banjax-go is a rewrite of this which performs the same functionality, but as a separate process rather than a plugin. We're also using it with Nginx now instead of Trafficserver, but the idea should work with any reverse proxy that supports X-Accel-Redirect. Instead of doing the regex matching on incoming requests in the Nginx/Trafficserver process, we are tailing access logs similarly to fail2ban.

The relationship between Nginx and banjax-go is probably best understood with a sample Nginx configuration:

```
# Nginx forwards incoming requests to banjax-go, which responds with an X-Accel-Redirect header
location / {
    proxy_pass http://banjax-go/auth_request
}

# if X-Accel-Redirect is "@access_granted", Nginx internally redirects here
location @access_granted {
    proxy_pass https://origin-server
}

# likewise if X-Accel-Redirect is "@access_denied"
location @access_denied {
    return 403 "access denied";
}
```

Some observations:
* The old plugin-based system was hooking Trafficserver's internal request-processing state machine
  events. This was quite hard to understand and extend, and the resulting behavior wasn't apparent
  or changeable in a config file. Leveraging existing higher-level HTTP middleware concepts makes
  the whole thing easier to understand and modify.
* We can leverage Nginx's powerful block-based configuration format. Caching the auth request
  responses, adding timeout and failure-handling behavior, or treating static files specially
  can all be done in the Nginx config instead of with code.

## Banjax-go's decision-making process

Banjax-go currently has four internal Decision types:

* Allow
  * returns `X-Accel-Redirect: @access_granted` to Nginx.
* NginxBlock
  * returns `X-Accel-Redirect: @access_denied` to Nginx.
* IptablesBlock
  * returns `@access_denied` *and also* blocks that IP with iptables.
* Challenge
  * returns a JS-based SHA-inverting proof-of-work page. if the request contains
    a cookie with a solved challenge, banjax-go returns `@access_granted`. if an IP
    exceeds a rate limit of failed challenges, they get blocked.

The Decision lists are populated by:

* The config file. This is useful for allowlisting or blocklisting known good or bad IPs.
* The regex-matching rate-limiting log tailer. Rules specify the regex to look for, the
  number of hits and time interval that determine the rate limit, and the Decision to
  take for future requests from that IP if the rate limit is exceeded.
* A Kafka topic. This is how Baskerville sends its ML-informed commands to Banjax-go.
* A rate limit on the number of failed challenges an IP submits. Bots will generally
  fail a bunch of challenges, and we want to block them after a while rather than
  serve them an unlimited number of challenge pages.

Decisions added at run-time (from the log tailer, Kafka, or the failed challenge rate limit)
expire after some configurable amount of time.

[XXX figure out priority levels between the lists and types]

## Password-protected paths

From the perspective of the JS and cookie cryptographic implementation, these work very
similarly to the SHA-inverting proof-of-work challenge. But the use-cases are different:
the PoW challenge is intended to filter out DDoS traffic, and so it makes sense for the
Nginx configuration to fail open in case Banjax-go is unreachable. Password-protected
paths should probably fail closed. [XXX does this make sense? there were other distinctions?]

## Sample configuration
```yaml
config_version: 2020-12-15_12:35:38
global_decision_lists:         # static allow/challenge/block decisions (global)
  allow:
  - 20.20.20.20
  block:
  - 30.40.50.60
  challenge:
  - 8.8.8.8
per_site_decision_lists:       # static allow/challenge/block decisions (per-site)
  example.com:
    allow:
    - 20.20.20.20
    block:
    - 30.40.50.60
    challenge:
    - 8.8.8.8
iptables_ban_seconds: 10       # how long an iptables ban lasts
iptables_unbanner_seconds: 5   # how often the unbanning task runs
kafka_brokers:
- localhost:9092
password_hashes:               # for password_protected_paths
  example.com: <base64 string> 
password_protected_paths:      # for password_protected_paths
  example.com:
  - wp-admin
per_site_rate_limited_regexes: # fail2ban-like challenging/blocking (per-site)
  example.com:
  - decision: block
    hits_per_interval: 10
    interval: 120
    name: UNNAMED RULE
    regex: 'GET \/search\/.*'
regexes_with_rates:            # fail2ban-like challenging/blocking (global)
- decision: block
  hits_per_interval: 0
  interval: 1
  regex: .*blockme.*
  rule: instant block
- decision: challenge
  hits_per_interval: 0
  interval: 1
  regex: .*challengeme.*
  rule: instant challenge
server_log_file: /var/log/banjax-next/banjax-next-format.log  # nginx log file with specific format
```

---

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/">
<img alt="Creative Commons Licence" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/80x15.png" /></a><br />
This work is copyright (c) 2020, eQualit.ie inc., and is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
