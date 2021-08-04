I'm usually running it in development like:
```
go run banjax-next.go -config-file banjax-next-config.yaml -standalone-testing
```
and then using curl in another window like:
```
curl "localhost:8081/auth_request?path=challengeme"
access granted
```

The `-standalone-testing` flag does some things to make standalone (not behind Nginx)
testing easier:
* tails "testing-log-file.txt" instead of whatever is in the config file
* writes the Gin access logs to that file (usually we tail an Nginx log)
* sets the `X-Client-IP`, `X-Requested-Host`, and `X-Requested-Path` headers
  (usually these would be set by Nginx). `X-Requested-Path` gets set to the value
  of the `path` query parameter (it's a more convenient curl command than
  setting the header).

### TLDR version
* verify Allow works by running
```
curl "localhost:8081/auth_request?path=test"
```
a bunch of times. You should always get "200, access granted"
* verify NginxBlock works by running
```
curl "localhost:8081/auth_request?path=blockme"
```
  a bunch of times. You should get "403, access denied" after the first one
  goes through. You should let it expire and then verify you can get through
  again.
* verify Challenge works by hitting
```
curl "localhost:8081/auth_request?path=challengeme"
```
a bunch of times. First time: allowed. Then some challenger pages. Then a
block page. Then you let it expire and get an allow page again.

### Allow, Challenge, and NginxBlock

The basic behaviors you'll want to test are Allow, Challenge, and NginxBlock.
* Allow is the default if no rules match, and you can trigger it by running
```
curl "localhost:8081/auth_request?path=test"
```
  a bunch of times (you should get "200, access granted" every time).
* Challenge will serve a sha-inverse challenger page. The crypto (in JS and Go) should
  be tested later, but you can trigger the page with
```
curl "localhost:8081/auth_request?path=challengeme"
```
  The first time you run it, you'll probably get "200, access granted" because the log
  tailing and regex matching happens asynchronously outside of the `/auth_request`
  handling. The second time you run it, you should get a challenger page.
* NginxBlock will serve a "403, access denied" response and you can trigger it with
```
curl "localhost:8081/auth_request?path=blockme"
```

There is also some support for an Allow decision, and an IptablesBlock one. The first one
might theoretically be useful as an unblocking backdoor. The second one will block traffic
at the `iptables` level instead of the Nginx level. IptablesBlock is the main kind of
blocking in our current production system, but we've been talking a lot recently about
switching to HTTP-level blocking only.

Cons:
  * More expensive to serve a small string from Nginx than to drop traffic at the kernel.
    My gut feeling says we can afford it, but we should do synthetic benchmarks eventually.

Pros:
  * We continue to see and analyze bot traffic even after its blocked. This is the reasoning
    behind the "grace period" that exists in the current production system.
  * It's a lot simpler to QA. You need like three computers to test it properly, and it's
    going to potentially behave differently if you run everything under docker-compose
    rather than deflect-next.
  * iptables gets slow when you have a bunch of rules.
  * There's probably a way to tell Nginx to refuse connections from a list of IPs, if we
    need it. That would be easier to understand and more portable across environments.

So, given all that, I think we won't be configuring any Allow or IptablesBlock decisions in
the near future, and you can skip QAing them.

### Dynamic/Expiring Decisions

You can hard-code some unchanging Allow/Challenge/NginxBlock lists of IPs (per-site or global)
in the config file. But the interesting decision lists are populated at run-time by the
log tailer and from commands received over the Kafka channel (from Baskerville).

Per-site lists are checked first, then global lists, and then the dynamic lists. I think this
ordering makes sense, but double-check me on it.

The dynamic decisions expire after `expiring_decision_ttl_seconds` seconds. So, to test this,
you would trigger a Challenge or an NginxBlock as above, wait that many seconds, and then
perform another request that should result in the default/config/hard-coded behavior.

### Rate-limiting the number of failed challenges

The challenge page verification path is probably relatively expensive, and this is the one
that non-challenge-passing bots will hit over and over again, so it makes sense to rate-limit it.
The relevant config values are:
```yaml
too_many_failed_challenges_interval_seconds: 10
too_many_failed_challenges_threshold: 3
```
and the rate-limiting works like the regex rate-limits. When the limit is exceeded, an
NginxBlock decision gets put into the dynamic list with a TTL of
`expiring_decision_ttl_seconds`.

You should test this by curling the "challengeme" path a bunch of times. You should eventually
get "403, access denied". And if you let that expire, it should start over again at
"200, access granted".

### Inspecting the internal state

For debugging and QA purposes (and also for building a mental model of how the thing works),
it's useful to be able to see the decision lists and rate-limit
counters. You can do it with the following two endpoints:
```
curl "localhost:8081/decision_lists"
per_site:
example.com:
	90.90.90.90:
		Allow
	91.91.91.91:
		Challenge


global:
70.80.90.100:
	NginxBlock
8.8.8.8:
	Challenge
20.20.20.20:
	Allow
30.40.50.60:
	IptablesBlock


expiring:
127.0.0.1:
	NginxBlock until 15:38:18
```
```
curl "localhost:8081/rate_limit_states"
regexes:
127.0.0.1:
	instant challenge:
		{4 2021-04-09 16:09:13 +0200 CEST}
	instant block:
		{1 2021-04-09 15:38:12 +0200 CEST}
	All sites/methods: 800 req/30 sec:
		{7 2021-04-09 16:09:07 +0200 CEST}
	All sites/GET on root: 22 req/10 sec:
		{7 2021-04-09 16:09:07 +0200 CEST}


failed challenges:
127.0.0.1,: interval_start: 16:09:12, num hits: 4
```

### Testing the challenge pages and cookie crypto

[XXX TODO]

### Testing with Nginx

This probably needs to be done when QAing deflect-next, as the Nginx configuration included
in the banjax-next repo's docker-compose setup isn't going to be representative enough for QA.

* verify fail-open and fail-closed work
* verify that banjax-next responses are cached and purged correctly
