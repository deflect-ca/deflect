### The `auth_request` endpoint that Nginx talks to

Nginx `proxy_pass`es to banjax-go, which makes a decision (Allow, Challenge, NginxBlock, or IptablesBlock)
based on the requested host and the client IP. In pseudocode, banjax-go's decision-making works like this:

```python
if password_protected_path[requested_host][requested_path]:
    return send_or_validate_password_page()

decision = per_site_decision_lists[requested_host][client_ip]
if decision == Allow:
    return access_granted()
if decision == Challenge:
    return send_or_validate_challenge()
if decision in [NginxBlock, IptablesBlock]:
    return access_denied()

decision = global_decision_lists[client_ip]
# [...] same as above

# if nothing matched above
return access_granted()
```

The decision lists are populated from:
  * the config file, which is read at startup and on SIGHUP [XXX todo]. See `per_site_decision_lists`
    and `global_decision_lists`. This is useful for allowlisting or blocklisting known good or bad IPs.
  * the regex-based rate-limiting rules explained in more detail below.
  * commands received over the Kafka connection. This is how Baskerville communicates with banjax-go.

`access_granted()` returns a response with a header: `X-Accel-Redirect: @access_granted` which instructs
Nginx to perform an internal redirect to the location block named `@access_granted`. That block should
`proxy_pass` to the upstream origin site.

`access_denied()` works similarly, but the `@access_denied` block might just return a "403, access denied"
response.

The relevant Nginx config might look similar to:

```
location /wp-admin/ {
	error_page 500 501 502 @fail_closed;
	proxy_pass http://<banjax-go>/auth_request?;
}

location / {
	error_page 500 501 502 @fail_open;
	proxy_pass http://<banjax-go>/auth_request?;
}

location @access_denied {
	return 403 "access denied";
}

location @access_granted {
	proxy_pass http://<upstream site>;
}

location @fail_open {
	proxy_pass http://<upstream site>;
}

location @fail_closed {
	return 403 "error talking to banjax-go, failing closed";
}
```

It's probably a good idea to add per-block logging and caching behavior to the above.

### Challenge-response authentication (SHA-inverse and password-protected paths)

There are currently two forms of challenge-response authentication which involve a back-and-forth
between banjax-go and the browser: a SHA-inverting proof-of-work challenge, and a basic password form.
The first is useful for denying access to simple bots which don't execute JavaScript, and the second is
useful for adding another layer of authentication in front of sensitive routes (for example, `wp-admin`).

`send_or_validate_password_page()` and `send_or_validate_challenge()` both basically work like:

```python
if cookie_contains_solved_challenge(cookie):
    return access_granted()
else:
    return 401, challenge page + new cookie
```

Note that this will currently serve an unlimited number of challenges to a bot that isn't solving them.
banjax-go's predecessor would eventually block this kind of bot at the iptables level, but there are some
intel-gathering benefits in not doing that. We will probably want to rate-limit this, though. [XXX todo]

### Regex-based rate-limits

One of the ways the decision lists are populated is by tailing an Nginx access log and applying regex-based
rate-limiting rules.  The log format expected looks like this:
```
1617871463.867 1.2.3.4 GET /wp-admin/ HTTP/1.1 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) -
```

and a rule looks like this:
```yaml
- decision: challenge
  hits_per_interval: 800
  interval: 30
  regex: .*
  rule: "All sites/methods: 800 req/30 sec"
```

Decisions correspond to those mentioned above: "allow", "challenge", "nginx_block", "iptables_block".

The log tailing loop basically looks like this:
```python
for log_line in lines(log_file):
    for rule in rules:
        if not rule.regex.match(log_line):
            continue

        rule_state = ip_to_rule_states[ip][rule]
        if (rule_state == None) or (log_line.timestamp - rule_state.interval_start_time > rule.interval):
            rule_state = {num_hits: 1, interval_start_time: log_line.timestamp}
        else:
            rule_state.num_hits++

        if rule_state.num_hits > rule.hits_per_interval:
            global_decision_lists[ip] = rule.decision
```

The actual code has some extra stuff to deal with adding/removing iptables rules and clearing stale decisions
from the Nginx cache.

[XXX todo] Banjax-go's predecessor never unblocked an IP after it triggered a rule (it would stay in effect
until ATS restarted). We probably want to add an explicit time limit somewhere (per rule or global?). Also, note
to self to be careful here: when I delete a regex-triggered Decision, it should probably restore any Decision
that might have been loaded from the config file.
