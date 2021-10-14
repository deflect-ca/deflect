# The good parts

* Nginx is an improvement over ATS.
    * There's one config file format which is good at expressing how the different parts
      (routing, caching, logging, etc.) work together. ATS has several disjointed config
      files and it's not obvious how the options in each interact with each other.

* Generating configuration in Python is an improvement over the mix of Python, Ansible, and Bash
  that we had before.
    * `gen_site_config.py` -> sites.yml -> Ansible -> Jinja2 -> Bash -> whatever was a
      nightmare to trace through. Lots of boundaries between languages where mistakes
      could and did happen.
    * Now that deflect-web and deflect-next are both Python, they can potentially be
      more intelligent with each other.
      * Responsibilities overlap with: DNS zone file templating, certificate uploading, etc.
      * It's currently possible for a bad `sites.yml` to cause errors in the config
        generation code. We can/do ignore the errors silently to proceed, but it would be
        better to catch them in deflect-web so we can tell the user what happened.

* Containers are an improvement over no containers.
    * Previously, all components were installed on Debian stable. If something needed a newer
      version of Debian, or if that version became EOL, we'd have to spend a long time upgrading
      everything.
    * When we start a new container, we know that it doesn't care about the state of the host
      or any of the other containers (except for explicitly defined fs mounts and namespace shares).
    * When we kill/remove a container, we know it didn't leave a mess behind on the host.
    * the `docker-compose.yml` config in the Banjax repo has been a very convenient way
      to demo the interaction between Nginx and Banjax (eg. for debugging an issue, or testing
      out a new feature before porting it to the deflect-next config/orchestration parts).

* Banjax as a Go service is an improvement over Banjax as a plugin.
    * Previously I had to have a Debian VM running ATS and had to load the plugin into ATS
      to test it. I can develop and test the Go service on its own.
    * C++ is a nasty language, Go is a nice language.
    * We don't have to know about internal ATS state machine details to answer simple questions
      like "does Banjax serve a challenge before or after the cache lookup?". This is
      easily determined (or changed) from the Nginx config file now.
    * Other proxy servers than Nginx should be usable if they support `X-Accel-Redirect`.
    * We don't need Swabber because the Go service can talk to `iptables` by itself.



