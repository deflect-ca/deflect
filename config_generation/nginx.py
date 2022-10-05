# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import nginx
import os
import shutil
import tarfile
import json
from jinja2 import Template
from pyaml_env import parse_config

import logging
from util.helpers import (
        get_logger,
        get_config_yml_path,
        path_to_input,
        path_to_output,
        path_to_containers,
)

logger = get_logger(__name__)
CONFIG = None

def redirect_to_https_server(site: dict):
    """
    Add a 301 to https
    """
    return nginx.Conf(
        nginx.Server(
            nginx.Key('set', "$loc_in \"redir_to_ssl\""),
            nginx.Key('set', "$loc_out \"redir_to_ssl\""),
            nginx.Key('server_name', " ".join(site["server_names"])),
            nginx.Key('listen', '80'),
            nginx.Key(
                # note that we always redirect to the non-www hostname
                'return', "301 https://$server_name$request_uri")
        )
    )


def ssl_certificate_and_key(dconf, site):
    keys = []

    if site.get("uploaded_cert_bundle_name"):
        chain_path = f"/etc/ssl-uploaded/{site['public_domain']}.cert-and-chain"
        key_path = f"/etc/ssl-uploaded/{site['public_domain']}.key"
    else:
        chain_path = f"/etc/ssl/sites/{site['public_domain']}/fullchain1.pem"
        key_path = f"/etc/ssl/sites/{site['public_domain']}/privkey1.pem"

    keys.append(nginx.Key('ssl_certificate', chain_path))
    keys.append(nginx.Key('ssl_certificate_key', key_path))
    return keys


def proxy_to_upstream_server(site, dconf, edge_https, origin_https):
    server = nginx.Server()

    server.add(nginx.Key('server_name', " ".join(site["server_names"])))
    server.add(nginx.Key('proxy_set_header', 'Host $host'))

    if edge_https:
        server.add(nginx.Key('listen', '443 ssl http2'))
        server.add(*ssl_certificate_and_key(dconf, site))
        server.add(nginx.Key('ssl_ciphers', dconf["nginx"]["ssl_ciphers"]))
    else:
        server.add(nginx.Key('listen', '80'))

    if dconf['nginx'].get('header_srv_custom', False):
        server.add(nginx.Key('server_tokens', "off"))

    server.add(nginx.Key('include', 'snippets/error_pages.conf'))

    # for sites who disable logging, we send their log to baskerville for ML only
    # therefore put it in different file and send to different logstash topic
    server.add(nginx.Key('set', f"$disable_logging {1 if site['disable_logging'] else 0}"))
    if site['disable_logging']:
        server.add(nginx.Key('access_log', "/var/log/nginx/banjax-format.log banjax_format"))  # always send to banjax
        server.add(nginx.Key('access_log', "/var/log/nginx/nginx-logstash-format-temp.log logstash_format_json"))

    for pattern in sorted(site['password_protected_paths']):
        server.add(
            pass_prot_location(pattern, origin_https, site)
        )

    # XXX i think the order we match these in matters
    for exc in sorted(site['cache_exceptions']):
        server.add(
            cache_exc_location(exc, origin_https, site)
        )

    if not site['static_to_banjax']:
        server.add(
            static_files_location(site, dconf, edge_https, origin_https)
        )

    server.add(
        slash_location(origin_https, site)
    )

    server.add(
        access_denied_location(site)
    )

    server.add(
        access_granted_location_block(site, dconf, edge_https, origin_https)
    )

    server.add(
        fail_open_location_block(site, dconf, edge_https, origin_https)
    )

    server.add(
        fail_closed_location_block(site, dconf, edge_https, origin_https)
    )

    return server


def proxy_pass_to_banjax_keys(origin_https, site):
    global CONFIG
    return [
        # nginx.Key('access_log', "off"),  # XXX maybe log to a different file

        # nginx.Key('proxy_cache', "auth_requests_cache"),
        nginx.Key('proxy_cache_key',
                  '"$remote_addr $host $cookie_deflect_challenge"'),

        nginx.Key('proxy_set_header', "X-Requested-Host $host"),
        nginx.Key('proxy_set_header', "X-Client-IP $remote_addr"),
        nginx.Key('proxy_set_header', "X-Requested-Path $request_uri"),
        nginx.Key('proxy_set_header', "X-Client-User-Agent $http_user_agent"),
        nginx.Key('proxy_pass_request_body', "off"),
        # to make keepalive work
        # XXX remove 0706 client are getting 504 in pass_prot
        #nginx.Key('proxy_set_header', "Connection \"\""),
        #nginx.Key('proxy_http_version', "1.1"),
        nginx.Key('proxy_pass', "http://banjax/auth_request?"),
        #nginx.Key('proxy_read_timeout', str(CONFIG['nginx'].get('banjax_proxy_read_timeout', 30))),
        #nginx.Key('proxy_connect_timeout', str(CONFIG['nginx'].get('banjax_proxy_connect_timeout', 30))),
    ]


def pass_prot_location(pattern, origin_https, site):
    # XXX triage and review all my location matching patterns at some point.
    # XXX i don't think we're ensuring there aren't overlapping patterns?
    if "." in pattern:
        location = nginx.Location(f"= /{pattern}")
    else:
        location = nginx.Location(f"/{pattern}/")

    location.add(nginx.Key('set', "$loc_in \"pass_prot\""))

    location.add(nginx.Key('proxy_cache', 'off'))
    location.add(nginx.Key('proxy_cache_valid', '0'))

    location.add(nginx.Key('proxy_intercept_errors', 'on'))
    location.add(nginx.Key('error_page', "500 /500.html"))
    location.add(nginx.Key('error_page', "502 /502-banjax.html"))
    location.add(*proxy_pass_to_banjax_keys(origin_https, site))

    return location


# XXX looks like i'm not converting these in the site dict code right now
def cache_exc_location(exc, origin_https, site):
    location = nginx.Location(f"~* {exc['location_regex']}")

    location.add(nginx.Key('set', "$loc_in \"cache_exc\""))

    location.add(
        *default_site_content_cache_include_conf(
            exc['cache_time_minutes'], site
        ))

    location.add(nginx.Key('error_page', "500 @access_granted"))
    location.add(*proxy_pass_to_banjax_keys(origin_https, site))

    return location


def slash_location(origin_https, site):
    location = nginx.Location('/')
    location.add(nginx.Key('set', "$loc_in \"slash_block\""))
    # location.add(*default_site_content_cache_include_conf(site['default_cache_time_minutes'], site))

    """
    This is a tricky part, if banjax is down, we will get error page 502
    but we redirect this to @fail_open. In that section, we still do
    reverse proxy to bypass banjax.

    Confirm fail open working
    """
    location.add(nginx.Key('proxy_intercept_errors', 'on'))
    location.add(nginx.Key('error_page', "500 @fail_open"))
    location.add(nginx.Key('error_page', "502 @fail_open"))
    location.add(*proxy_pass_to_banjax_keys(origin_https, site))

    return location

# XXX somehow this needs to be an @access_granted_cache_static block or something


def static_files_location(site, global_config, edge_https, origin_https):
    # XXX how to avoid sending js challenger pages to (embedded) filetypes?
    location = nginx.Location(
        '~* \.(css|js|json|png|gif|ico|jpg|jpeg|svg|ttf|woff|woff2|avi|bin|bmp|dmg|doc|docx|dpkg|exe|flv|htm|html|ics|img|m2a|m2v|mov|mp3|mp4|mpeg|mpg|msi|pdf|pkg|png|ppt|pptx|ps|rar|rss|rtf|swf|tif|tiff|txt|webp|wmv|xhtml|xls|xml|zip)$')
    location.add(nginx.Key('set', "$loc_in \"static_file\""))
    location.add(nginx.Key('set', "$loc_out \"static_file\""))
    location_contents = _access_granted_fail_open_location_contents(
        site, global_config, edge_https, origin_https)
    location.add(*location_contents)

    # location.add(nginx.Key('proxy_cache_valid', '200 302 10m'))  # XXX config
    # location.add(nginx.Key('proxy_cache_valid', '404 30s'))  # XXX other error pages?

    # location.add(nginx.Key('error_page', "500 @access_granted"))
    # location.add(*proxy_pass_to_banjax_keys(origin_https, site))

    return location


def _access_granted_fail_open_location_contents(
        site, global_config, edge_https, origin_https
):
    location_contents = []
    location_contents += default_site_content_cache_include_conf(
        site['default_cache_time_minutes'], site
    )

    limit_except = nginx.LimitExcept(
        'GET POST PUT DELETE MKCOL COPY MOVE OPTIONS PROPFIND PROPPATCH LOCK UNLOCK PATCH')
    limit_except.add(nginx.Key('deny', 'all'))
    location_contents.append(limit_except)
    if global_config['nginx'].get('header_srv_custom', False):
        header_srv_custom_str = global_config['nginx'].get('header_srv_custom_str', 'Deflect (nginx)')
        location_contents.append(nginx.Key('add_header', f"X-Server '{header_srv_custom_str}'"))
    if global_config['nginx'].get('header_show_time', False):
        location_contents.append(nginx.Key('add_header', "X-Deflect-Upstream-Response-Time $upstream_response_time"))
        location_contents.append(nginx.Key('add_header', "X-Deflect-Upstream-Connect-Time $upstream_connect_time"))
        location_contents.append(nginx.Key('add_header', "X-Deflect-Upstream-Status $upstream_status"))
    location_contents.append(nginx.Key('add_header', "X-Deflect-Cache $upstream_cache_status"))
    location_contents.append(nginx.Key('add_header', "X-Deflect-Edge $hostname"))

    if site['enable_sni']:
        location_contents.append(nginx.Key('proxy_ssl_server_name', "on"))

    if site.get('alias_of_domain'):
        www_domain = True if site.get('alias_of_domain').startswith('www.') else False
        parent_site = {
            'public_domain': site.get('alias_of_domain'),
            'origin_https_port': 443,
            'origin_http_port': 80,
            'origin_ip': site.get('origin_ip'),
        }
        logger.info("setting %s as an alias of domain: %s",
            site['public_domain'], parent_site.get('public_domain'))
        location_contents.append(nginx.Key('proxy_set_header', "X-Forwarded-For $proxy_add_x_forwarded_for"))
        location_contents.append(nginx.Key('proxy_set_header', f"Host {parent_site.get('public_domain')}"))
        # disable gzip from origin
        location_contents.append(nginx.Key('proxy_set_header', "Accept-Encoding \"\""))
        location_contents.append(nginx.Key('proxy_hide_header', "Upgrade"))
        location_contents.append(nginx.Key('proxy_hide_header', "Link"))
        location_contents.append(nginx.Key('proxy_ssl_name', parent_site.get('public_domain')))
        location_contents.append(nginx.Key('proxy_pass_request_body', "on"))
        # handle "Location:" header replace
        for proto in ['http', 'https']:
            for triple_w in ['', 'www.']:
                location_contents.append(nginx.Key('proxy_redirect',
                    f"'{proto}://{parent_site.get('public_domain')}' '{proto}://{triple_w}{site.get('public_domain')}'"))
        if www_domain:
            # remove www.
            domain_to_replace = parent_site.get('public_domain').replace('www.', '')
        location_contents.append(nginx.Key('sub_filter_once', "off"))
        location_contents.append(nginx.Key('sub_filter', f"'{parent_site.get('public_domain')}' 'www.{site.get('public_domain')}'"))
        location_contents.append(nginx.Key('sub_filter', f"'{domain_to_replace}' '{site.get('public_domain')}'"))
        location_contents.append(nginx.Key('sub_filter_types', "text/html text/css text/xml text/plain text/javascript application/javascript application/json"))
        return _proxy_pass_to_origin(location_contents, parent_site, origin_https)

    # normal site settings
    location_contents.append(nginx.Key('proxy_set_header', "X-Forwarded-For $proxy_add_x_forwarded_for"))
    location_contents.append(nginx.Key('proxy_set_header', "Host $host"))
    location_contents.append(nginx.Key('proxy_hide_header', "Upgrade"))
    location_contents.append(nginx.Key('proxy_ssl_name', '$host'))
    location_contents.append(nginx.Key('proxy_pass_request_body', "on"))

    return _proxy_pass_to_origin(location_contents, site, origin_https)


def _proxy_pass_to_origin(location_contents, site, origin_https):
    if origin_https:
        # if origin_https_port == 80, we assume it is http
        proto = 'https' if site['origin_https_port'] != 80 else 'http'
        location_contents.append(nginx.Key(
            'proxy_pass', f"{proto}://{site['origin_ip']}:{site['origin_https_port']}"))
    else:
        location_contents.append(nginx.Key(
            'proxy_pass', f"http://{site['origin_ip']}:{site['origin_http_port']}"))

    return location_contents


def access_granted_location_block(site, global_config, edge_https, origin_https):
    location = nginx.Location("@access_granted")
    location.add(nginx.Key('set', "$loc_out \"access_granted\""))
    location.add(nginx.Key('set', "$banjax_decision \"$upstream_http_x_banjax_decision\""))
    location_contents = _access_granted_fail_open_location_contents(
        site, global_config, edge_https, origin_https)
    location.add(*location_contents)

    # 502 in access granted section means origin is down, not banjax
    location.add(nginx.Key('error_page', "502 /502.html"))
    location.add(nginx.Key('error_page', "504 /504.html"))
    return location


def fail_open_location_block(site, global_config, edge_https, origin_https):
    location = nginx.Location("@fail_open")
    location.add(nginx.Key('set', "$loc_out \"fail_open\""))
    location.add(nginx.Key('set', "$banjax_error \"$upstream_http_x_banjax_error\""))
    location_contents = _access_granted_fail_open_location_contents(
        site, global_config, edge_https, origin_https)
    location.add(*location_contents)

    # 502 in fail open section means origin is down, not banjax
    location.add(nginx.Key('error_page', "502 /502.html"))
    location.add(nginx.Key('error_page', "504 /504.html"))
    return location


def port_80_server_block(dconf, site, http_req_does):
    if http_req_does == 'redirect':
        return redirect_to_https_server(site)

    elif http_req_does == 'http_proxy_pass':
        # legacy behavior. maybe we want to upgrade http -> https when we can?
        return proxy_to_upstream_server(
            site, dconf, edge_https=False, origin_https=False)

    else:
        raise Exception(f"unrecognized http_request_does: {http_req_does}")


def port_443_server_block(dconf, site, https_req_does):
    if https_req_does == 'https_proxy_pass':
        return proxy_to_upstream_server(
            site, dconf, edge_https=True, origin_https=True)

    elif https_req_does == 'http_proxy_pass':
        return proxy_to_upstream_server(
            site, dconf, edge_https=True, origin_https=False)

    else:
        raise Exception(f"unrecognized https_request_does: {https_req_does}")


def per_site_include_conf(site, dconf):
    nconf = nginx.Conf()

    """
    map $upstream_http_set_cookie $bypass_cache_{site_name} {
        "~*pll" 0;
        "~*="   1;
        default 0;
    }
    """
    if len(site['cache_cookie_allowlist']) > 0:
        site_name = site['public_domain'].replace('.', '_')
        cache_cookie_map = nginx.Map(f'$upstream_http_set_cookie $bypass_cache_{site_name}')
        for cookie in site['cache_cookie_allowlist']:
            # if regex match these cookie, allow cache
            cache_cookie_map.add(nginx.Key(f"~*{cookie}", '0'))
        # default prevent cache if there is set-cookie
        cache_cookie_map.add(nginx.Key("~*=", '1'))
        cache_cookie_map.add(nginx.Key("default", '0'))
        nconf.add(cache_cookie_map)

    # 301 to https:// or proxy_pass to origin port 80
    http_req_does = site['http_request_does']
    if http_req_does != "nothing":
        nconf.add(port_80_server_block(dconf, site, http_req_does))

    # proxy_pass to origin port 80 or 443
    https_req_does = site['https_request_does']
    if https_req_does != "nothing":
        nconf.add(port_443_server_block(dconf, site, https_req_does))

    return nconf


# https://serverfault.com/questions/578648/properly-setting-up-a-default-nginx-server-for-https/1044022#1044022
# this keeps nginx from choosing some random site if it can't find one...
def empty_catchall_server_http(config):
    server = nginx.Server(
        nginx.Key('listen', "80 default_server"),
        nginx.Key('listen', "[::]:80 default_server"),
        nginx.Key('server_name', "_")
    )
    if config['nginx'].get('default_server_rlimit'):
        server.add(nginx.Key('limit_conn', 'default_http_limit_per_ip 1'))
        server.add(nginx.Key('limit_req', 'zone=default_http_req_limit burst=5 nodelay'))

    server.add(nginx.Key('return', '444'))

    return [
        nginx.Key('limit_conn_zone', '$binary_remote_addr zone=default_http_limit_per_ip:10m'),
        nginx.Key('limit_req_zone','$binary_remote_addr zone=default_http_req_limit:10m rate=1r/s'),
        server,
    ]


def empty_catchall_server_https(config):
    server = nginx.Server(
        nginx.Key('listen', "443 ssl http2 default_server"),
        nginx.Key('listen', "[::]:443 ssl http2 default_server"),
        nginx.Key('server_name', "_"),
        nginx.Key('ssl_ciphers', "aNULL"),
        nginx.Key('ssl_certificate', "data:$empty"),
        nginx.Key('ssl_certificate_key', "data:$empty"),
    )

    if config['nginx'].get('default_server_rlimit'):
        server.add(nginx.Key('limit_conn', 'default_https_limit_per_ip 1'))
        server.add(nginx.Key('limit_req', 'zone=default_https_req_limit burst=5 nodelay'))

    server.add(nginx.Key('return', '444'))

    return [
        nginx.Key('limit_conn_zone', '$binary_remote_addr zone=default_https_limit_per_ip:10m'),
        nginx.Key('limit_req_zone','$binary_remote_addr zone=default_https_req_limit:10m rate=1r/s'),
        server,
    ]


# the built-in stub_status route shows us the number of active connections.
# /info is useful for checking what version of config is loaded.
def info_and_stub_status_server(timestamp, dconf):
    server = nginx.Server(
        nginx.Key('listen', "80"),
        nginx.Key('server_name', "127.0.0.1"),  # metricbeat doesn't allow setting the Host header
        nginx.Key('allow', "127.0.0.1"),
    )

    if 'nginx' in dconf:
        for item in dconf['nginx']['allow_stub_status']:
            server.add(nginx.Comment(item['comment']))
            server.add(nginx.Key('allow', item['ip']))

    info_json = json.dumps({
        "config_version": timestamp,
        "hostname": "$hostname"
    }).replace('"', '\\"')
    server.add(
        nginx.Key('deny', "all"),
        nginx.Key('access_log', "off"),

        nginx.Location('/info',
            nginx.Key('return', f"200 \"{info_json}\"")),

        nginx.Location('/stub_status',
            nginx.Key('stub_status', None))
    )
    return server


def banjax_server(dconf):
    server = nginx.Server(
        nginx.Key('listen', "80"),
        nginx.Key('server_name', "banjax"),
        nginx.Key('allow', "127.0.0.1"),
    )

    if 'nginx' in dconf:
        for item in dconf['nginx']['allow_banjax_info']:
            server.add(nginx.Comment(item['comment']))
            server.add(nginx.Key('allow', item['ip']))

    server.add(
        nginx.Key('deny', "all"),
        nginx.Key('access_log', "off"),  # XXX?

        # should we just pass every request?
        nginx.Location('/info',
            nginx.Key('proxy_pass', "http://127.0.0.1:8081/info")),

        nginx.Location('/decision_lists',
            nginx.Key('proxy_pass', "http://127.0.0.1:8081/decision_lists")),

        nginx.Location('/rate_limit_states',
            nginx.Key('proxy_pass', "http://127.0.0.1:8081/rate_limit_states")),
    )
    return server


def cache_purge_server(dconf):
    server = nginx.Server(
        nginx.Key('listen', "80"),
        nginx.Key('server_name', '"cache_purge"'),
        nginx.Key('access_log', "off"),
        nginx.Key('allow', "127.0.0.1"),
    )

    if 'nginx' in dconf:
        for item in dconf['nginx']['allow_purge']:
            server.add(nginx.Comment(item['comment']))
            server.add(nginx.Key('allow', item['ip']))

    server.add(
        nginx.Key('deny', "all"),

        nginx.Location('~ /auth_requests/(.*)',
            nginx.Key('proxy_cache_purge', "auth_requests_cache $1")),

        nginx.Location('~ /site_content/(.*)',
            nginx.Key('proxy_cache_purge', "site_content_cache $1")),
    )
    return server


def init_nginx_var_with_map(var_name, default_val='-', base_var='host', add_keys=[]):
    map = nginx.Map(f"${base_var} ${var_name}")
    for key in add_keys:
        map.add(key)
    if isinstance(default_val, str):
        map.add(nginx.Key('default', f"\"{default_val}\""))
    else:
        map.add(nginx.Key('default', f"{default_val}"))
    return map


def http_block(dconf, timestamp):
    http = nginx.Http()
    # optimization
    # XXX could not build optimal server_names_hash, you should increase either server_names_hash_max_size: 512 or server_names_hash_bucket_size: 128; ignoring server_names_hash_bucket_size
    http.add(nginx.Key('server_names_hash_bucket_size', str(dconf['nginx'].get('server_names_hash_bucket_size', 64))))
    http.add(nginx.Key('server_names_hash_max_size', str(dconf['nginx'].get('server_names_hash_max_size', 1024))))

    # copies data between one FD and other from within the kernel
    # faster than read() + write()
    http.add(nginx.Key('sendfile', 'on'))

    # send headers in one piece, it is better than sending them one by one
    http.add(nginx.Key('tcp_nopush', 'on'))

    # proxy buffer settings for large header
    if dconf['nginx'].get('increase_proxy_buffer_size') != False:
        http.add(nginx.Key('proxy_busy_buffers_size', '256k'))
        http.add(nginx.Key('proxy_buffers', '8 256k'))
        http.add(nginx.Key('proxy_buffer_size', '128k'))

    http.add(nginx.Key('log_format', "banjax_format '$msec $remote_addr $request_method $host $request $http_user_agent'"))
    http.add(nginx.Key('log_format', 'nginx_default \'$remote_addr $server_name $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for" $server_port $upstream_bytes_received "$sent_http_content_type" $host "$https" "$http_cookie"\''))

    # Init $banjax_decision to avoid var not defined errors
    # We use $host here but it does not matter since we make it default to "-"
    http.add(init_nginx_var_with_map('banjax_decision'))
    # Error if banjax panic
    http.add(init_nginx_var_with_map('banjax_error'))
    http.add(init_nginx_var_with_map('disable_logging', 0))

    http.add(nginx.Key('log_format', """logstash_format_json escape=json
        '{'
            '"time_local": "$time_local",'
            '"request_id": "$request_id",'
            '"client_user": "$remote_user",'
            '"client_ip": "$remote_addr",'
            '"http_request_scheme": "$scheme",'
            '"client_request_method": "$request_method",'
            '"client_request_host": "$host",'
            '"http_response_code": $status,'
            '"reply_length_bytes": $body_bytes_sent,'
            '"cache_result": "$upstream_cache_status",'
            '"http_request_version": "$server_protocol",'
            '"referer": "$http_referer",'
            '"client_ua": "$http_user_agent",'
            '"client_url": "$uri",'
            '"querystring": "$args",'
            '"proxy_host": "$proxy_host",'
            '"proxy_port": "$proxy_port",'
            '"content_type": "$sent_http_content_type",'
            '"request_time": $request_time,'
            '"forwardedfor": "$http_x_forwarded_for",'
            '"loc_in": "$loc_in",'
            '"loc_out": "$loc_out",'
            '"upstream_addr": "$upstream_addr",'
            '"upstream_status": "$upstream_status",'
            '"upstream_response_time": "$upstream_response_time",'
            '"upstream_header_time": "$upstream_header_time",'
            '"upstream_connect_time": "$upstream_connect_time",'
            '"upstream_bytes_sent": "$upstream_bytes_sent",'
            '"upstream_bytes_received": "$upstream_bytes_received",'
            '"banjax_decision": "$banjax_decision",'
            '"banjax_error": "$banjax_error",'
            '"disable_logging": $disable_logging'
        '}' """
    ))

    http.add(init_nginx_var_with_map(
        'loggable', default_val=1, base_var='disable_logging', add_keys=[nginx.Key('1', '0')]))

    http.add(nginx.Key('error_log', "/dev/stdout warn"))
    if dconf['nginx'].get('default_access_log', True):
        http.add(nginx.Key('access_log', "/var/log/nginx/access.log nginx_default"))
    http.add(nginx.Key('access_log', "/var/log/nginx/banjax-format.log banjax_format"))
    http.add(nginx.Key('access_log', "/var/log/nginx/nginx-logstash-format.log logstash_format_json if=$loggable"))

    http.add(nginx.Key('proxy_cache_path', "/data/nginx/auth_requests_cache keys_zone=auth_requests_cache:10m"))
    http.add(nginx.Key('proxy_cache_path', "/data/nginx/site_content_cache keys_zone=site_content_cache:50m inactive=30m max_size=50g"))
    http.add(nginx.Key('client_max_body_size', "2G"))  # XXX think about this

    http.add(nginx.Key('proxy_set_header', "X-Forwarded-For $proxy_add_x_forwarded_for"))

    # https://serverfault.com/questions/578648/properly-setting-up-a-default-nginx-server-for-https/1044022#1044022
    # this keeps nginx from choosing some random site if it can't find one
    http.add(nginx.Map('"" $empty', nginx.Key("default", '""')))
    http.add(*empty_catchall_server_http(dconf))
    http.add(*empty_catchall_server_https(dconf))

    # /info and /stub_status
    http.add(info_and_stub_status_server(timestamp, dconf))

    # exposing a few banjax endpoints
    http.add(banjax_server(dconf))

    # purge the auth_requests or site_content caches
    http.add(cache_purge_server(dconf))

    # only add upstream once
    banjax_upstream = nginx.Upstream('banjax')
    banjax_upstream.add(nginx.Key('server', '127.0.0.1:8081'))
    # XXX remove 0706 client are getting 504 in pass_prot
    # banjax_upstream.add(nginx.Key('keepalive', str(dconf['nginx'].get('banjax_keepalive', '128'))))
    http.add(banjax_upstream)

    # include all the per-site files
    http.add(nginx.Key('include', "/etc/nginx/sites.d/*.conf"))

    return http


def top_level_conf(dconf, timestamp):
    nconf = nginx.Conf()

    nconf.add(nginx.Key('load_module', '/usr/lib/nginx/modules/ngx_http_cache_purge_module_torden.so'))

    # you must set worker processes based on your CPU cores, nginx does not benefit from setting more than that
    nconf.add(nginx.Key('worker_processes', 'auto'))

    # number of file descriptors used for nginx
    # the limit for the maximum FDs on the server is usually set by the OS.
    # if you don't set FD's then OS settings will be used which is by default 2000
    nconf.add(nginx.Key('worker_rlimit_nofile', '100000'))

    # determines how much clients will be served per worker
    # max clients = worker_connections * worker_processes
    # max clients is also limited by the number of socket connections available on the system (~64k)
    nconf.add(nginx.Events(
        nginx.Key('worker_connections', str(dconf['nginx'].get('worker_connections', '4096'))),
        nginx.Key('use', 'epoll'),
    ))

    nconf.add(http_block(dconf, timestamp))

    return nconf


def default_site_content_cache_include_conf(cache_time_minutes, site):
    # disable cache for this site
    if site["cache_disable"]:
        return []

    arr = [
        nginx.Key('proxy_cache', "site_content_cache"),
        nginx.Key('proxy_cache_key', '"$host $scheme $uri $is_args $args"'),
        nginx.Key('proxy_cache_valid', f"200 302 {str(cache_time_minutes)}m"),
        # for 5XX error page, 10s micro cache to prevent flooding the origin
        nginx.Key('proxy_cache_valid', "500 501 502 503 504 10s"),
        nginx.Key('proxy_cache_valid', "any 30s"),
        # do not cache if user logged into to pass_prot
        nginx.Key('proxy_cache_bypass', "$cookie_deflect_password2"),
        # do not cache if hit number is low, especailly when there is /?s={rand}
        nginx.Key('proxy_cache_min_uses', '3'),
    ]

    if site["cache_lock"]:
        arr.append(nginx.Key('proxy_cache_lock', "on"))

    if site['cache_use_stale']:
        arr.append(nginx.Key('proxy_cache_use_stale', "updating error timeout invalid_header http_500 http_502 http_503 http_504"))

    # option to force site to use 'Vary: Accept-Encoding' header
    if site['cache_override_vary_only_encoding']:
        arr += [
            nginx.Key('proxy_ignore_headers', "Vary"),
            nginx.Key('proxy_hide_header', "Vary"),
            nginx.Key('add_header', "Vary 'Accept-Encoding'"),
        ]

    # ignore cache-control header from origin
    if site['cache_ignore_cache_control']:
        arr += [
            nginx.Key('proxy_ignore_headers', "Cache-Control"),
            nginx.Key('proxy_hide_header', "Cache-Control"),
        ]

    if site['cache_ignore_expires']:
        arr += [
            nginx.Key('proxy_ignore_headers', "Expires"),
            nginx.Key('proxy_hide_header', "Expires"),
        ]

    # by default, do not cache content if 'Set cookie' header present
    # but do cache if cookie name match config
    if len(site['cache_cookie_allowlist']) > 0:
        site_name = site['public_domain'].replace('.', '_')
        arr.append(nginx.Key('proxy_ignore_headers', 'Set-cookie'))
        arr.append(nginx.Key('proxy_no_cache', f'$bypass_cache_{site_name}'))
        arr.append(nginx.Key('add_header', f'X-Deflect-Cache-Bypass $bypass_cache_{site_name}'))

    return arr


def access_denied_location(site):
    location = nginx.Location('@access_denied')
    location.add(nginx.Key('set', "$loc_out \"access_denied\""))
    location.add(nginx.Key('set', "$banjax_decision \"$upstream_http_x_banjax_decision\""))
    # Confirm working
    location.add(nginx.Key('error_page', "403 /403.html"))
    location.add(nginx.Key('return', "403"))
    return location


def fail_closed_location_block(site, global_config, edge_https, origin_https):
    location = nginx.Location('@fail_closed')
    location.add(nginx.Key('set', "$loc_out \"fail_closed\""))
    # This block isn't used for now
    location.add(nginx.Key('error_page', "500 /500.html"))
    location.add(nginx.Key('return', "500"))
    return location


def get_output_dir(formatted_time, dnet):
    return os.path.join(path_to_output(), formatted_time, f"etc-nginx-{dnet}")


# XXX ugh this needs redoing
def generate_nginx_config(all_sites, config, formatted_time):
    global CONFIG
    CONFIG = config
    # clear out directories
    for dnet in sorted(config['dnets']):
        output_dir = get_output_dir(formatted_time, dnet)
        if os.path.isdir(output_dir):
            logger.debug(f"removing {output_dir}")
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)

        with open(output_dir + "/nginx.conf", "w") as f:
            nginx.dump(top_level_conf(config, formatted_time), f)

        info_dir = output_dir + "/info"
        os.mkdir(info_dir)
        with open(info_dir + "/info", "w") as f:
            f.write(json.dumps({"config_version": formatted_time}))

        os.mkdir(output_dir + "/sites.d")
        shutil.copytree(
            f"{path_to_containers()}/nginx/error-pages",
            f"{output_dir}/error-pages")
        shutil.copytree(
            f"{path_to_containers()}/nginx/snippets",
            f"{output_dir}/snippets")

    # write out the client sites
    for name, site in all_sites['client'].items():
        public_domain = site['public_domain']
        output_dir = get_output_dir(formatted_time, site['dnet'])
        # XXX check for cert existence properly
        if False:
            logger.debug(f"!!! http-only for {site} because we couldn't find certs !!!")
            conf = nginx.Conf()
            conf.add(proxy_to_upstream_server(site, config, edge_https=False, origin_https=False))
            with open(f"{output_dir}/sites.d/{public_domain}.conf", "w") as f:
                nginx.dump(conf, f)
        with open(f"{output_dir}/sites.d/{public_domain}.conf", "w") as f:
            nginx.dump(per_site_include_conf(site, config), f)

    # write out the system sites
    for name, site in all_sites['system'].items():
        # make these live on every dnet?
        for dnet in config['dnets']:
            output_dir = get_output_dir(formatted_time, dnet)
            with open(f"{path_to_input()}/templates/system_site_nginx.conf.j2", "r") as tf:
                template = Template(tf.read())
                with open(f"{output_dir}/sites.d/{name}.conf", "w") as f:
                    f.write(template.render(
                        server_name=name,
                        cert_name=name,
                        ssl_ciphers=config['nginx']['ssl_ciphers'],
                        proxy_pass=f"http://{site['origin_ip']}:{site['origin_http_port']}",
                    ))

    # create tarfiles
    for dnet in config['dnets']:
        output_dir = get_output_dir(formatted_time, dnet)
        if os.path.isfile(f"{output_dir}.tar"):
            os.remove(f"{output_dir}.tar")

        logger.info(f"Writing {output_dir}.tar")
        with tarfile.open(f"{output_dir}.tar", "x") as tar:
            tar.add(output_dir, arcname=".")


if __name__ == "__main__":
    from orchestration.shared import get_all_sites

    config = parse_config(get_config_yml_path())

    all_sites, formatted_time = get_all_sites()

    generate_nginx_config(all_sites, config, formatted_time)
