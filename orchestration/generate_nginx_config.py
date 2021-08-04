# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import nginx
import os
import shutil
import yaml
import tarfile
import json
from jinja2 import Template
from pyaml_env import parse_config

# TODO: use config
test_domain = 'test.me.uk'

def redirect_to_https_server_block(site: dict):
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
                'return', f"301 https://$server_name$request_uri/")
        )
    )


def access_log_banjax_next_format():
    return nginx.Key('access_log', "/var/log/banjax-next/banjax-next-format.log banjax_next_format")


def proxy_pass_to_origin_server_block(site, global_config, edge_https, origin_https):
    server = nginx.Server()

    server.add(nginx.Key('server_name', " ".join(site["server_names"])))
    server.add(nginx.Key('proxy_set_header', 'Host $host'))

    if edge_https:
        server.add(nginx.Key('listen', '443 ssl http2'))
        if site.get("uploaded_cert_bundle_name"):
            filename = f"{site['public_domain']}"
            server.add(nginx.Key('ssl_certificate',
                                 f"/etc/ssl-uploaded/{filename}.cert-and-chain"))
            server.add(nginx.Key('ssl_certificate_key',
                                 f"/etc/ssl-uploaded/{filename}.key"))
        else:
            server.add(nginx.Key('ssl_certificate',
                                 f"/etc/ssl/sites/{site['public_domain']}.le.fullchain.crt"))
            server.add(nginx.Key('ssl_certificate_key',
                                 f"/etc/ssl/sites/{site['public_domain']}.le.key"))
        # XXX config
        server.add(nginx.Key('ssl_ciphers', global_config["ssl_ciphers"]))
    else:
        server.add(nginx.Key('listen', '80'))

    for password_protected_path in site['password_protected_paths']:
        server.add(proxy_pass_password_protected_path(
            password_protected_path, origin_https, site))
    # XXX how to check these exceptions are valid and in the right order?
    for cache_exception in site['cache_exceptions']:
        server.add(proxy_pass_cache_exception(
            cache_exception, origin_https, site))
    server.add(proxy_pass_to_origin_location_block_dont_challenge_static_files(
        site, global_config, edge_https, origin_https))
    server.add(proxy_pass_to_origin_location_block(origin_https, site))
    server.add(access_denied_location(site))
    server.add(access_granted_location_block(
        site, global_config, edge_https, origin_https))
    server.add(fail_open_location_block(
        site, global_config, edge_https, origin_https))
    server.add(fail_closed_location_block(
        site, global_config, edge_https, origin_https))
    return server


def proxy_pass_to_banjax_keys(origin_https, site):
    return [
        # nginx.Key('access_log', "off"),  # XXX maybe log to a different file

        # nginx.Key('proxy_cache', "auth_requests_cache"),
        nginx.Key('proxy_cache_key',
                  '"$remote_addr $host $cookie_deflect_challenge"'),

        nginx.Key('proxy_set_header', "X-Requested-Host $host"),
        nginx.Key('proxy_set_header', "X-Client-IP $remote_addr"),
        nginx.Key('proxy_set_header', "X-Requested-Path $request_uri"),
        # XXX i just want to discard the path
        # TODO: use config for port, ip
        nginx.Key('proxy_pass', "http://127.0.0.1:8081/auth_request?")
    ]

# XXX make sure trailing slashes are right


def proxy_pass_password_protected_path(password_protected_path, origin_https, site):
    location = nginx.Location(f"/{password_protected_path}/")
    location.add(nginx.Key('set', "$loc_in \"pass_protected\""))
    # XXX force no-cache here
    location.add(nginx.Key('proxy_cache_valid', '0'))
    # location.add(*password_protected_auth_request_keys())

    location.add(nginx.Key('error_page', "500 501 502 @fail_closed"))
    location.add(*proxy_pass_to_banjax_keys(origin_https, site))

    return location


def proxy_pass_cache_exception(cache_exception, origin_https, site):
    location = nginx.Location(f"~* {cache_exception['location_regex']}")
    location.add(nginx.Key('set', "$loc_in \"cache_exception\""))
    location.add(
        *default_site_content_cache_include_conf(cache_exception['cache_time_minutes'], site))

    location.add(nginx.Key('error_page', "500 @access_granted"))
    location.add(*proxy_pass_to_banjax_keys(origin_https, site))

    return location


# XXX misnamed
def proxy_pass_to_origin_location_block(origin_https, site):
    location = nginx.Location('/')
    location.add(nginx.Key('set', "$loc_in \"slash_block\""))
    # location.add(*default_site_content_cache_include_conf(site['default_cache_time_minutes'], site))

    location.add(nginx.Key('error_page', "500 501 502 @fail_open"))
    location.add(*proxy_pass_to_banjax_keys(origin_https, site))

    return location

# XXX somehow this needs to be an @access_granted_cache_static block or something


def proxy_pass_to_origin_location_block_dont_challenge_static_files(site, global_config, edge_https, origin_https):
    # XXX how to avoid sending js challenger pages to (embedded) filetypes?
    location = nginx.Location(
        '~* \.(css|js|json|png|gif|ico|jpg|jpeg|svg|ttf|woff|woff2)$')
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


def _access_granted_fail_open_location_contents(site, global_config, edge_https, origin_https):
    location_contents = []
    location_contents += default_site_content_cache_include_conf(site['default_cache_time_minutes'], site)

    limit_except = nginx.LimitExcept(
        'GET POST PUT MKCOL COPY MOVE OPTIONS PROPFIND PROPPATCH LOCK UNLOCK PATCH')
    limit_except.add(nginx.Key('deny', 'all'))
    location_contents.append(limit_except)
    location_contents.append(nginx.Key('add_header', "X-Deflect-Cache $upstream_cache_status"))
    # location_contents.append(nginx.Key('add_header', "X-Deflect-upstream_addr $upstream_addr"))
    location_contents.append(nginx.Key('add_header', "X-Deflect-upstream_response_time $upstream_response_time"))
    location_contents.append(nginx.Key('proxy_set_header', "X-Forwarded-For $proxy_add_x_forwarded_for"))
    location_contents.append(nginx.Key('proxy_set_header', "Host $host"))
    location_contents.append(nginx.Key('proxy_ssl_name', '$host'))

    if origin_https:
        location_contents.append(nginx.Key(
            'proxy_pass', f"https://{site['origin_ip']}:{site['origin_https_port']}"))
    else:
        location_contents.append(nginx.Key(
            'proxy_pass', f"http://{site['origin_ip']}:{site['origin_http_port']}"))

    return location_contents


def access_granted_location_block(site, global_config, edge_https, origin_https):
    location = nginx.Location("@access_granted")
    location.add(nginx.Key('set', "$loc_out \"access_granted\""))
    location_contents = _access_granted_fail_open_location_contents(
        site, global_config, edge_https, origin_https)
    location.add(*location_contents)
    return location


def fail_open_location_block(site, global_config, edge_https, origin_https):
    location = nginx.Location("@fail_open")
    location.add(nginx.Key('set', "$loc_out \"fail_open\""))
    location_contents = _access_granted_fail_open_location_contents(
        site, global_config, edge_https, origin_https)
    location.add(*location_contents)
    return location


def per_site_include_conf(site, global_config):
    conf = nginx.Conf()

    if site['http_request_does'] == 'redirect':
        conf.add(redirect_to_https_server_block(site))
    elif site['http_request_does'] == 'http_proxy_pass':
        # legacy behavior. maybe we want to upgrade http -> https when we can?
        conf.add(proxy_pass_to_origin_server_block(
            site, global_config, edge_https=False, origin_https=False))
    elif site['http_request_does'] == 'nothing':
        pass
    else:
        raise Exception("unrecognized value of http_request_does: %s" %
                        site['http_request_does'])

    if site['https_request_does'] == 'https_proxy_pass':
        conf.add(proxy_pass_to_origin_server_block(
            site, global_config, edge_https=True, origin_https=True))
    elif site['https_request_does'] == 'http_proxy_pass':
        conf.add(proxy_pass_to_origin_server_block(
            site, global_config, edge_https=True, origin_https=False))
    elif site['https_request_does'] == 'nothing':
        pass
    else:
        raise Exception("unrecognized value of https_request_does: %s" %
                        site['https_request_does'])

    return conf


def top_level_conf(timestamp):
    return nginx.Conf(
        nginx.Key(
            'load_module', '/usr/lib/nginx/modules/ngx_http_cache_purge_module_torden.so'),

        nginx.Events(
            nginx.Key('worker_connections', '1024')
        ),

        nginx.Http(
            nginx.Key('server_names_hash_bucket_size', '128'),
            nginx.Key(
                'log_format', "main '$time_local | $status | $request_time (s)| $remote_addr | $request'"),
            nginx.Key(
                'log_format', "banjax_next_format '$msec $remote_addr $request_method $host $request $http_user_agent'"),
            nginx.Key(
                'log_format', "logstash_format '$remote_addr $remote_user [$time_local] \"$request\" $scheme $host $status $bytes_sent \"$http_user_agent\" $upstream_cache_status $content_type $hostname $request_time $scheme://$host$uri \"$http_referer\" \"$http_x_forwarded_for\"'"),

            # XXX i'd rather keep the nginx names, but if they collide with other names in ELK, i can't
            # get the correct types (numbers show up as strings)
            nginx.Key('log_format', """ json_combined escape=json
                '{'
                    '"time_local":"$time_local",'
                    '"remote_addr":"$remote_addr",'
                    '"request_host":"$host",'
                    '"request_uri":"$request_uri",'
                    '"ngx_status": "$status",'
                    '"ngx_body_bytes_sent": "$body_bytes_sent",'
                    '"ngx_upstream_addr": "$upstream_addr",'
                    '"ngx_upstream_cache_status": "$upstream_cache_status",'
                    '"ngx_upstream_response_time": "$upstream_response_time",'
                    '"ngx_request_time": "$request_time",'
                    '"http_referrer": "$http_referer",'
                    '"http_user_agent": "$http_user_agent",'
                    '"ngx_loc_in": "$loc_in",'
                    '"ngx_loc_out": "$loc_out",'
                    '"ngx_loc_in_out": "${loc_in}-${loc_out}"'
                '}' """
                      ),


            nginx.Key('error_log', "/dev/stdout warn"),
            nginx.Key('access_log', "/var/log/nginx/access.log json_combined"),
            nginx.Key('access_log', "/var/log/banjax-next/banjax-next-format.log banjax_next_format"),
            nginx.Key('access_log', "/var/log/banjax-next/nginx-logstash-format.log logstash_format"),

            nginx.Key('proxy_cache_path',
                      "/data/nginx/auth_requests_cache keys_zone=auth_requests_cache:10m"),
            nginx.Key('proxy_cache_path',
                      "/data/nginx/site_content_cache keys_zone=site_content_cache:10m max_size=50g"),

            # https://serverfault.com/questions/578648/properly-setting-up-a-default-nginx-server-for-https/1044022#1044022
            nginx.Map('"" $empty', nginx.Key("default", '""')),

            nginx.Key('proxy_set_header', "X-Forwarded-For $proxy_add_x_forwarded_for"),

            nginx.Server(
                nginx.Key('listen', "80 default_server"),
                nginx.Key('listen', "443 ssl http2 default_server"),
                nginx.Key('listen', "[::]:80 default_server"),
                nginx.Key('listen', "[::]:443 ssl http2 default_server"),

                nginx.Key('server_name', "_"),

                nginx.Key('ssl_ciphers', "aNULL"),
                nginx.Key('ssl_certificate', "data:$empty"),
                nginx.Key('ssl_certificate_key', "data:$empty"),

                nginx.Key('return', '444')
            ),

            # XXX https? authentication?
            nginx.Server(
                nginx.Key('listen', "80"),
                nginx.Key('server_name', "127.0.0.1"),  # XXX ugh. metricbeat doesn't allow setting Host header
                nginx.Key('access_log', "off"),  # XXX? # TODO
                nginx.Location('/info', nginx.Key('return',
                                                  f"200 \"{timestamp}\\n\"")),
                nginx.Location('/stub_status', nginx.Key('stub_status', None))
            ),

            # XXX https? authentication?
            nginx.Server(
                nginx.Key('listen', "80"),
                nginx.Key('server_name', "banjax-next"),
                nginx.Key('access_log', "off"),  # XXX?
                # XXX do this differently?
                nginx.Location('/info',
                               nginx.Key('proxy_pass',
                                         "http://127.0.0.1:8081/info")
                               ),
                nginx.Location('/decision_lists',
                               nginx.Key('proxy_pass',
                                         "http://127.0.0.1:8081/decision_lists")
                               ),
                nginx.Location('/rate_limit_states',
                               nginx.Key('proxy_pass',
                                         "http://127.0.0.1:8081/rate_limit_states")
                               ),
            ),

            nginx.Server(
                # XXX localhost can be port 80, but non-local should be https-only
                nginx.Key('listen', "80"),
                nginx.Key('server_name', '"cache_purge"'),
                # XXX maybe log to a separate file
                nginx.Key('access_log', "off"),

                nginx.Location('~ /auth_requests/(.*)',
                               nginx.Key('allow', "127.0.0.1"),
                               nginx.Key('deny', "all"),
                               nginx.Key('proxy_cache_purge',
                                         "auth_requests_cache $1")
                               ),

                nginx.Location('~ /site_content/(.*)',
                               nginx.Key('allow', "127.0.0.1"),
                               nginx.Key('allow', "all"),
                               nginx.Key('proxy_cache_purge',
                                         "site_content_cache $1")
                               ),

                nginx.Location('/',
                               nginx.Key(
                                   'return', "404 \"you\'re looking for /auth_requests/<ip>* or \'/site_content/<scheme><site>*\'\\n\""),
                               )
            ),

            nginx.Key('include', "/etc/nginx/sites.d/*.conf")
        )
    )


def default_site_content_cache_include_conf(cache_time_minutes, site):
    return [
        nginx.Key('proxy_cache', "site_content_cache"),
        nginx.Key('proxy_cache_key', '"$host $scheme $uri $is_args $args"'),
        nginx.Key('proxy_cache_valid', f"any {str(cache_time_minutes)}")
    ]


# def password_protected_auth_request_keys():
#     return [
#         nginx.Key('auth_request', "/password_protected_auth"),
#         # XXX does this interfere with a 401 or 403 from the origin?
#         nginx.Key('error_page', "401 403 /password_protected_auth"),
#         nginx.Key('error_page', "500 @banjax_fail_closed")
#     ]

def access_denied_location(site):
    location = nginx.Location('@access_denied')
    location.add(nginx.Key('set', "$loc_out \"access_denied\""))
    location.add(nginx.Key('return', "403 \"access denied\""))
    return location


def fail_closed_location_block(site, global_config, edge_https, origin_https):
    location = nginx.Location('@fail_closed')
    location.add(nginx.Key('set', "$loc_out \"fail_closed\""))
    location.add(nginx.Key('return', "500 \"error talking to banjax-next, failing closed\""))
    return location


# XXX ugh this needs redoing
def main(all_sites, config, formatted_time):
    for dnet, _ in config['dnets_to_edges'].items():
        output_dir = f"./output/{formatted_time}/etc-nginx-{dnet}"
        if os.path.isdir(output_dir):
            print(f"removing {output_dir}")
            shutil.rmtree(f"./{output_dir}")
        os.makedirs(output_dir)

        with open(output_dir + "/nginx.conf", "w") as f:
            nginx.dump(top_level_conf(formatted_time), f)

        info_dir = output_dir + "/info"
        os.mkdir(info_dir)
        with open(info_dir + "/info", "w") as f:
            f.write(json.dumps({"config_version": formatted_time}))

        os.mkdir(output_dir + "/sites.d")

        # XXX another special case that needs to be handled properly eventually
        test_origin_site = all_sites['system'][f"test-origin.{test_domain}"]
        public_domain = test_origin_site['public_domain']
        with open(f"{output_dir}/sites.d/{public_domain}.conf", "w") as f:
            nginx.dump(per_site_include_conf(test_origin_site, config), f)

        for name, site in all_sites['client'].items():
            if dnet != site['dnet']:
                continue
            public_domain = site['public_domain']
            if not (
                os.path.isfile(f"./input/certs/{formatted_time}/{public_domain}.le.fullchain.crt") 
                or
                os.path.isfile(f"./output/{formatted_time}/etc-ssl-uploaded/{public_domain}.cert-and-chain") 
                or
                site.get('https_request_does') == "nothing"
                or True
                # or
                # site['ns_on_deflect'] == False
            ):
                print(f"SKIPPING site: {public_domain:30} {site.get('https_request_does'):20} {site['letsencrypt']:5} {site['ns_on_deflect']:5}")
                continue
            with open(f"{output_dir}/sites.d/{public_domain}.conf", "w") as f:
                nginx.dump(per_site_include_conf(site, config), f)

        # XXX handling system sites here. should clean this up someday.
        with open("templates/kibana_doh_nginx.conf.j2", "r") as tf:
            template = Template(tf.read())
            with open(output_dir + "/nginx.conf", "w") as f:
                nginx.dump(top_level_conf(formatted_time), f)

            for name, site in all_sites['system'].items():
                # XXX ugh... special case later
                if name == "prod.deflect.ca":
                    continue
                # XXX fix these special cases
                if name == f"test-origin.{test_domain}":
                    continue
                with open(f"{output_dir}/sites.d/{name}.conf", "w") as f:
                    f.write(template.render(
                        server_name=name,
                        cert_name=name,
                        ssl_ciphers=config['ssl_ciphers'],
                        proxy_pass=f"http://{site['origin_ip']}:{site['origin_http_port']}",
                    ))
            # XXX edgemanage does the equivalent of
            # curl -k --header "Host: prod.deflect.ca" https://one33.prod.deflect.ca/deflectlogo_RED.png
            # which results in a mismatch between the Host header and the SNI field.
            # usually, we use the --resolve thing, or equivalent, which does not result in a mismatch.
            # so i have to do a wildcard server_name here to account for this.
        with open(f"{output_dir}/sites.d/prod.deflect.ca.conf", "w") as f:
            f.write(template.render(
                server_name="prod.deflect.ca *.prod.deflect.ca",
                cert_name="prod.deflect.ca",
                ssl_ciphers=config['ssl_ciphers'],
                proxy_pass=f"http://85.10.195.146:80", # XXX
            ))

    for dnet, _ in config['dnets_to_edges'].items():
        output_dir = f"./output/{formatted_time}/etc-nginx-{dnet}"
        if os.path.isfile(f"{output_dir}.tar"):
            os.remove(f"{output_dir}.tar")

        with tarfile.open(f"{output_dir}.tar", "x") as tar:
            tar.add(output_dir, arcname=".")


if __name__ == "__main__":
    from orchestration.shared import get_all_sites

    config = parse_config('input/current/config.yml')

    all_sites, formatted_time = get_all_sites()

    main(all_sites, config, formatted_time)
