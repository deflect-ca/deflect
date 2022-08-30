# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import yaml
import re
import os
from datetime import datetime
from util.helpers import (
        get_sites_yml_path,
        get_system_sites_yml_path,
        get_logger,
)

logger = get_logger(__name__)


def validate_old_regex(rprop):
    skip = False
    for prop in rprop.items():
        if prop is None:
            skip = True
            break
    return skip


def validate_regex(regex, public_domain):
    try:
        re.compile(regex)
    except re.error as err:
        logger.warning(f"{public_domain}: skip invalid regex")
        logger.warning(f"\tre.compile error: {err}, strlen: {len(regex)}")
        logger.warning(f"\t{regex}")
        return False
    return True


def old_to_new_rate_limited_regexes(old_regexes, public_domain):
    """
    Old format: [
        {
            "regex": {
                "url": "\\/xmlrpc\\.php",
                "ua": ".*",
                "method": "POST"
            },
            "interval": 120,
            "hits_per_interval": 10
        }
    ]

    Banjax log tailing:
        1651049088.455 1.1.1.1 POST equalit.ie POST /xmlrpc.php HTTP/1.1 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)
        1651049088.455 2.2.2.2 GET equalit.ie GET / HTTP/1.1 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)
        1651049575.705 3.3.3.3 GET equalit.ie GET / HTTP/1.1 Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML,like Gecko) Chrome/51.0.2704.103 Safari/537.36
    """
    new_regexes = []
    for old_regex in old_regexes:
        rprop = {}
        rprop['method'] = old_regex['regex'].get('method')
        rprop['url'] = old_regex['regex'].get('url')
        rprop['ua'] = old_regex['regex'].get('ua', '.*')
        rprop['interval'] = old_regex.get('interval')
        rprop['hits_per_interval'] = old_regex['hits_per_interval']

        if validate_old_regex(rprop):
            logger.warning(f"skipping broken regex {old_regex} for {public_domain}")
            continue

        escaped_public_domain = public_domain.replace('.', '\.')
        new_regex = {}
        h_url = rprop['url'].replace('\\/', '/')  # for rule name

        # Per site example.com POST /xmlrpc\.php: 10 req/120 sec
        # XXX in banjax its not "name" but "rule"
        new_regex["rule"] = old_regex.get("rule",
            f"Per-site {public_domain} m={rprop['method']} p={h_url} u={rprop['ua']} "
            f"{rprop['hits_per_interval']}req/{rprop['interval']}sec")
        new_regex["interval"] = rprop["interval"]
        new_regex["hits_per_interval"] = rprop["hits_per_interval"]
        new_regex["decision"] = old_regex.get("decision", "nginx_block")

        # GET equalit.ie GET .* HTTP/[1-2.]+ .*Mozilla.*
        temp_regex = f"{rprop['method']} {escaped_public_domain} "
        temp_regex += f"{rprop['method']} {rprop['url']} "
        # Handle HTTP/1.1 and HTTP/2.0 before user agent
        temp_regex += f"HTTP\/[0-2.]+ {rprop['ua']}"

        if validate_regex(temp_regex, public_domain):
            new_regex["regex"] = temp_regex
            new_regexes.append(new_regex)

    return new_regexes


def old_to_new_cache_exceptions(old_cache_exceptions):
    new_cache_exceptions = []
    for old_exception in old_cache_exceptions:
        parts = old_exception.split(" ")

    return []  # XXX actually do this


def old_to_new_site_dict(old_dict):
    new_dict = {}
    # XXX not implemented in banjax
    new_dict["challenge_everyone_captcha"] = old_dict.get(
        "banjax_captcha", False)
    new_dict["sitewide_sha_inv"] = old_dict.get(
        "banjax_sha_inv", False)
    new_dict["sitewide_sha_inv_no_block"] = old_dict.get(
        "user_banjax_sha_inv", False)
    banjax_path = old_dict.get("banjax_path", None)
    if banjax_path in [None, "", [], [""]]:
        new_dict["password_protected_paths"] = []
    elif isinstance(banjax_path, str):
        new_dict["password_protected_paths"] = [banjax_path.strip(" /")]
    elif isinstance(banjax_path, list):
        new_dict["password_protected_paths"] = list(
            set([p.strip(" /") for p in banjax_path]))
    new_dict["password_protected_paths_password"] = old_dict.get(
        "banjax_password", None)
    new_dict["rate_limited_regexes"] = old_to_new_rate_limited_regexes(
        old_dict.get("banjax_regex_banner", []), old_dict["url"])
    new_dict["additional_domain_prefix"] = old_dict.get("additional_domain_prefix", [])
    for subdomain in ['www'] + new_dict['additional_domain_prefix']:
        full_domain = subdomain + '.' + old_dict["url"]
        new_dict["rate_limited_regexes"] += old_to_new_rate_limited_regexes(
            old_dict.get("banjax_regex_banner", []), full_domain)
    new_dict["password_protected_path_exceptions"] = old_dict.get('banjax_path_exceptions', [])
    new_dict["default_cache_time_minutes"] = old_dict["cache_time"]
    new_dict["cache_exceptions"] = old_to_new_cache_exceptions(
        old_dict.get("cache_exceptions", []))
    new_dict["disable_logging"] = old_dict.get("disable_logging", False)
    new_dict["dnet"] = old_dict.get("network", "dnext1")
    new_dict["origin_ip"] = old_dict["origin"]
    new_dict["public_domain"] = old_dict["url"]
    new_dict["dns_records"] = old_dict.get("dns_records", {})
    new_dict["allow_http_delete_push"] = old_dict.get(
        "allow_http_delete_push", False)  # XXX think about changing this
    new_dict["origin_http_port"] = old_dict.get("origin_http_port", 80)
    new_dict["origin_https_port"] = old_dict.get("origin_https_port", 443)
    new_dict["http_request_does"] = "http_proxy_pass" if old_dict["http_type"] in [
        "http", "https"] else "redirect"
    new_dict["https_request_does"] = "https_proxy_pass" if old_dict["http_type"] in [
        "https", "https_redirect", "https_only"] else "nothing"
    new_dict["letsencrypt"] = old_dict.get("letsencrypt", False)
    new_dict["uploaded_cert_bundle_name"] = old_dict.get("tls_bundle", None)
    server_names = []
    root_name = new_dict["public_domain"]
    # not seen
    if not old_dict.get("www_only", False):
        server_names.append(root_name)
    # only 3
    if not old_dict.get("no_www", False):
        server_names.append("www." + root_name)
    for prefix in old_dict.get("additional_domain_prefix", []):
        server_names.append(prefix + "." + root_name)
    new_dict["server_names"] = server_names
    new_dict["ns_on_deflect"] = old_dict["ns_on_deflect"]
    # append origin IP to banjax per site whitelist
    new_dict["ip_allowlist"] = old_dict.get("add_banjax_whitelist", []) + [old_dict["origin"]]
    new_dict["ip_blocklist"] = old_dict.get("add_banjax_blocklist", [])
    new_dict["cache_cookie_allowlist"] = old_dict.get("cache_cookie_allowlist", [])
    new_dict["cache_lock"] = old_dict.get("cache_lock", False)
    new_dict["cache_use_stale"] = old_dict.get("cache_use_stale", False)
    new_dict["cache_override_vary_only_encoding"] = old_dict.get("cache_override_vary_only_encoding", False)
    new_dict["static_to_banjax"] = old_dict.get("static_to_banjax", False)
    new_dict["cache_disable"] = old_dict.get("cache_disable", False)
    new_dict["enable_sni"] = old_dict.get("enable_sni", False)

    return new_dict


def complete_system_sites(config, system_sites):
    fixed_system_sites = {}
    for name, site in system_sites.items():
        fixed_name = f"{name}.{config['system_root_zone']}"
        fixed_site = site
        fixed_server_names = []
        for server_name in fixed_site['server_names']:
            fixed_server_names.append(f"{server_name}.{config['system_root_zone']}")
        fixed_site['server_names'] = fixed_server_names
        fixed_site['public_domain'] = f"{fixed_site['public_domain']}.{config['system_root_zone']}"
        fixed_site['origin_ip'] = config['controller']['ip']  # system sites all live on the controller
        fixed_site['additional_domain_prefix'] = []
        fixed_system_sites[fixed_name] = fixed_site
    return fixed_system_sites

def get_all_sites(config):
    logger.debug('Getting all sites')
    old_client_sites = {}
    old_client_sites_timestamp = None
    # with open("input/current/old-sites.yml", "r") as f:
    while True:
        try:
            with open(get_sites_yml_path(), "r") as f:
                old_client_sites_dict = yaml.load(f.read(), Loader=yaml.SafeLoader)
                old_client_sites_timestamp = old_client_sites_dict["timestamp"]
                old_client_sites = old_client_sites_dict["remap"]
                break
        except FileNotFoundError:
            logger.info(f"didn't find anything at {get_sites_yml_path()}, sleeping...")
            time.sleep(5)

    time_from_inside_file = datetime.fromtimestamp(float(old_client_sites_timestamp)/1000.0)
    formatted_time = time_from_inside_file.strftime("%Y-%m-%d_%H:%M:%S")

    logger.debug('Getting new client sites: old_to_new_site_dict.main')
    new_client_sites = convert_old_sites_to_new_sites(
        old_client_sites, old_client_sites_timestamp
    )

    logger.debug('Getting new system_sites')
    system_sites = {}
    with open(get_system_sites_yml_path(), "r") as f:
        system_sites = yaml.load(f.read(), Loader=yaml.SafeLoader)
        system_sites = complete_system_sites(config, system_sites)

    all_sites = {'client': new_client_sites, 'system': system_sites}
    # logger.debug(f'All sites:{json.dumps(all_sites, indent=2)}')
    return all_sites, formatted_time


def convert_old_sites_to_new_sites(old_sites, old_sites_timestamp):
    logger.debug(f">>> Converting old sites to new sites, count {len(old_sites)}")

    new_sites = {}
    for name, old_site in old_sites.items():
        new_site = old_to_new_site_dict(old_site)
        new_sites[name] = new_site

    time = datetime.fromtimestamp(float(old_sites_timestamp)/1000.0)
    formatted_time = time.strftime("%Y-%m-%d_%H:%M:%S")

    if not os.path.isdir(f"./output/{formatted_time}"):
        os.mkdir(f"./output/{formatted_time}")

    if os.path.isfile(f"./output/{formatted_time}/new-sites.yml"):
        os.remove(f"./output/{formatted_time}/new-sites.yml")

    with open(f"output/{formatted_time}/new-sites.yml", "w") as f:
        f.write(yaml.dump(new_sites, default_flow_style=False))

    return new_sites


if __name__ == "__main__":
    old_client_sites = {}
    old_client_sites_timestamp = None
    with open(get_sites_yml_path(), "r") as f:
        old_client_sites_dict = yaml.load(f.read(), Loader=yaml.SafeLoader)
        old_client_sites_timestamp = old_client_sites_dict["timestamp"]
        old_client_sites = old_client_sites_dict["remap"]

    time = datetime.fromtimestamp(float(old_client_sites_timestamp)/1000.0)
    formatted_time = time.strftime("%Y-%m-%d_%H:%M:%S")

    new_client_sites = convert_old_sites_to_new_sites(old_client_sites, old_client_sites_timestamp)
