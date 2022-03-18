# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import yaml
import shutil
import os
from datetime import datetime
from util.helpers import (
        get_sites_yml_path,
        get_system_sites_yml_path,
        get_logger,
)
import logging
import json

logger = get_logger(__name__, logging_level=logging.DEBUG)


def old_to_new_rate_limited_regexes(old_regexes, public_domain):
    new_regexes = []
    for old_regex in old_regexes:
        new_regex = {}
        # print(public_domain)
        # print(old_regex)
        escaped_public_domain = public_domain.replace('.', '\.')
        old_regex_method = old_regex['regex']['method']
        old_regex_path = old_regex['regex']['url']

        new_regex["name"] = old_regex.get("rule", "UNNAMED RULE")
        new_regex["interval"] = old_regex["interval"]
        new_regex["hits_per_interval"] = old_regex["hits_per_interval"]
        new_regex["decision"] = "nginx_block"
        # GET http://wp-admin example.com Mozilla
        temp_regex = f"^{old_regex_method} "
        temp_regex += f"{escaped_public_domain} "
        temp_regex += f"{old_regex_path} "
        temp_regex += old_regex.get("ua", "")
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
    # XXX not implemented in banjax-next
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
    new_dict["default_cache_time_minutes"] = old_dict["cache_time"]
    new_dict["cache_exceptions"] = old_to_new_cache_exceptions(
        old_dict.get("cache_exceptions", []))
    new_dict["disable_logging"] = old_dict.get("disable_logging", False)
    new_dict["dnet"] = old_dict["network"]
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
    if not old_dict.get("www_only", False):
        server_names.append(root_name)
    if not old_dict.get("no_www", False):
        server_names.append("www." + root_name)
    for prefix in old_dict.get("additional_domain_prefix", []):
        server_names.append(prefix + "." + root_name)
    new_dict["server_names"] = server_names
    new_dict["ns_on_deflect"] = old_dict["ns_on_deflect"]
    new_dict["ip_allowlist"] = old_dict.get("add_banjax_whitelist", [])

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
        fixed_system_sites[fixed_name] = fixed_site
    return fixed_system_sites

def get_all_sites(config):
    logger.info('Getting all sites')
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
    logger.debug(f"Site count in site.yml file: {len(old_sites)}")

    new_sites = {}
    for name, old_site in old_sites.items():
        # print(f"doing {name}")
        # XXX think about this. ATS ignores missing certs, but Nginx does not.
        # if not old_site["ns_on_deflect"]:
        #     continue
        if name in ["acmx.ch", "donuz.okajak.com", "abortion-pills.org", "zemzen.defakto.support", "irancybercrime.org"]: #, "gubernia.com", "old.gubernia.com", "radiozamaneh.com", "volksentscheid-berlin-autofrei.de", "zemzen.defakto.support", "dev.pandemicbigbrother.online", "pandemicbigbrother.online"]:
            continue
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
