# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

from pyaml_env import parse_config

from orchestration.cert_converter import main as cert_converter_main
from orchestration.helpers import get_config_yml_path
from orchestration.make_nginx_public import main as make_nginx_public_main
from orchestration.shared import get_all_sites

import logging
from orchestration.helpers import get_logger, get_config_yml_path
logger = get_logger(__name__, logging_level=logging.DEBUG)

from orchestration import generate_bind_config, \
    generate_nginx_config, generate_banjax_next_config, \
    decrypt_and_verify_cert_bundles, cert_converter

from orchestration import install_delta_config

if __name__ == '__main__':
    # todo: many things to be fleshed out to deflect-next config
    config = parse_config(get_config_yml_path())
    dn_config = parse_config('input/deflect-next_config.yaml')
    temp_config = parse_config('input/temp/config.yml')

    ### begin temporary kludge ###
    import os.path
    import yaml

    system_sites = []
    with open("input/system-sites.example.yml", "r") as f:
        system_sites = yaml.load(f)

    # get example.com from controller.example.com
    test_root = ".".join(config['controller']['hostname'].split(".")[1:])

    if not os.path.isfile("input/system-sites.yml"):
        fixed_system_sites = {}
        for name, site in system_sites.items():
            fixed_name = name.replace("test.me.uk", test_root)
            fixed_site = site
            fixed_server_names = []
            for server_name in fixed_site['server_names']:
                fixed_server_names.append(server_name.replace("test.me.uk", test_root))
            fixed_site['server_names'] = fixed_server_names
            fixed_site['public_domain'] = fixed_site['public_domain'].replace("test.me.uk", test_root)
            fixed_site['origin_ip'] = config['controller']['ip']  # system sites all live on the controller
            fixed_system_sites[fixed_name] = fixed_site
        with open("input/system-sites.yml", "w") as f:
            yaml.dump(fixed_system_sites, f)

    if not os.path.isfile("input/named.conf.local"):
        with open("input/named.conf.local", "w") as dest:
            with open("input/named.example.conf.local", "r") as src:
                dest.write(src.read().replace("test.me.uk", test_root))

    if not os.path.isfile(f"input/{test_root}.zone"):
        with open(f"input/{test_root}.zone", "w") as dest:
            with open("input/test.me.uk.zone", "r") as src:
                dest.write(src.read().replace("test.me.uk", test_root))
    ### end temporary kludge ###

    all_sites, formatted_time = get_all_sites()

    logger.info('>>> Running decrypt_and_verify_cert_bundlesg...')
    decrypt_and_verify_cert_bundles.main(all_sites, formatted_time)

    if dn_config['certs']['convert']:
        logger.info('>>> Running cert_converter...')
        cert_converter_main(formatted_time)

    logger.info('>>> Generating bind config...')
    generate_bind_config.main(config, all_sites, formatted_time)

    logger.info('>>> Generating nginx config...')
    generate_nginx_config.main(all_sites, config, formatted_time)

    logger.info('>>> Generating banjax-next config...')
    generate_banjax_next_config.main(config, all_sites, formatted_time)

    # logger.info('>>> Running make_nginx_public...')
    # make_nginx_public_main(config)

    logger.info('>>> Running install_delta_config...')
    install_delta_config.main(
        config,
        all_sites,
        formatted_time,
        formatted_time,
        temp_config=temp_config
    )
