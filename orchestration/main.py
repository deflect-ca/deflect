# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

from pyaml_env import parse_config

from orchestration.cert_converter import main as cert_converter_main
from orchestration.install_delta_config import install_delta_config
from orchestration.make_nginx_public import main as make_nginx_public_main
from orchestration.shared import get_all_sites

if __name__ == '__main__':
    # todo: many things to be fleshed out to deflect-next config
    config = parse_config('input/current/config.yml')
    dn_config = parse_config('input/deflect-next_config.yaml')

    all_sites, formatted_time = get_all_sites()
    if dn_config['certs']['convert']:
        cert_converter_main(formatted_time)
    install_delta_config(config)
    make_nginx_public_main(config)
