# Copyright (c) 2020, eQualit.ie inc.
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
    # todo: use arg parser for the path?
    # todo: also at some point we need to introduce a config for the project e.g. deflect-next config
    config = parse_config('input/current/config.yml')
    all_sites, formatted_time = get_all_sites()
    cert_converter_main(formatted_time)
    install_delta_config(config)
    make_nginx_public_main(config)
