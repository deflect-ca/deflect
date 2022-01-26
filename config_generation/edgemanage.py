# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

from pyaml_env import parse_config
from util.helpers import get_logger, get_config_yml_path, path_to_input, path_to_output

# todo: use configuration for the logger
logger = get_logger(__name__, logging_level=logging.DEBUG)


def generate_edgemanage_config(config, all_sites, timestamp):
    pass


if __name__ == "__main__":
    from orchestration.shared import get_all_sites

    config = parse_config(get_config_yml_path())
    all_sites, formatted_time = get_all_sites()
    generate_edgemanage_config(config, all_sites, formatted_time)
