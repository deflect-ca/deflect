# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import os
import shutil
import logging
import tarfile
import yaml

from pyaml_env import parse_config
from util.config_parser import parse_container_config_with_defaults
from util.helpers import (
    get_logger,
    get_config_yml_path,
    path_to_input,
    path_to_output,
)

logger = get_logger(__name__)


def generate_legacy_filebeat_config(config, all_sites, timestamp):
    # Setup dirs
    output_dir = f"{path_to_output()}/{timestamp}/etc-legacy-filebeat"
    output_dir_tar = f"{output_dir}.tar"

    if len(output_dir) == 0:
        raise Exception("output_dir cannot be empty")

    if os.path.isdir(output_dir):
        logger.debug(f"Removing output dir: {output_dir}")
        shutil.rmtree(f"{output_dir}")

    os.mkdir(output_dir)

    # copy certs and key to output dir
    filebeat_configs = [
        'edgecert.key',
        'edgecert.pem',
        'rootca.pem',
    ]
    for config in filebeat_configs:
        logger.debug(f"Copy {config} to output dir")
        shutil.copyfile(
            f"{path_to_input()}/legacy-filebeat/{config}",
            f"{output_dir}/{config}")

    # Output files, compress and clean
    if os.path.isfile(output_dir_tar):
        logger.debug(f"Removing {output_dir_tar}")
        os.remove(output_dir_tar)

    logger.info(f"Writing {output_dir_tar}")
    with tarfile.open(output_dir_tar, "x") as tar:
        tar.add(output_dir, arcname=".")


if __name__ == "__main__":
    from orchestration.shared import get_all_sites

    config = parse_config(get_config_yml_path())
    all_sites, formatted_time = get_all_sites()
    generate_legacy_filebeat_config(config, all_sites, formatted_time)
