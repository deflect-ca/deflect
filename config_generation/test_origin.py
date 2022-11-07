# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import os
import shutil
import tarfile
import json
import uuid

from util.helpers import (
    get_logger,
    path_to_output,
)

logger = get_logger(__name__)


def generate_test_origin_config(config, all_sites, timestamp):
    # Setup dirs
    output_dir = f"{path_to_output()}/{timestamp}/test-origin"
    output_dir_tar = f"{output_dir}.tar"

    if len(output_dir) == 0:
        raise Exception("output_dir cannot be empty")

    if os.path.isdir(output_dir):
        logger.debug(f"Removing output dir: {output_dir}")
        shutil.rmtree(f"{output_dir}")

    os.mkdir(output_dir)

    # generate edge list in JSON to be served by test-origin
    t_token = config.get('test_origin_file_token')
    file_token = str(uuid.uuid4()) if t_token is None else t_token
    edge_list = []
    dnets = {}
    for edge in config['edges']:
        edge_list.append(edge['ip'])
        if edge['dnet'] in dnets:
            dnets[edge['dnet']].append(edge['ip'])
        else:
            dnets[edge['dnet']] = [edge['ip']]

    with open(f"{output_dir}/edges_{file_token}.json", 'w') as f:
        logger.info(f"Writing edge list to {output_dir}/edges-{file_token}.json")
        json.dump(edge_list, f)

    with open(f"{output_dir}/dnets_{file_token}.json", 'w') as f:
        logger.info(f"Writing dnet list to {output_dir}/dnets-{file_token}.json")
        json.dump(dnets, f)

    # Output files, compress and clean
    if os.path.isfile(output_dir_tar):
        logger.debug(f"Removing {output_dir_tar}")
        os.remove(output_dir_tar)

    logger.info(f"Writing {output_dir_tar}")
    with tarfile.open(output_dir_tar, "x") as tar:
        tar.add(output_dir, arcname=".")
