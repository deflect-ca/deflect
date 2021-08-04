# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.


import datetime
import logging
import traceback

import docker
from docker.models.images import RegistryData

from orchestration import shared
from orchestration.helpers import NAME_TO_ROLE, get_logger
from pyaml_env import parse_config


if __name__ == '__main__':
    config = parse_config('input/current/config.yml')
    dn_config = parse_config('input/deflect-next_config.yaml')
    docker_conf = dn_config['docker']
    images = []

    logger = get_logger(__name__, logging_level=logging.DEBUG)
    timestamp = str(datetime.datetime.utcnow().timestamp())
    client = docker.from_env()
    registry = docker_conf['registry']
    logger.debug(client.api.info())
    logger.debug(f'TIMESTAMP: {timestamp}')

    for name, role in NAME_TO_ROLE.items():
        try:
            # for the image tagging, get latest
            image, logs = shared.build_new_image(
                name, client, timestamp, registry
            )
            images.append(image)
            logger.debug(client.api.history(image.id))
        except:
            traceback.print_exc()
    client.login(
        username=docker_conf['username'],
        password=docker_conf['password']
    )

    if registry:
        for image in images:
            logger.debug(image.tags)
            for line in client.images.push(image.tags[-1], stream=True, decode=True):
                    logger.debug(line)

        # we need a good strategy for managing images in the registry
        # one is timestamp as Joe does
        # but I haven't found a way to get the latest image without a tag
        # you can't just do pull dn-nginx:latest
        # I suggest we use stable versioning and bump the minors every time we
        # change something. We can use autobuild from dockerhub to github
        # todo: check how flexible autobuild is
        s = client.images.list(registry)
        rd = RegistryData(registry)
        # print('HISTORY:', client.api.history(registry))
        sorted_by_date = sorted(s, key=lambda x: x.attrs.get('Created'),
                                reverse=True)
        # d = client.images.get_registry_data(
        #     'mkaran/test:deflect-next-nginx-1625667728.930734')
        logger.debug(client.api.pull(
            registry,
            tag=sorted_by_date[0].tags[-1].replace(f'{registry}:', ''),
            decode=True,
            stream=False
        ))
        # im = client.api.pull('mkaran/dn-nginx', tag=sorted_by_date[0].tags[0])
