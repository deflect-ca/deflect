# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.


import datetime
import logging
import traceback

import docker

from orchestration import shared
from orchestration.helpers import NAME_TO_ROLE, get_logger, get_sites_yml_path
from pyaml_env import parse_config


def build_all_images(client, registry=None):
    """
    Builds all deflect-next images, as they are defined in NAME_TO_ROLE:
        "nginx": RoleEnum.edge,
        "bind-server": RoleEnum.controller,
        "certbot": RoleEnum.controller,
        "banjax": RoleEnum.edge,
        "origin-server": RoleEnum.none,
        "doh-proxy": RoleEnum.testing,
        "filebeat": RoleEnum.none,
        "elasticsearch": RoleEnum.none,
        "kibana": RoleEnum.none,
        "pebble": RoleEnum.testing
    :param docker.Client client: the docker client to be used
    :param str registry: the docker-hub registry
    :return: list of built images
    """
    timestamp = str(datetime.datetime.utcnow().timestamp())
    logger.debug(client.api.info())
    logger.debug(f'TIMESTAMP: {timestamp}')
    images = []
    for name, role in NAME_TO_ROLE.items():
        try:
            # for the image tagging, get latest
            image, logs = shared.build_new_image(
                name, client, timestamp, registry
            )
            images.append(image)
            logger.debug(client.api.history(image.id))
        except Exception:
            traceback.print_exc()

    return images


def push_all_to_registry(images, client, registry, pull=False):
    """
    Push all images to registry
    :param client:
    :param registry:
    :param pull:
    :return:
    """
    if registry:
        for image in images:
            logger.debug(image.tags)
            for line in client.images.push(
                    image.tags[-1], stream=True, decode=True
            ):
                logger.debug(line)
        if pull:
            # we need a good strategy for managing images in the registry
            # one is timestamp as Joe does
            # but I haven't found a way to get the latest image without a tag
            # you can't just do pull dn-nginx:latest
            # I suggest we use stable versioning and bump the minors every time
            # we change something. We can use autobuild from dockerhub to
            # github
            # todo: check how flexible autobuild is
            s = client.images.list(registry)
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
        # im = client.api.pull(registry, tag=sorted_by_date[0].tags[0])
    else:
        logger.info('No registry')


if __name__ == '__main__':
    config = parse_config(get_sites_yml_path())
    logger = get_logger(__name__)
    dn_config = parse_config('input/deflect-next_config.yaml')
    docker_conf = dn_config['docker']
    images = []
    client = docker.from_env()
    registry = docker_conf['registry']
    if registry:
        client.login(
            username=docker_conf['username'],
            password=docker_conf['password']
        )
    images = build_all_images(client, registry)
    push_all_to_registry(images, client, registry)
