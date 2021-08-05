# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import unittest

import docker
from testcontainers.nginx import DockerContainer


class TestContainers(unittest.TestCase):
    def setUp(self):
        self.docker_client = docker.DockerClient()
        self.current_container = None

    def tearDown(self) -> None:
        if self.current_container:
            del self.current_container

    def test_nginx_container(self):
        from orchestration.shared import build_new_image
        image_name = 'nginx'
        image_build_timestamp = 'image_build_timestamp'
        image, logs = build_new_image(
            image_name,
            client=self.docker_client,
            timestamp=image_build_timestamp
        )

        with DockerContainer(image.tags[0]) as container:
            self.current_container = container
            print(self.current_container.get_container_host_ip())
            result = self.current_container.exec('cat /etc/nginx/nginx.conf')
            self.assertEqual(result.exit_code, 0)
            from orchestration.helpers import get_orchestration_path, NAME_TO_ROLE
            path = f"{get_orchestration_path()}/../containers/" \
                   f"{NAME_TO_ROLE[image_name].value}/{image_name}/nginx.conf"
            with open(path, 'r') as f:
                self.assertEqual(
                    result.output.decode('utf-8'),
                    ''.join(f.readlines())
                )

    def test_banjax_next_container(self):
        from orchestration.shared import build_new_image
        image_name = 'banjax-next'
        image_build_timestamp = 'image_build_timestamp'
        image, logs = build_new_image(
            image_name,
            client=self.docker_client,
            timestamp=image_build_timestamp
        )
        print(image.tags)
        with DockerContainer(image.tags[0]) as container:
            self.current_container = container
            print(self.current_container.get_container_host_ip())

