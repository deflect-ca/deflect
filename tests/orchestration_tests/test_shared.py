# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
import os
import unittest
from unittest import mock

import docker
from orchestration.helpers import orchestration_path, FILENAMES_TO_TAIL, \
    DEFAULT_RESTART_POLICY, path_to_input, get_sites_yml_path


class TestShared(unittest.TestCase):
    def setUp(self):
        # self.old_sites_path = get_path_to_input() + '/current/old-sites.yml'
        # self.mock_old_to_new_site_dict_patcher = mock.patch(
        #     'orchestration.old_to_new_site_dict.main')
        # self.o2n_dict_mock = self.mock_old_to_new_site_dict_patcher.start()
        pass

    def old_sites_yaml(self):
        if os.path.isfile(self.old_sites_path):
            os.rename(self.old_sites_path, self.old_sites_path)
        with open(get_sites_yml_path(), 'w+') as f:
            pass

    def test_find_existing_or_start_new_container(self):
        from orchestration.shared import find_existing_or_start_new_container
        expected_value = 1
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [1]
        image_name = 'image_name'
        image_build_timestamp = 'image_build_timestamp'
        config = {}
        result = find_existing_or_start_new_container(
            mock_client, image_name, image_build_timestamp, config
        )
        self.assertEquals(expected_value, result)

    def test_find_running_container(self):
        from orchestration.shared import \
            find_running_container
        expected_value = 1
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [1]
        image_name = 'image_name'
        result = find_running_container(
            mock_client, image_name
        )
        self.assertEquals(expected_value, result)

    def test_build_new_image_key_error(self):
        from orchestration.shared import \
            build_new_image
        mock_client = mock.MagicMock()
        mock_client.images.build.return_value = 1, 1
        image_name = 'testing'
        image_build_timestamp = 'image_build_timestamp'
        with self.assertRaises(KeyError):
            _ = build_new_image(
                image_name, mock_client, image_build_timestamp
            )

    def test_build_new_image(self):
        from orchestration.shared import \
            build_new_image
        expected_value = 1, 1
        image_name = 'nginx'
        image_build_timestamp = 'image_build_timestamp'
        expected_path = f"{orchestration_path()}/../containers/edge/nginx"
        expected_tag = f"deflect-next-{image_name}-{image_build_timestamp}"
        mock_client = mock.MagicMock()
        mock_client.images.build.return_value = 1, 1
        result = build_new_image(
            image_name, mock_client, image_build_timestamp
        )
        mock_client.images.build.assert_called_once_with(
            path=expected_path, tag=expected_tag
        )
        self.assertEqual(expected_value, result)

    def test_start_new_nginx_container(self):
        from orchestration.shared import \
            start_new_nginx_container
        expected_value = 1
        image_name = 'nginx'
        image_build_timestamp = 'image_build_timestamp'
        mock_client = mock.MagicMock()
        mock_client.containers.run.return_value = 1
        result = start_new_nginx_container(
            mock_client, image_name, image_build_timestamp
        )
        # todo: check individual args and kwargs for each run call
        times_called = len(FILENAMES_TO_TAIL) + 1
        mock_client.containers.run.assert_called()
        self.assertEqual(mock_client.containers.run.call_count, times_called)
        # means we went through all files to tail and we also created one extra
        # container
        self.assertEqual(mock_client.containers.run.return_value, expected_value)
        self.assertEqual(expected_value, result)

    def test_start_new_bind_container(self):
        from orchestration.shared import \
            start_new_bind_container
        expected_value = 1
        image_id = 'test'
        image_build_timestamp = 'image_build_timestamp'
        mock_client = mock.MagicMock()
        mock_client.containers.run.return_value = 1
        result = start_new_bind_container(
            mock_client, image_id, image_build_timestamp
        )

        mock_client.containers.run.assert_called_once_with(
            image_id,
            detach=True,
            ports={
                '53/udp': ('0.0.0.0', '53'),
                '53/tcp': ('0.0.0.0', '53'),
                '8085/tcp': ('0.0.0.0', '8085'),
            },
            labels={
                'name': "bind-server",
                'version': image_build_timestamp
            },
            name="bind-server",
            restart_policy=DEFAULT_RESTART_POLICY
        )
        self.assertEqual(expected_value, result)

    def test_start_new_certbot_container(self):
        from orchestration.shared import \
            start_new_certbot_container
        expected_value = 1
        image_id = 'test'
        image_build_timestamp = 'image_build_timestamp'
        mock_client = mock.MagicMock()
        mock_client.containers.run.return_value = 1
        result = start_new_certbot_container(
            mock_client, image_id, image_build_timestamp
        )

        mock_client.containers.run.assert_called_once_with(
            image_id,
            detach=True,
            labels={
                'name': "certbot",
                'version': image_build_timestamp
            },
            name="certbot",
            restart_policy=DEFAULT_RESTART_POLICY,
            network_mode="container:bind-server"
        )
        self.assertEqual(expected_value, result)

    def test_start_new_banjax_next_container(self):
        from orchestration.shared import \
            start_new_banjax_next_container
        expected_value = 1
        image_id = 'test'
        container_name = 'container_name'
        image_build_timestamp = 'image_build_timestamp'
        mock_client = mock.MagicMock()
        mock_client.containers.run.return_value = 1
        mock_nginx_container = mock.MagicMock()
        mock_nginx_container.name = container_name
        mock_client.containers.list.return_value = [mock_nginx_container]
        result = start_new_banjax_next_container(
            mock_client, image_id, image_build_timestamp
        )

        mock_client.containers.run.assert_called_with(
            image_id,
            # command=f"tail --retry --follow=name /var/log/banjax/gin.log",
            detach=True,
            labels={
                'name': "banjax",
                'version': image_build_timestamp
            },
            volumes={  # XXX check out volumes_from?
                '/root/banjax/':  # XXX
                    {
                        'bind': '/var/log/banjaxt/',
                        'mode': 'ro'
                    }
            },
            name="banjax",
            restart_policy=DEFAULT_RESTART_POLICY,
            cap_add=["NET_ADMIN"],
            # XXX should we specify container id instead?
            network_mode=f"container:{mock_nginx_container.name}"
        )
        self.assertEqual(expected_value, result)

    def test_start_new_origin_container(self):
        from orchestration.shared import \
            start_new_origin_container
        expected_value = 1
        image_id = 'test'
        image_build_timestamp = 'image_build_timestamp'
        mock_client = mock.MagicMock()
        mock_client.containers.run.return_value = 1
        result = start_new_origin_container(
            mock_client, image_id, image_build_timestamp
        )

        mock_client.containers.run.assert_called_once_with(
            image_id,
            detach=True,
            ports={
                '8080/tcp': ('0.0.0.0', '8080'),
            },
            labels={
                'name': "origin-server",
                'version': image_build_timestamp
            },
            name="origin-server",
            restart_policy=DEFAULT_RESTART_POLICY
        )
        self.assertEqual(expected_value, result)

    def test_start_new_pebble_container(self):
        from orchestration.shared import \
            start_new_pebble_container
        expected_value = 1
        image_id = 'test'
        image_build_timestamp = 'image_build_timestamp'
        mock_client = mock.MagicMock()
        mock_client.containers.run.return_value = 1
        result = start_new_pebble_container(
            mock_client, image_id, image_build_timestamp
        )

        mock_client.containers.run.assert_called_once_with(
            image_id,
            command="pebble -config /test/config/pebble-config.json -dnsserver 127.0.0.1:53",
            detach=True,
            labels={
                'name': "pebble",
                'version': image_build_timestamp
            },
            environment={
                'PEBBLE_VA_NOSLEEP': "1",
            },
            name="pebble",
            restart_policy=DEFAULT_RESTART_POLICY,
            network_mode="container:bind-server"
        )
        self.assertEqual(expected_value, result)

    def test_start_new_doh_proxy_container(self):
        from orchestration.shared import \
            start_new_doh_proxy_container
        expected_value = 1
        image_id = 'test'
        image_build_timestamp = 'image_build_timestamp'
        mock_client = mock.MagicMock()
        mock_client.containers.run.return_value = 1
        result = start_new_doh_proxy_container(
            mock_client, image_id, image_build_timestamp
        )

        mock_client.containers.run.assert_called_once_with(
            image_id,
            detach=True,
            labels={
                'name': "doh-proxy",
                'version': image_build_timestamp
            },
            name="doh-proxy",
            restart_policy=DEFAULT_RESTART_POLICY,
            network_mode="container:bind-server"
        )
        self.assertEqual(expected_value, result)

    def test_start_new_elasticsearch_container(self):
        from orchestration.shared import \
            start_new_elasticsearch_container
        expected_value = 1
        image_id = 'test'
        image_build_timestamp = 'image_build_timestamp'
        mock_client = mock.MagicMock()
        mock_client.containers.run.return_value = 1
        result = start_new_elasticsearch_container(
            mock_client, image_id, image_build_timestamp
        )

        mock_client.containers.run.assert_called_once_with(
            image_id,
            detach=True,
            ports={
                '9200/tcp': ('0.0.0.0', '9200'),
            },
            labels={
                'name': "elasticsearch",
                'version': image_build_timestamp
            },
            environment={
                "discovery.type": "single-node",
                "bootstrap.memory_lock": "true",
                "ES_JAVA_OPTS": "-Xms512m -Xmx512m",
                "xpack.security.enabled": "true",
                "xpack.security.transport.ssl.enabled": "true",
                "xpack.security.transport.ssl.key": "/usr/share/elasticsearch/config/instance.key",
                "xpack.security.transport.ssl.certificate": "/usr/share/elasticsearch/config/instance.crt",
                "xpack.security.http.ssl.enabled": "true",
                "xpack.security.http.ssl.key": "/usr/share/elasticsearch/config/instance.key",
                "xpack.security.http.ssl.certificate": "/usr/share/elasticsearch/config/instance.crt",
            },
            ulimits=[
                docker.types.Ulimit(name='memlock', soft=-1, hard=-1),
            ],
            name="elasticsearch",
            restart_policy=DEFAULT_RESTART_POLICY,
        )
        self.assertEqual(expected_value, result)

    def test_start_new_kibana_container(self):
        from orchestration.shared import \
            start_new_kibana_container
        expected_value = 1
        image_id = 'test'
        image_build_timestamp = 'image_build_timestamp'
        config = {
            'controller_ip': 1,
            'elastic_password': 1
        }
        mock_client = mock.MagicMock()
        mock_client.containers.run.return_value = 1
        result = start_new_kibana_container(
            mock_client, image_id, image_build_timestamp, config
        )

        mock_client.containers.run.assert_called_once_with(
            image_id,
            detach=True,
            ports={
                '5601/tcp': ('0.0.0.0', '5601'),
            },
            labels={
                'name': "kibana",
                'version': image_build_timestamp
            },
            environment={
                "ELASTICSEARCH_HOSTS": f"https://1:9200",
                "ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES": "/etc/kibana/ca.crt",
                "ELASTICSEARCH_SSL_VERIFICATIONMODE": "none",
                "ELASTICSEARCH_USERNAME": "elastic",
                "ELASTICSEARCH_PASSWORD": 1,
            },
            volumes={
                '/var/run/':  # XXX
                    {
                        'bind': '/var/run/',
                        'mode': 'ro'
                    }
            },
            name="kibana",
            restart_policy=DEFAULT_RESTART_POLICY,
        )
        self.assertEqual(expected_value, result)

    def test_start_new_filebeat_container(self):
        from orchestration.shared import \
            start_new_filebeat_container
        expected_value = 1
        dnet = 'test_dnet'
        edge_name = 'test_edge.prod.deflect.ca'
        config = {
            'controller_ip': 1,
            'elastic_password': 1,
            'edge_names_to_dnets': {edge_name: 'test_dnet'}
        }
        image_id = 'test'
        image_build_timestamp = 'image_build_timestamp'
        mock_client = mock.MagicMock()
        mock_client.info.return_value = {'Name': 'test_edge'}
        mock_client.containers.run.return_value = 1
        result = start_new_filebeat_container(
            mock_client, image_id, image_build_timestamp, config
        )

        mock_client.containers.run.assert_called_once_with(
            image_id,
            detach=True,
            user="root",
            labels={
                'name': "filebeat",
                'version': image_build_timestamp
            },
            hostname=edge_name,
            environment={
                "ELASTICSEARCH_HOST": f"https://1:9200",
                "KIBANA_HOST": f"https://1:5601",
                "ELASTICSEARCH_PASSWORD": 1,
                "DEFLECT_EDGE_NAME": edge_name,
                "DEFLECT_DNET": dnet,
            },
            volumes={
                '/var/run/':  # XXX
                    {
                        'bind': '/var/run/',
                        'mode': 'ro'
                    },
                '/var/lib/docker/containers/':  # XXX
                    {
                        'bind': '/var/lib/docker/containers/',
                        'mode': 'ro'
                    },
            },
            name="filebeat",
            restart_policy=DEFAULT_RESTART_POLICY,
        )
        self.assertEqual(expected_value, result)

    def test_start_new_container(self):
        raise NotImplementedError

    def test_kill_containers_with_label(self):
        from orchestration.shared import kill_containers_with_label

        expected_value = None
        label = 'test'
        mock_client = mock.MagicMock()
        mock_container_1 = mock.MagicMock()
        mock_container_2 = mock.MagicMock()
        mock_client.containers.list.return_value = [
            mock_container_1, mock_container_2
        ]
        containers_list = [
            mock_container_1, mock_container_2,
            mock_container_1, mock_container_2
        ]
        result = kill_containers_with_label(
            mock_client, label
        )
        for c in containers_list:
            c.kill.assert_called()
            self.assertEqual(c.kill.call_count, 2)
        self.assertEqual(expected_value, result)

    def test_kill_containers_with_label_exception(self):
        from orchestration.shared import \
            kill_containers_with_label
        expected_value = None
        label = 'test'
        mock_client = mock.MagicMock()
        mock_container_1 = mock.MagicMock()
        mock_container_2 = mock.MagicMock()
        mock_container_1.kill.side_effect = mock.Mock(
            side_effect=Exception('Test')
        )
        mock_client.containers.list.return_value = [
            mock_container_1, mock_container_2
        ]
        containers_list = [
            mock_container_1, mock_container_2,
            mock_container_1, mock_container_2
        ]
        result = kill_containers_with_label(
            mock_client, label
        )
        for i, c in enumerate(containers_list):
            c.kill.assert_called()
            self.assertEqual(c.kill.call_count, 2)
            if not i % 2 == 0:
                c.remove.assert_called()
                self.assertEqual(c.remove.call_count, 2)
        self.assertEqual(expected_value, result)

    def test_get_all_sites(self):
        pass
