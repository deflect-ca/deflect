import unittest
from unittest import mock


class TestInstallDeltaConfig(unittest.TestCase):
    def setUp(self):
        self.mock_client = mock.MagicMock()
        self.image_name = 'test_image'
        self.image_build_timestamp = 'image_build_timestamp'

    @mock.patch(
        "orchestration.install_delta_config.kill_containers_with_label",
        return_value=['a', 'b']
    )
    @mock.patch("orchestration.shared.build_new_image", return_value=['a', 'b'])
    @mock.patch(
        "orchestration.shared.start_new_container",
        return_value='start_new_container'
    )
    def test_kill_build_and_start_container(
            self,
            mock_kill,
            mock_build,
            mock_start
    ):
        from orchestration.install_delta_config import kill_build_and_start_container
        expected_result = 'start_new_container'
        result = kill_build_and_start_container(
            self.mock_client, self.image_name, self.image_build_timestamp
        )
        self.assertEqual(result, expected_result)
        # TODO fixme: config?

    @mock.patch("orchestration.shared.find_existing_or_start_new_container",
                return_value=mock.MagicMock())
    def test_install_bind_config(self, mock_find):
        from orchestration.install_delta_config import install_bind_config
        mock_open = mock.mock_open(read_data=b'test')
        with mock.patch('builtins.open', mock_open):
            expected_result = None
            config = {}
            # TODO: fixme: all_sites not used
            result = install_bind_config(
                self.mock_client,
                config,
                {},
                self.image_build_timestamp,
                self.image_build_timestamp
            )
            self.assertEqual(result, expected_result)
            bind_container = mock_find.return_value
            bind_container.put_archive.assert_called_once()
            bind_container.kill.assert_called_once_with(signal="SIGHUP")

    @mock.patch("orchestration.shared.find_existing_or_start_new_container",
                return_value=mock.MagicMock())
    def test_install_doh_proxy_config(self, mock_find):
        from orchestration.install_delta_config import install_doh_proxy_config
        expected_result = None
        config = {}
        # TODO: fixme: all_sites and config_timestamp not used
        result = install_doh_proxy_config(
            self.mock_client,
            config,
            {},
            self.image_build_timestamp,
            self.image_build_timestamp
        )
        self.assertEqual(result, expected_result)
        # TODO: not much to test here, is it used?

    @mock.patch(
        "orchestration.shared.find_existing_or_start_new_container",
        return_value=mock.MagicMock()
    )
    @mock.patch("tarfile.open", return_value=mock.MagicMock())
    def test_run_certbot_and_get_certs(self, mock_tarfile_open, mock_find):
        from orchestration.install_delta_config import run_certbot_and_get_certs
        mock_open = mock.mock_open(read_data=b'test')
        mock_find.return_value.exec_run.return_value = 'exit_code', b'output'
        mock_find.return_value.get_archive.return_value = ['chunks'], 'stat'
        with mock.patch('builtins.open', mock_open):
            expected_result = None
            config = {
                'certbot_options': ['test']
            }
            all_sites = {
                'client': {
                    'a': {'server_names': ['server_a']}
                },
                'system': {
                    'c': {'server_names': ['server_c']}
                }
            }
            result = run_certbot_and_get_certs(
                self.mock_client,
                config,
                all_sites,
                self.image_build_timestamp,
                self.image_build_timestamp
            )
            self.assertEqual(result, expected_result)
            mock_tarfile_open.assert_called_once()
            # mock_tarfile.extractall.assert_called_once()
            container = mock_find.return_value
            container.exec_run.assert_called()
            container.get_archive.assert_called_once()

    @mock.patch(
        "orchestration.install_delta_config.kill_build_and_start_container",
        return_value=mock.MagicMock()
    )
    def test_install_banjax_next_config(self, mock_kill):
        from orchestration.install_delta_config import install_banjax_next_config
        mock_open = mock.mock_open(read_data=b'test')
        with mock.patch('builtins.open', mock_open):
            expected_result = None
            config = {}
            # TODO: reload container
            result = install_banjax_next_config(
                self.mock_client,
                config,
                {},
                self.image_build_timestamp
            )
            self.assertEqual(result, expected_result)
            container = mock_kill.return_value
            container.put_archive.assert_called_once()
            # container.kill.assert_called_once_with(signal="SIGHUP")

    @mock.patch("orchestration.shared.find_existing_or_start_new_container",
                return_value=mock.MagicMock())
    def test_install_nginx_config(self, mock_find):
        from orchestration.install_delta_config import install_nginx_config
        mock_open = mock.mock_open(read_data=b'test')
        with mock.patch('builtins.open', mock_open):
            expected_result = None
            config = {}
            # TODO: fixme: all_sites not used
            result = install_nginx_config(
                self.mock_client,
                config,
                {},
                self.image_build_timestamp,
                self.image_build_timestamp
            )
            self.assertEqual(result, expected_result)
            container = mock_find.return_value
            # todo: ensure details
            container.exec_run.assert_called()
            container.put_archive.assert_called()
            container.kill.assert_called_once_with(signal="SIGHUP")

    @mock.patch(
        "orchestration.install_delta_config.kill_build_and_start_container",
        return_value=mock.MagicMock()
    )
    def test_install_test_origin_config(self, mock_kill):
        from orchestration.install_delta_config import install_test_origin_config
        expected_result = None
        config = {}
        # TODO: fixme: all_sites not used
        result = install_test_origin_config(
            self.mock_client,
            config,
            {},
            self.image_build_timestamp,
            self.image_build_timestamp
        )
        self.assertEqual(result, expected_result)
        # todo: ensure details
        mock_kill.assert_called_once()

    def test_import_kibana_saved_objects(self):
        raise NotImplementedError

    def test_get_elastic_password_from_command_output(self):
        raise NotImplementedError

    def test_install_elasticsearch_kibana(self):
        raise NotImplementedError

    @mock.patch("orchestration.shared.find_existing_or_start_new_container",
                return_value=mock.MagicMock())
    def test_install_filebeat(self, mock_find):
        from orchestration.install_delta_config import install_filebeat
        expected_result = None
        config = {}
        # TODO: fixme: all_sites not used
        result = install_filebeat(
            self.mock_client,
            config,
            {},
            self.image_build_timestamp,
            self.image_build_timestamp
        )
        self.assertEqual(result, expected_result)
        mock_find.assert_called_once_with(
            self.mock_client, "filebeat", self.image_build_timestamp, config
        )

    @mock.patch("orchestration.shared.find_existing_or_start_new_container",
                return_value=mock.MagicMock())
    def test_install_legacy_filebeat(self, mock_find):
        from orchestration.install_delta_config import install_legacy_filebeat
        expected_result = None
        config = {}
        # TODO: fixme: all_sites not used
        result = install_legacy_filebeat(
            self.mock_client,
            config,
            {},
            self.image_build_timestamp,
            self.image_build_timestamp
        )
        self.assertEqual(result, expected_result)
        mock_find.assert_called_once_with(
            self.mock_client, "legacy-filebeat", self.image_build_timestamp, config
        )

    @mock.patch("orchestration.shared.find_existing_or_start_new_container",
                return_value=mock.MagicMock())
    def test_install_legacy_logstash(self, mock_find):
        from orchestration.install_delta_config import install_legacy_logstash
        expected_result = None
        config = {}
        # TODO: fixme: all_sites not used
        result = install_legacy_logstash(
            self.mock_client,
            config,
            {},
            self.image_build_timestamp,
            self.image_build_timestamp
        )
        self.assertEqual(result, expected_result)
        mock_find.assert_called_once_with(
            self.mock_client, "legacy-logstash", self.image_build_timestamp, config
        )

    # TODO: the following needs either too many mocks or restructuring?
    # @mock.patch("docker", return_value=mock.MagicMock())
    # @mock.patch("install_bind_config", return_value=mock.MagicMock())
    # @mock.patch("install_doh_proxy_config", return_value=mock.MagicMock())
    # @mock.patch("install_test_origin_config", return_value=mock.MagicMock())
    # def test_main(self, mock_docker):
    #     from orchestration.install_delta_config import main
    #     mock_open = mock.mock_open(read_data=b'test')
    #     with mock.patch('builtins.open', mock_open):
    #         expected_result = None
    #         config = {
    #             'dnets_to_edges': {
    #                 'a': 'b',
    #                 'c': 'd',
    #             }
    #         }
    #         # TODO: fixme: all_sites not used
    #         result = main(
    #             config,
    #             {},
    #             self.image_build_timestamp,
    #             self.image_build_timestamp
    #         )
    #         self.assertEqual(result, expected_result)