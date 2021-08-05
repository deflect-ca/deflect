# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import unittest
from unittest import mock


class TestGenerateNginxConfig(unittest.TestCase):
    # def setUp(self):
    #     self.nginx_patcher = mock.patch('nginx')
    #     self.nginx_mock = self.nginx_patcher.start()
    #
    # def tearDown(self) -> None:
    #     if self.nginx_patcher:
    #         self.nginx_patcher.stop()

    @mock.patch('nginx.Conf')
    @mock.patch('nginx.Key')
    def test_redirect_to_https_server_block(self, mock_key, mock_config):
        test_site = {
            'server_names': ['a', 'b', 'c']
        }
        from orchestration.generate_nginx_config import \
            redirect_to_https_server_block
        result = redirect_to_https_server_block(test_site)
        mock_config.assert_called_once()
        mock_key.assert_has_calls(
            [
            ['set', "$loc_in \"redir_to_ssl\""],
            ['set', "$loc_out \"redir_to_ssl\""],
            ['server_name', "a b c"],
            ['listen', '80'],
            ['return', f"301 https://$server_name$request_uri/"],
            ]
        )

    def test_access_log_banjax_next_format(self):
        raise NotImplementedError

    def test_proxy_pass_to_origin_server_block(self):
        raise NotImplementedError

    def test_proxy_pass_to_banjax_keys(self):
        raise NotImplementedError

    def test_proxy_pass_password_protected_path(self):
        raise NotImplementedError

    def test_proxy_pass_cache_exception(self):
        raise NotImplementedError

    def test_proxy_pass_to_origin_location_block(self):
        raise NotImplementedError

    def test_proxy_pass_to_origin_location_block_dont_challenge_static_files(self):
        raise NotImplementedError

    def test_access_granted_fail_open_location_contents(self):
        raise NotImplementedError

    def test_access_granted_location_block(self):
        raise NotImplementedError

    def test_fail_open_location_block(self):
        raise NotImplementedError

    def test_per_site_include_conf(self):
        raise NotImplementedError

    def test_top_level_conf(self):
        raise NotImplementedError

    def test_default_site_content_cache_include_conf(self):
        raise NotImplementedError

    def test_access_denied_location(self):
        raise NotImplementedError

    def test_fail_closed_location_block(self):
        raise NotImplementedError

    def test_main(self):
        raise NotImplementedError
