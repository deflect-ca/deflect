import os
import unittest
from pathlib import Path
from unittest.mock import patch

from util.config_parser import parse_container_config_with_defaults


def fixtures_path(file=""):
    return os.path.join(str(Path(__file__).parent.parent), "fixtures", file)


class TestConfigParser(unittest.TestCase):

    @patch("util.helpers.get_container_path", new=fixtures_path)
    @patch("util.helpers.path_to_input", new=fixtures_path)
    def test_parse_container_config_with_defaults(self):
        config = parse_container_config_with_defaults("edgemanage",
                                                      "edgemanage.yaml")

        # Basic assertion to check that all the settings are present after
        # merging the defaults
        self.assertEqual(4, len(config))

        # Check that a default value has been propagated
        self.assertEqual("/static/deflectlogo_RED.png",
                         config["testobject"]["uri"])

        # Check that new values overwrite default ones
        self.assertEqual(80,
                         config["testobject"]["port"])

        # Check that values that are not defined in the defaults are included 
        self.assertEqual(4,
                         config["edge_count"])

