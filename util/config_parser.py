import copy

from pyaml_env import parse_config

from util.helpers import get_config_file_path, get_container_default_config_path


def parse_container_config_with_defaults(container_name, config_name):
    config_path = get_config_file_path(config_name)
    defaults_path = get_container_default_config_path(container_name, config_name)
    config = parse_config(config_path)
    defaults = parse_config(defaults_path)
    return set_defaults(config, defaults)


def set_defaults(config, defaults):
    for key, element in defaults.items():
        if type(element) == dict:
            if key in config:
                set_defaults(config[key], defaults[key])
            else:
                config[key] = copy.deepcopy(element)
        elif key not in config:
            config[key] = element
    return config
