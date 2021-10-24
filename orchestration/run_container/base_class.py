import logging
import os.path
from util.helpers import get_logger, path_to_containers, get_persisted_config_yml_path
logger = get_logger(__name__, logging_level=logging.DEBUG)

import yaml

# XXX this is weird and should be cleaned up
def get_persisted_config():
    p_conf = {}
    if not os.path.isfile(get_persisted_config_yml_path()):
        return {}
    with open(get_persisted_config_yml_path(), "r") as f:
        p_conf = yaml.load(f)
    return p_conf

def save_persisted_config(p_conf):
    with open(get_persisted_config_yml_path(), "w") as f:
        yaml.dump(p_conf, f)

def kill_containers_with_label(client, label):
    logger.info(f"killing containers with label or name {label}")
    print(f"killing containers with label or name {label}")
    # XXX this doesn't work TODO: fixme
    containers1 = client.containers.list(
        all=True,
        filters={'label': f"name={label}"}
    )
    containers2 = client.containers.list(
        all=True,
        filters={'name': label}
    )
    for container in containers1 + containers2:
        logger.info(f"killing {container} with label or name {label}")
        print(f"killing {container} with label or name {label}")
        # XXX ugh all of this
        try:
            container.kill()
        except:
            logger.error('Could not kill container')
            pass
        try:
            container.remove()  # XXX just so i can use a name later... re-think
        except:
            logger.error('Could not remove container')
            pass



class Container:
    known_containers = []

    # TODO: needs to be in config, especially because we might need different
    # TODO:.. retry policies per container
    CONTAINER_MAX_RETRY_COUNT = 5
    DEFAULT_RESTART_POLICY = {
        "Name": "on-failure", "MaximumRetryCount": CONTAINER_MAX_RETRY_COUNT
    }

    def __init__(self, client, config, config_timestamp, find_existing=False, kill_existing=False):
        self.client = client
        concrete_class = self.__class__.__name__
        self.set_hostname_and_dnet(config)
        self.config_timestamp = config_timestamp.replace(":", "_")
        self.lowercase_name = {
            "Banjax": "banjax",
            "Bind": "bind",
            "Certbot": "certbot",
            "DohProxy": "doh-proxy",
            "Elasticsearch": "elasticsearch",
            "Filebeat": "filebeat",
            "Kibana": "kibana",
            "Metricbeat": "metricbeat",
            "Nginx": "nginx",
            "Pebble": "pebble",
            "TestOrigin": "test-origin",
        }[concrete_class]
        if find_existing:
            self.container = self.find_existing_or_start_new_container(config)
        elif kill_existing:
            self.container = self.kill_build_and_start_container(config)
        else:
            logger.error("Container() constructor requires either `find_existing` or `kill_existing`")
            raise RuntimeError("Container() constructor requires either `find_existing` or `kill_existing`")
        Container.known_containers.append(self.container)


    def update(self):
        raise RuntimeError("need to implement update() in the concrete class")

    def start_new_container(self, config, image_id):
        raise RuntimeError("need to implement start_new_container() in the concrete class")

    def _get_image_name(self, name, registry=''):
        if registry:
            registry += ':'
        # user/registry:tag
        return f"{registry}deflect-next-{name}",

    def build_image(self, registry=''):
        """
        Builds a new image based on the image name,
        returns image and respective logs
        """
        (image, image_logs) = self.client.images.build(
            path=f"{path_to_containers()}/{self.lowercase_name}",
            tag=self._get_image_name(self.lowercase_name, registry),
            rm=True     # remove intermediate containers to avoid system pollution
        )
        return image, image_logs

    def kill_build_and_start_container(self, config):
        kill_containers_with_label(self.client, self.lowercase_name)
        (image, image_logs) = self.build_image()
        return self.start_new_container(config, image.id)


    def find_existing_or_start_new_container(self, config):
        """
        Find a container based on image_name
        If one does not exist, kill any containers with image_name
        and build a new one
        """
        logger.info(f"find_existing_or_start_new ({self.lowercase_name})")
        containers = self.client.containers.list(
            filters={"label": f"name={self.lowercase_name}"}
        )

        if len(containers) == 1:
            logger.debug(f"find_existing_or_start_new ({self.lowercase_name}), found 1")
            return containers[0]
        if len(containers) == 0:
            logger.debug(f"find_existing_or_start_new ({self.lowercase_name}), found 0")
            return self.kill_build_and_start_container(config)
        raise Exception(
            f"expected 0 or 1 container called {self.lowercase_name}, but found {len(containers)}")

    def set_hostname_and_dnet(self, config):
        hostname = f"{self.client.info().get('Name')}"
        self.hostname = hostname
        for c_edge in config['edges']:
            if c_edge['hostname'].startswith(hostname):
                self.dnet = c_edge['dnet']
        self.dnet = "controller"  # XXX hacky

