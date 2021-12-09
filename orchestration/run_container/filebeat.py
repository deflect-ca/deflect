from orchestration.run_container.base_class import Container
from orchestration.run_container.base_class import get_persisted_config


class Filebeat(Container):
    def update(self, config_timestamp):
        pass

    def start_new_container(self, config, image_id):
        ELASTICSEARCH_HOST = config['logging']['elasticsearch_host']
        KIBANA_HOST = config['logging']['kibana_host']
        ELASTICSEARCH_PASSWORD = config['logging']['elasticsearch_password']

        if config['server_env'] != 'production':
            controller_host = "gateway.docker.internal"
            if config['controller']['ip'] != "127.0.0.1":
                controller_host = config['controller']['ip']
            ELASTICSEARCH_HOST = f"https://{controller_host}:9200"
            KIBANA_HOST = f"https://{controller_host}:5601"
            ELASTICSEARCH_PASSWORD = get_persisted_config()['elastic_password']

        return self.client.containers.run(
            image_id,
            detach=True,
            user="root",  # XXX needed?
            labels={
                'name': "filebeat",
            },
            hostname=self.hostname,
            environment={
                "ELASTICSEARCH_HOST": ELASTICSEARCH_HOST,
                "KIBANA_HOST": KIBANA_HOST,
                "ELASTICSEARCH_PASSWORD": ELASTICSEARCH_PASSWORD,
                "DEFLECT_EDGE_NAME": self.hostname,
                "DEFLECT_DNET": self.dnet,
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
            restart_policy=Container.DEFAULT_RESTART_POLICY,
        )
