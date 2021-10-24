from orchestration.run_container.base_class import Container
from orchestration.run_container.base_class import get_persisted_config

class Filebeat(Container):
    def update(self, config_timestamp):
        pass

    def start_new_container(self, config, image_id):
        return self.client.containers.run(
            image_id,
            detach=True,
            user="root",  # XXX needed?
            labels={
                'name': "filebeat",
            },
            hostname=self.hostname,
            environment={
                "ELASTICSEARCH_HOST": f"https://{config['controller']['ip']}:9200",
                "KIBANA_HOST": f"https://{config['controller']['ip']}:5601",
                "ELASTICSEARCH_PASSWORD": get_persisted_config()['elastic_password'],
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
