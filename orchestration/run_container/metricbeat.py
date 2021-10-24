from orchestration.run_container.base_class import Container
from orchestration.run_container.base_class import get_persisted_config


class Metricbeat(Container):
    def update(self, config_timestamp):
        pass

    def start_new_container(self, config, image_id):
        # XXX consider a different approach (making the caller pass in the network and fs namespaces?)
        nginx_containers = self.client.containers.list(
            filters={"label": "name=nginx"}
        )

        if len(nginx_containers) != 1:
            print("start_new_metricbeat_container() expected to find a single running nginx container (whose namespaces we can join)")
            raise Exception

        nginx_container = nginx_containers[0]

        return self.client.containers.run(
            image_id,
            detach=True,
            user="root",
            labels={
                'name': "metricbeat",
            },
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
                '/sys/fs/cgroup':  # XXX
                    {
                        'bind': '/hostfs/sys/fs/cgroup',
                                'mode': 'ro'
                    },
                '/proc':  # XXX
                    {
                        'bind': '/hostfs/proc',
                                'mode': 'ro'
                    },
            },
            name="metricbeat",
            network_mode=f"container:{nginx_container.name}",
            # extra_hosts={"nginx": "127.0.0.1"}, # XXX can't set Host header in metricbeat
            restart_policy={"Name": "on-failure", "MaximumRetryCount": 5},
        )


