from orchestration.run_container.base_class import Container


class KafkaFilebeat(Container):
    def update(self, config_timestamp):
        with open(f"output/{config_timestamp}/etc-kafka-filebeat.tar", "rb") as f:
            self.container.put_archive("/etc/filebeat", f.read())

    def start_new_container(self, config, image_id):
        return self.client.containers.run(
            image_id,
            detach=True,
            user="root",
            labels={
                'name': "kafka-filebeat",
            },
            hostname=self.hostname,
            environment={
                "LOGSTASH_HOST": config['logging']['logstash_external']['logstash_host'],
                "KAFKA_HOST1": config['logging']['logstash_external']['kafka_host1'],
                "KAFKA_HOST2": config['logging']['logstash_external']['kafka_host2'],
                "KAFKA_HOST3": config['logging']['logstash_external']['kafka_host3'],
                "KAFKA_TOPIC": config['logging']['logstash_external']['kafka_topic'],
                "DEFLECT_EDGE_NAME": self.hostname,
                "DEFLECT_DNET": self.dnet,
                "FILEBEAT_LOG_LEVEL": config['logging'].get('filebeat_log_level', 'warning'),
            },
            volumes={
                self.get_volume_name('nginx', '/var/log/nginx'):
                {
                    'bind': '/var/log/nginx/',
                    'mode': 'ro'
                },
                self.get_volume_name('banjax', '/var/log/banjax'):
                {
                    'bind': '/var/log/banjax/',
                    'mode': 'ro'
                }
            },
            name="kafka-filebeat",
            restart_policy=Container.DEFAULT_RESTART_POLICY,
        )
