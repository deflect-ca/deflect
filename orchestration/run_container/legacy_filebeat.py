from orchestration.run_container.base_class import Container


class LegacyFilebeat(Container):
    def update(self, config_timestamp):
        with open(f"output/{config_timestamp}/etc-legacy-filebeat.tar", "rb") as f:
            self.container.put_archive("/etc/filebeat", f.read())

        # print file stat
        (_, output) = self.container.exec_run(
            "stat /var/log/nginx/nginx-logstash-format.log /var/log/banjax/banjax-logstash-format.log")
        self.logger.info(output.decode('utf-8'))


    def start_new_container(self, config, image_id):
        return self.client.containers.run(
            image_id,
            detach=True,
            user="root",
            labels={
                'name': "legacy-filebeat",
            },
            hostname=self.hostname,
            environment={
                "LOGSTASH_HOST": config['logging']['logstash_external']['logstash_host'],
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
            name="legacy-filebeat",
            restart_policy=Container.DEFAULT_RESTART_POLICY,
        )
