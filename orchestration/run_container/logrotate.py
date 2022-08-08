from orchestration.run_container.base_class import Container


class Logrotate(Container):
    def update(self, timestamp):
        pass

    def start_new_container(self, config, image_id):
        return self.client.containers.run(
            image_id,
            detach=True,
            user="root",
            labels={
                'name': "logrotate",
            },
            hostname=self.hostname,
            environment={
                "LOGROTATE_CRON": "0 0 * * *",  # run daily
            },
            volumes={
                self.get_volume_name('nginx', '/var/log/nginx'):
                {
                    'bind': '/var/log/nginx/',
                    'mode': 'rw'
                },
                self.get_volume_name('banjax', '/var/log/banjax'):
                {
                    'bind': '/var/log/banjax/',
                    'mode': 'rw'
                }
            },
            name="logrotate",
            restart_policy=Container.DEFAULT_RESTART_POLICY,
        )
