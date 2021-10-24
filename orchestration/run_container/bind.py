from orchestration.run_container.base_class import Container


class Bind(Container):
    def update(self, config_timestamp):
        with open(f"output/{config_timestamp}/etc-bind.tar", "rb") as f:
            self.container.put_archive("/etc/bind", f.read())
        self.container.kill(signal="SIGHUP")


    def start_new_container(self, config, image_id):
        return self.client.containers.run(
            image_id,
            detach=True,
            ports={
                '53/udp': ('0.0.0.0', '53'),
                '53/tcp': ('0.0.0.0', '53'),
                '8085/tcp': ('0.0.0.0', '8085'),  # XXX for doh-proxy
            },
            labels={
                'name': "bind",
            },
            name="bind",
            restart_policy=Container.DEFAULT_RESTART_POLICY
        )


