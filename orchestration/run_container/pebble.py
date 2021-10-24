from orchestration.run_container.base_class import Container

class Pebble(Container):
    def update(self, config_timestamp):
        pass

    def start_new_container(self, config, image_id):
        return self.client.containers.run(
            image_id,
            command="pebble -config /test/config/pebble-config.json -dnsserver 127.0.0.1:53",
            # command="sleep infinity",
            detach=True,
            labels={
                    'name': "pebble",
            },
            environment={
                'PEBBLE_VA_NOSLEEP': "1",
            },
            name="pebble",
            restart_policy=Container.DEFAULT_RESTART_POLICY,
            # XXX should we specify container id instead?
            network_mode="container:bind"
        )



