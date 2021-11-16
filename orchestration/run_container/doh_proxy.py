from orchestration.run_container.base_class import Container


class DohProxy(Container):
    def update(self, config_timestamp):
        pass

    def start_new_container(self, config, image_id):
        return self.client.containers.run(
            image_id,
            detach=True,
            labels={
                'name': "doh-proxy",
            },
            name="doh-proxy",
            restart_policy=Container.DEFAULT_RESTART_POLICY,
            # XXX should we specify container id instead?
            network_mode="container:bind"
        )
