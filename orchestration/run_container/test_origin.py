from orchestration.run_container.base_class import Container


class TestOrigin(Container):
    def update(self, config_timestamp):
        pass

    def start_new_container(self, config, image_id):
        return self.client.containers.run(
            image_id,
            detach=True,
            ports={
                '8080/tcp': ('0.0.0.0', '8080'),
            },
            labels={
                'name': "test-origin",
            },
            name="test-origin",
            restart_policy=Container.DEFAULT_RESTART_POLICY
        )
