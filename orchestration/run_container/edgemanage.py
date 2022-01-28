from orchestration.run_container.base_class import Container


class EdgeManage(Container):
    def update(self, config_timestamp):
        #with open(f"output/{config_timestamp}/etc-edgemanage.tar", "rb") as f:
        #    self.container.put_archive("/etc/edgemanage", f.read())
        self.container.kill(signal="SIGHUP")

    def start_new_container(self, config, image_id):
        return self.client.containers.run(
            image_id,
            detach=True,
            ports={},
            labels={
                "name": "edgemanage",
            },
            name="edgemanage",
            restart_policy=Container.DEFAULT_RESTART_POLICY,
            # XXX should we specify container id instead?
            network_mode="container:bind",
            volumes={
                "bind-data": {"bind": "/etc/bind", "mode": "rw"},
            },
        )
