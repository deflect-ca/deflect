from orchestration.run_container.base_class import Container


class EdgeManage(Container):
    def update(self, config_timestamp):
        with open(f"output/{config_timestamp}/etc-edgemanage.tar", "rb") as f:
            self.container.put_archive("/etc/edgemanage", f.read())

        # XXX: I think we don't need this because edgemanage is not a service?
        # self.container.kill(signal="SIGHUP")

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
                config["prometheus_data"]["host_path"]: {
                    "bind": config["prometheus_data"]["container_path"],
                    "mode": "rw",
                },
            },
        )
