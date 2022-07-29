from orchestration.run_container.base_class import Container


class EdgeManage(Container):
    def update(self, config_timestamp):
        with open(f"output/{config_timestamp}/etc-edgemanage.tar", "rb") as f:
            self.container.put_archive("/etc/edgemanage", f.read())

        # run init script to update crontab config
        (exit_code, output) = self.container.exec_run("/init.sh")
        if exit_code != 0:
            self.logger.error(f"edgemanage init failed. output: {output}")
            raise Exception("edgemanage init failed")

    def start_new_container(self, config, image_id):
        # We create a container here that does nothing
        # but bind to a volume of /etc/edgemanage so we can upload stuff to it
        # before the edgemanage container starts
        self.logger.info("starting edgemanage-config container")
        edgemanage_config_container = self.client.containers.run(
            "debian:buster-slim",
            command="sleep infinity",
            detach=True,
            labels={
                'name': "edgemanage-config",
            },
            volumes={
                "edgemanage-data": {"bind": "/etc/edgemanage", "mode": "rw"},
            },
            name="edgemanage-config",
            restart_policy=Container.DEFAULT_RESTART_POLICY
        )

        self.logger.info("uploading etc-edgemanage.tar to edgemanage config container")
        with open(f"output/{self.timestamp}/etc-edgemanage.tar", "rb") as f:
            edgemanage_config_container.put_archive("/etc/edgemanage", f.read())

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
                "bind-cache": {"bind": "/var/cache/bind", "mode": "rw"},
                "edgemanage-state": {"bind": "/var/lib/edgemanage", "mode": "rw"},
                "edgemanage-data": {"bind": "/etc/edgemanage", "mode": "rw"},
                config["prometheus_data"]["host_path"]: {
                    "bind": config["prometheus_data"]["container_path"],
                    "mode": "rw",
                },
            },
        )
