from orchestration.run_container.base_class import Container


class Bind(Container):
    def update(self, config_timestamp):
        with open(f"output/{config_timestamp}/etc-bind.tar", "rb") as f:
            self.container.put_archive("/etc/bind", f.read())

        # call named checks
        (exit_code, output) = self.container.exec_run('/etc/bind/named-checks.sh')
        self.logger.info(output.decode())
        if exit_code != 0:
            raise Exception("named-check.sh failed")

        self.container.kill(signal="SIGHUP")

    def toggle_recursion(self, recursion):
        """
        Toggle recursion on or off for certbot challenge
        """
        sed_cmd = ""
        if recursion:
            self.logger.info("enabling bind recursion")
            sed_cmd = "sed 's/recursion no/recursion yes/g' /etc/bind/named.conf.local"
        else:
            self.logger.info("disableing bind recursion")
            sed_cmd = "sed 's/recursion yes/recursion no/g' /etc/bind/named.conf.local"

        # print the output for logging
        (exit_code, output) = self.container.exec_run(sed_cmd)
        self.logger.debug(output.decode())

        # actually run the command
        sed_cmd = sed_cmd.replace('sed', 'sed -i')
        self.container.exec_run(sed_cmd)
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
            restart_policy=Container.DEFAULT_RESTART_POLICY,
            volumes={
                "bind-data": {"bind": "/etc/bind", "mode": "rw"},
            }
        )
