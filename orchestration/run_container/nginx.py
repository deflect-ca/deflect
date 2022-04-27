from datetime import datetime

from orchestration.run_container.base_class import Container
from util.helpers import FILENAMES_TO_TAIL, path_to_output


class Nginx(Container):
    def update(self, config_timestamp):
        self.container.exec_run("rm -rf /etc/nginx")
        self.container.exec_run("mkdir -p /etc/nginx")

        self.logger.info(f"installing nginx config for host '{self.hostname}', dnet '{self.dnet}'")
        with open(f"{path_to_output()}/{config_timestamp}/etc-nginx-{self.dnet}.tar", "rb") as f:
            self.container.put_archive("/etc/nginx", f.read())

        # XXX should i do this? stale certs?
        self.container.exec_run("rm -rf /etc/ssl/sites")

        # XXX currently all the certs are on every edge. we should make it so each edge
        # only has the certs for the dnet it belongs to.
        with open(f"{path_to_output()}/{config_timestamp}/etc-ssl-sites.tar.gz.tar", "rb") as f:
            self.container.put_archive("/etc/ssl/", f.read())

        # # XXX is this right? what about the live directory?
        # self.container.exec_run("mv /etc/ssl/archive /etc/ssl/sites")

        self.container.exec_run(f"tar xzf /etc/ssl/output/{config_timestamp}/etc-ssl-sites.tar.gz --directory /etc/ssl")
        self.container.exec_run("mv /etc/ssl/archive /etc/ssl/sites")

        # XXX specific to our internals
        # with open(f"{path_to_output()}/{config_timestamp}/etc-ssl-uploaded.tar", "rb") as f:
        #     self.container.put_archive("/etc/ssl-uploaded/", f.read())

        # XXX note that sending this signal does not guarantee the new config is actually loaded.
        # the config might be invalid.
        (exit_code, output) = self.container.exec_run("nginx -t")
        if exit_code != 0:
            self.logger.error(f"nginx config failed validation. output: {output}")
            raise Exception("nginx config failed validation")
        else:
            self.container.kill(signal="SIGHUP")

        self.logger.info("installed new config + certs on nginx container")

        # >>> d["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
        # '172.17.0.5'
        resp = self.client.api.inspect_container(self.container.id)
        self.logger.info(
            f" !!! nginx container ip is "
            f"{resp['NetworkSettings']['Networks']['bridge']['IPAddress']}"
        )

    def start_new_container(self, config, image_id):
        """
        Using the same volume: runs as many (tailer) containers as the
        FILENAMES_TO_TAIL and eventually starts a new nginx container
        """
        build_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        logs_volume = self.client.volumes.create(name=f"nginx-{build_timestamp}")
        # XXX think about this approach. also need to delete these containers...
        # TODO: delete? when?
        for filename_to_tail in FILENAMES_TO_TAIL:
            base_name = filename_to_tail.split("/")[-1].replace(".", "-")  # XXX
            self.logger.info(f'Run container for: {base_name}')
            self.client.containers.run(
                "debian:buster-slim",
                command=f"tail --retry --follow=name {filename_to_tail}",
                detach=True,
                labels={
                        'name': "nginx-log-tailer",
                        'version': build_timestamp,
                        'ngx_log_file': base_name
                },
                volumes={
                    logs_volume.name:
                    {
                        'bind': '/var/log/nginx/',
                        'mode': 'ro'
                    },
                },
                name=f"nginx-{base_name}-tailer-{build_timestamp}",
                restart_policy=Container.DEFAULT_RESTART_POLICY,
            )
        return self.client.containers.run(
            image_id,
            detach=True,
            # XXX revisit this with the nat switcher and 0-downtime deploy stuff
            # ports={
            #     '80/tcp': ('0.0.0.0', None),  # None means docker chooses an available port
            #     '443/tcp': ('0.0.0.0', None), # XXX making these private ports public for now
            # },
            ports={
                '80/tcp': ('0.0.0.0', 80),
                '443/tcp': ('0.0.0.0', 443),
            },
            labels={
                'name': "nginx",
                'version': build_timestamp
            },
            # XXX making a volume for access logs, and a bind mount for the banjax stuff...
            # think about this.
            volumes={
                logs_volume.name:
                {
                    'bind': '/var/log/nginx/',
                    'mode': 'rw'
                }
            },
            name=f"nginx-{build_timestamp}",
            restart_policy=Container.DEFAULT_RESTART_POLICY
        )
