from orchestration.run_container.base_class import Container
import logging
from util.helpers import get_logger, FILENAMES_TO_TAIL, path_to_output
logger = get_logger(__name__, logging_level=logging.DEBUG)

class Nginx(Container):
    def update(self, config_timestamp):
        self.container.exec_run("rm -rf /etc/nginx")
        self.container.exec_run("mkdir -p /etc/nginx")

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

        with open(f"{path_to_output()}/{config_timestamp}/etc-ssl-uploaded.tar", "rb") as f:
            self.container.put_archive("/etc/ssl-uploaded/", f.read())

        # XXX note that sending this signal does not guarantee the new config is actually loaded.
        # the config might be invalid.
        self.container.kill(signal="SIGHUP")

        logger.debug("installed new config + certs on nginx container")

        # >>> d["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
        # '172.17.0.5'
        resp = self.client.api.inspect_container(self.container.id)
        logger.info(
            f" !!! nginx container ip is "
            f"{resp['NetworkSettings']['Networks']['bridge']['IPAddress']}"
        )

    def start_new_container(self, config, image_id):
        """
        Using the same volume: runs as many (tailer) containers as the
        FILENAMES_TO_TAIL and eventually starts a new nginx container
        """
        logs_volume = self.client.volumes.create(name=f"nginx-{self.config_timestamp}")
        # XXX think about this approach. also need to delete these containers...
        # TODO: delete? when?
        for filename_to_tail in FILENAMES_TO_TAIL:
            base_name = filename_to_tail.split("/")[-1].replace(".", "-")  # XXX
            logger.debug(f'Run container for: {base_name}')
            self.client.containers.run(
                "debian:buster-slim",
                command=f"tail --retry --follow=name {filename_to_tail}",
                detach=True,
                labels={
                        'name': "nginx-log-tailer",
                        'version': self.config_timestamp,
                        'ngx_log_file': base_name
                },
                volumes={
                    logs_volume.name:
                    {
                        'bind': '/var/log/nginx/',
                        'mode': 'ro'
                    },
                },
                name=f"nginx-{base_name}-tailer-{self.config_timestamp}",
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
                'version': self.config_timestamp
            },
            # XXX making a volume for access logs, and a bind mount for the banjax-next stuff...
            # think about this.
            volumes={
                logs_volume.name:
                {
                    'bind': '/var/log/nginx/',
                    'mode': 'rw'
                },
                '/root/banjax/':
                {
                    'bind': '/var/log/banjax/',
                    'mode': 'rw'
                }
            },
            name=f"nginx-{self.config_timestamp}",
            restart_policy=Container.DEFAULT_RESTART_POLICY
        )


