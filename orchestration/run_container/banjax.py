from orchestration.run_container.base_class import Container

import logging
from util.helpers import get_logger
logger = get_logger(__name__, logging_level=logging.DEBUG)


class Banjax(Container):
    def update(self, config_timestamp):
        with open(f"output/{config_timestamp}/etc-banjax.tar", "rb") as f:
            self.container.put_archive("/etc/banjax", f.read())

        # XXX config reload not implemented yet
        #  banjax_container.kill(signal="SIGHUP")


    def start_new_container(self, config, image_id):
        # XXX consider a different approach (making the caller pass in the network and fs namespaces?)
        nginx_containers = self.client.containers.list(
            filters={"label": f"name=nginx"}
        )

        if len(nginx_containers) != 1:
            logger.error(
                f"start_new_banjax_container() expected to find a single "
                f"running nginx container (whose namespaces we can join)"
            )
            raise Exception

        nginx_container = nginx_containers[0]

        # XXX bad duplication with the nginx log tailers above
        filenames_to_tail = [
            "/var/log/banjax/gin.log",
            "/var/log/banjax/metrics.log",
        ]
        for filename in filenames_to_tail:
            base_name = filename.split("/")[-1].replace(".", "-")  # XXX
            self.client.containers.run(
                "debian:buster-slim",
                command=f"tail --retry --follow=name {filename}",
                detach=True,
                labels={
                        'name': "banjax-log-tailer",
                        'banjax_next_log_file': base_name
                },
                volumes={  # XXX check out volumes_from?
                    '/root/banjax/':  # XXX
                    {
                        'bind': '/var/log/banjax/',
                        'mode': 'ro'
                    }
                },
                name=f"banjax-log-{base_name}",
                restart_policy={"Name": "on-failure", "MaximumRetryCount": 5}
            )

        return self.client.containers.run(
            image_id,
            detach=True,
            labels={
                'name': "banjax",
            },
            volumes={  # XXX check out volumes_from?
                '/root/banjax/':  # XXX
                {
                    'bind': '/var/log/banjax/',
                    'mode': 'rw'
                }
            },
            name="banjax",
            restart_policy=Container.DEFAULT_RESTART_POLICY,
            cap_add=["NET_ADMIN"],
            # XXX should we specify container id instead?
            network_mode=f"container:{nginx_container.name}"
        )


