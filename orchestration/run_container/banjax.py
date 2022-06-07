from datetime import datetime
from orchestration.run_container.base_class import Container, find_existing_container


class Banjax(Container):
    def update(self, config_timestamp):
        with open(f"output/{config_timestamp}/etc-banjax.tar", "rb") as f:
            self.container.put_archive("/etc/banjax", f.read())

        self.logger.info('Sending SIGHUP to banjax container')
        self.container.kill(signal="SIGHUP")

    def start_new_container(self, config, image_id):
        # XXX consider a different approach (making the caller pass in the network and fs namespaces?)
        nginx_containers = self.client.containers.list(
            filters={"label": "name=nginx"}
        )

        if len(nginx_containers) != 1:
            self.logger.error(
                "start_new_banjax_container() expected to find a single "
                "running nginx container (whose namespaces we can join)"
            )
            raise Exception

        build_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        banjax_logs_volume = self.client.volumes.create(name=f"banjax-{build_timestamp}")

        nginx_container = nginx_containers[0]
        nginx_d = self.client.api.inspect_container(nginx_container.id)
        nginx_logs_volume_name = None
        for mount in nginx_d["Mounts"]:
            if mount["Type"] == "volume":
                if mount["Destination"] == "/var/log/nginx":
                    nginx_logs_volume_name = mount["Name"]
                    break
        else:
            self.logger.error(nginx_d["Mounts"])
            raise Exception("couldn't find log volume in nginx container")

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
                        'banjax_log_file': base_name
                },
                volumes={  # XXX check out volumes_from?
                    banjax_logs_volume.name:  # XXX
                    {
                        'bind': '/var/log/banjax/',
                        'mode': 'ro'
                    }
                },
                name=f"banjax-log-{base_name}",
                restart_policy={"Name": "on-failure", "MaximumRetryCount": 5}
            )

        self.logger.info("starting banjax config container")
        banjax_config_container = self.client.containers.run(
            "debian:buster-slim",
            command="sleep infinity",
            detach=True,
            labels={
                'name': "banjax-config",
            },
            volumes={
                'banjax-config-volume':
                {
                    'bind': '/etc/banjax/',
                    'mode': 'rw'
                }
            },
            name="banjax-config",
            restart_policy=Container.DEFAULT_RESTART_POLICY
        )
        self.logger.info("uploading etc-banjax.tar to banjax config container")
        with open(f"output/{self.timestamp}/etc-banjax.tar", "rb") as tar:
            banjax_config_container.put_archive("/etc/banjax", tar.read())

        return self.client.containers.run(
            image_id,
            detach=True,
            labels={
                'name': "banjax",
            },
            volumes={  # XXX check out volumes_from?
                nginx_logs_volume_name:  # XXX
                {
                    'bind': '/var/log/nginx/',
                    'mode': 'rw'
                },
                banjax_logs_volume.name:  # XXX
                {
                    'bind': '/var/log/banjax/',
                    'mode': 'rw'
                },
                'banjax-config-volume':
                {
                    'bind': '/etc/banjax/',
                    'mode': 'rw'
                }
            },
            name="banjax",
            restart_policy=Container.DEFAULT_RESTART_POLICY,
            cap_add=["NET_ADMIN"],
            # XXX should we specify container id instead?
            network_mode=f"container:{nginx_container.name}"
        )
