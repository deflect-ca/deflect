from orchestration.run_container.base_class import Container
from util.helpers import (
    path_to_persisted,
)
import os.path


class Pebble(Container):
    # XXX i'm saving the CA to persisted/, but i'm not loading it from there yet
    def update(self, timestamp):
        self.logger.info("getting intermediate cert from pebble...")
        # XXX possible you need to wait for pebble to start accepting connections...
        (exit_code, output) = self.container.exec_run(
                "curl --silent -k https://localhost:15000/intermediates/0"
        )
        self.logger.debug(output)
        with open(os.path.join(path_to_persisted(), "pebble_ca.crt"), "wb") as dest:
            dest.write(output)
        self.logger.info("saved intermediate cert from pebble to persisted/pebble_ca.crt")

    def start_new_container(self, config, image_id):
        return self.client.containers.run(
            image_id,
            command="pebble -config /test/config/pebble-config.json -dnsserver 127.0.0.1:53",
            detach=True,
            labels={
                    'name': "pebble",
            },
            environment={
                'PEBBLE_VA_NOSLEEP': "1",
            },
            name="pebble",
            restart_policy=Container.DEFAULT_RESTART_POLICY,
            # XXX should we specify container id instead?
            network_mode="container:bind"
        )
