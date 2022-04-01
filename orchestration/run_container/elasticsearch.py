from config_generation.generate_elastic_keys import generate_new_elastic_certs
from orchestration.run_container.base_class import Container
from orchestration.run_container.base_class import get_persisted_config, save_persisted_config
from util.helpers import path_to_persisted
import os.path
import docker
import time
import traceback
import requests


def attempt_to_authenticate(ip, logger):
    p_conf = get_persisted_config()
    if 'elastic_password' not in p_conf:
        logger.warn("'elastic_password' not in persisted/config, auth failed")
        return False
    ca_file = f"{path_to_persisted()}/elastic_certs/ca.crt"
    if not os.path.isfile(ca_file):
        logger.warn("persisted/elastic_certs/ca.crt not found, auth failed")
        return False
    for _ in range(0, 5):
        logger.info(f"attempting to auth with password {p_conf['elastic_password']}")
        try:
            r = requests.get(
                    f"https://{ip}:9200",
                    verify=ca_file,
                    auth=("elastic", p_conf['elastic_password'])
            )
            logger.info(r.text)
            if r.status_code == 401:
                return False
            else:
                return True
        except Exception:
            logger.info("sleeping and retrying...")
            time.sleep(5)
    return False


class Elasticsearch(Container):
    def build_image(self, config, registry=''):
        for f in ["ca.crt", "ca.key", "instance.crt", "instance.key"]:
            if not os.path.isfile(os.path.join(path_to_persisted(), f)):
                self.logger.warn(f"ES didn't find persisted/{f}, so re-generating all certs")
                break
        else:
            self.logger.info("ES found all required certs under persisted/, not re-generating")
            return super().build_image()
        generate_new_elastic_certs(config, self.logger)

        return super().build_image(config, registry)

    # Changed password for user elastic
    # PASSWORD elastic = ${ELASTICSEARCH_PASSWORD}
    # etc.
    # i don't like screen-scraping CLIs, but my understanding of the documentation
    # is that this does a lot that would be annoying to do with the http rest api.
    def _get_elastic_password_from_command_output(self, output):
        lines = output.decode().splitlines()
        for line in lines:
            if line.startswith("PASSWORD elastic"):
                password = line.split(" ")[-1]
                self.logger.info(f"found elastic password: {password}")
                return password
        else:
            raise Exception("!!! did not find elastic password")

    def _generate_creds(self):
        for _ in range(0, 5):
            (exit_code, output) = self.container.exec_run(
                "elasticsearch-setup-passwords auto --batch "
                "-E 'xpack.security.transport.ssl.certificate_authorities=/usr/share/elasticsearch/config/ca.crt' "
                "-E 'xpack.security.transport.ssl.verification_mode=certificate' "
                "-E 'xpack.security.http.ssl.certificate_authorities=/usr/share/elasticsearch/config/ca.crt' "
                "-E 'xpack.security.http.ssl.verification_mode=certificate' "
            )
            try:
                self.logger.debug(output)
                elastic_password = self._get_elastic_password_from_command_output(output)
                break
            except Exception:
                traceback.print_exc()
                self.logger.info("waiting for /usr/share/elasticsearch/config/elasticsearch.keystore to appear...")
                time.sleep(5)
                continue
        else:
            raise Exception("!!! did not find elastic password 5 times !!!")

        # XXX this is weird
        p_conf = get_persisted_config()
        p_conf['elastic_password'] = elastic_password
        save_persisted_config(p_conf)

    def update(self, config_timestamp):
        # check if we already have certs + creds
        if attempt_to_authenticate(self.ip, self.logger):
            return
        # self._generate_certs()
        self._generate_creds()
        if not attempt_to_authenticate(self.ip, self.logger):
            self.logger.error("!!! we tried to generate certs and creds but still can't connect to ES !!!")
            self.logger.error("curl -v --resolve <name>:9200:<ip> --cacert persisted/elastic_certs/ca.crt https://<name>:9200 --user 'elastic:<pass>'")
            self.logger.error("could be 1) bad certs, 2) bad user/pass, 3) your bind9 server isn't running")
            raise RuntimeError("bad")

    def start_new_container(self, config, image_id):
        return self.client.containers.run(
            image_id,
            detach=True,
            ports={
                '9200/tcp': ('0.0.0.0', '9200'),
                '5601/tcp': ('0.0.0.0', '5601'), # for kibana joining network
            },
            labels={
                'name': "elasticsearch",
            },
            environment={
                "discovery.type": "single-node",
                "bootstrap.memory_lock": "true",
                "ES_JAVA_OPTS": "-Xms512m -Xmx512m",
                "xpack.security.enabled": "true",
                "xpack.security.transport.ssl.enabled": "true",
                "xpack.security.transport.ssl.key": "/usr/share/elasticsearch/config/instance.key",
                "xpack.security.transport.ssl.certificate": "/usr/share/elasticsearch/config/instance.crt",
                "xpack.security.http.ssl.enabled": "true",
                "xpack.security.http.ssl.key": "/usr/share/elasticsearch/config/instance.key",
                "xpack.security.http.ssl.certificate": "/usr/share/elasticsearch/config/instance.crt",
            },
            ulimits=[
                docker.types.Ulimit(name='memlock', soft=-1, hard=-1),
            ],
            name="elasticsearch",
            restart_policy=Container.DEFAULT_RESTART_POLICY,
        )
