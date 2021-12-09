from orchestration.run_container.base_class import Container
from orchestration.run_container.base_class import get_persisted_config
from util.helpers import path_to_input


class Kibana(Container):
    def _upload_saved_objects(self):
        import aiohttp
        import asyncio

        # XXX might have to wait for kibana to start accepting connections.
        # XXX don't want to re-upload this every time
        # XXX maybe requests is nicer?...
        async def main():
            async with aiohttp.ClientSession() as session:
                with open(f"{path_to_input()}/kibana-saved-objects.ndjson", "r") as f:
                    url = f"https://kibana.{self.hostname}/api/saved_objects/_import?overwrite=true"
                    headers = {"kbn-xsrf": "true"}
                    data = aiohttp.FormData()
                    data.add_field("file", f)
                    async with session.post(url, data=data, headers=headers) as resp:
                        self.logger.debug(
                            f"posted saved objects to kibana, response: {resp.status}")
                        self.logger.debug(await resp.text())

        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())

    def update(self, config_timestamp):
        pass
        # self._upload_saved_objects()

    def start_new_container(self, config, image_id):
        ELASTICSEARCH_HOST = config['logging']['elasticsearch_host']
        ELASTICSEARCH_PASSWORD = config['logging']['elasticsearch_password']

        if config['server_env'] != 'production':
            ELASTICSEARCH_HOST = "https://127.0.0.1:9200"  # joined ES network
            ELASTICSEARCH_PASSWORD = get_persisted_config()['elastic_password']

        return self.client.containers.run(
            image_id,
            detach=True,
            labels={
                'name': "kibana",
            },
            environment={
                "ELASTICSEARCH_HOSTS": ELASTICSEARCH_HOST,
                "ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES": "/etc/kibana/ca.crt",
                "ELASTICSEARCH_SSL_VERIFICATIONMODE": "none",
                "ELASTICSEARCH_USERNAME": "elastic",
                "ELASTICSEARCH_PASSWORD": ELASTICSEARCH_PASSWORD,
            },
            volumes={
                '/var/run/':  # XXX
                {
                    'bind': '/var/run/',
                            'mode': 'ro'
                }
            },
            name="kibana",
            restart_policy=Container.DEFAULT_RESTART_POLICY,
            network_mode="container:elasticsearch",  # join es netowkr to connect via loclahost
        )
