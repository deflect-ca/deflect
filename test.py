import docker

client = docker.DockerClient(
        base_url="ssh://root@46.101.104.167"
)
print(client)
