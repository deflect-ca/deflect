from orchestration.run_container.base_class import Container
from orchestration.run_container import Bind
import tarfile
import subprocess
import shutil
import os
import errno
from time import time
from util.helpers import path_to_input


class Certbot(Container):
    def update(self, all_sites, config, config_timestamp):
        # XXX this is another place where certbot might try to connect to pebble before pebble
        # is accepting connections.
        # XXX should i be removing this directory? do i need to worry about
        # stale certs being here?
        (exit_code, output) = self.container.exec_run("rm -rf /etc/letsencrypt/archive")
        (exit_code, output) = self.container.exec_run("rm -rf /etc/letsencrypt/live")
        (exit_code, output) = self.container.exec_run("rm -rf /etc/letsencrypt/renewal")
        (exit_code, output) = self.container.exec_run(
            "mkdir -p /etc/letsencrypt/archive")

        try:
            with open(f"./input/certs/latest.tar", "rb") as f:
                self.container.put_archive("/etc/letsencrypt/", f.read())
            self.logger.info(f"uploaded prev certs input/certs/latest.tar to certbot")
        except FileNotFoundError:
            self.logger.warning("didn't find previous certs under input/certs/latest.tar")

        (exit_code, output) = self.container.exec_run(
            f"certbot register {config['production_certbot_options']} --agree-tos --non-interactive"
        )
        self.logger.info(output)
        self.logger.info("certbot registered")

        # (exit_code, output) = self.container.exec_run(
        #     f"certbot renew {config['certbot_options']}"
        # )

        # XXX should be handled by the 'renew' command instead of doing it manually like this
        (exit_code, output) = self.container.exec_run(
            "ls /etc/letsencrypt/archive")
        sites_with_certs = output.decode().splitlines()

        client_and_system_sites = {**all_sites['client'], **all_sites['system']}
        # XXX always get a real non-staging cert for sites in the system list?
        # client_and_system_sites = {**all_sites['system']}

        # allow recursion
        Bind(self.client, config, find_existing=True, logger=self.logger).toggle_recursion(True)

        for domain, site in client_and_system_sites.items():
            # the autodeflect-formatted ones...
            if f"{domain}.le.key" in sites_with_certs:
                self.logger.info(f"{domain} (.le.key) already has a cert, skip certbot")
                continue
            # the letsencrypt / deflect-next formatted ones...
            if domain in sites_with_certs:
                self.logger.info(f"{domain} already has a cert, skip certbot")
                continue
            self.logger.info(f"trying to get a cert for {site['server_names']}")
            domains_args = "-d " + " -d ".join(site['server_names'])
            self.logger.info(domains_args)
            certbot_options = config['production_certbot_options'] if config['server_env'] == 'production' else config['staging_certbot_options']
            self.logger.info(f"Using certbot options: {certbot_options}")
            (exit_code, output) = self.container.exec_run(
                f"certbot certonly {certbot_options} --non-interactive --agree-tos"
                f" --preferred-challenges dns --cert-name {domain}"
                " --authenticator certbot-dns-standalone:dns-standalone"
                " --certbot-dns-standalone:dns-standalone-address=127.0.0.1"
                f" --certbot-dns-standalone:dns-standalone-port=5053 {domains_args}"
            )
            self.logger.info(output.decode())

        self.logger.info("ran certbot certonly")
        Bind(self.client, config, find_existing=True, logger=self.logger).toggle_recursion(False)

        with open(f"output/{config_timestamp}/etc-ssl-sites.tar", "wb") as tar_file:
            (chunks, stat) = self.container.get_archive(
                "/etc/letsencrypt/archive")
            for chunk in chunks:
                tar_file.write(chunk)

        etc_ssl_sites_tarfile_name = f"./output/{config_timestamp}/etc-ssl-sites.tar"
        # Never extract archives from untrusted sources without prior inspection. It is
        # possible that files are created outside of path, e.g. members that have
        # absolute filenames starting with "/" or filenames with two dots "..".
        with tarfile.open(etc_ssl_sites_tarfile_name, "r") as tar_file:
            tar_file.extractall(path=f"./output/{config_timestamp}/")

        # XXX might be worth it to compress this before we send it (later)
        gzip_proc = subprocess.run(["gzip", "--keep", "--force", etc_ssl_sites_tarfile_name],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if gzip_proc.returncode != 0:
            self.logger.warn(gzip_proc.stdout)
            self.logger.warn(gzip_proc.stderr)
            raise Exception("gzipping etc-ssl-sites.tar got non-zero exit code")

        # XXX put_archive() only accepts a tar, so...
        with tarfile.open(etc_ssl_sites_tarfile_name + ".gz.tar", "w") as tar_file:
            tar_file.add(etc_ssl_sites_tarfile_name + ".gz")

        # copy this to input for next time use
        latest_certs_in_input = f"{path_to_input()}/certs/{str(int(time()))}.tar"
        ln_target = f"{path_to_input()}/certs/latest.tar"
        if not os.path.isdir("./input/certs"):
            os.mkdir("./input/certs")
        shutil.copyfile(etc_ssl_sites_tarfile_name, latest_certs_in_input)
        self.logger.info(f"copied {etc_ssl_sites_tarfile_name} to {latest_certs_in_input}")
        try:
            # must use abs path to do ln
            os.symlink(latest_certs_in_input, ln_target)
        except OSError as err:
            if err.errno == errno.EEXIST:
                os.remove(ln_target)
                os.symlink(latest_certs_in_input, ln_target)
            else:
                raise err
        self.logger.info(f"created symlink {ln_target} -> {latest_certs_in_input}")

    def start_new_container(self, config, image_id):
        return self.client.containers.run(
            image_id,
            detach=True,
            labels={
                'name': "certbot",
            },
            name="certbot",
            restart_policy=Container.DEFAULT_RESTART_POLICY,
            # XXX should we specify container id instead?
            network_mode="container:bind"
        )
