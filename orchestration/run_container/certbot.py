import os
import shutil
import subprocess
import tarfile
import OpenSSL
from time import time
from datetime import datetime
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from orchestration.run_container import Bind
from orchestration.run_container.base_class import Container
from util.helpers import path_to_input, symlink_force


class Certbot(Container):
    """
    Process of the certbot container

    1. clear everything in /etc/letsencrypt/{archive,live,renewal} to
       start fresh (in case container is running)
    2. check previous certs under input/certs/latest.tar
      2.1. check for snake oil certs, remove them so we gen new ones
      2.2. check for expired certs, remove them so we gen new ones
      2.3. repack the latest.tar if we removed something in 2.1 or 2.2
    3. upload latest.tar (or latest_repack.tar) to certbot container,
       extract at /etc/letsencrypt/archive
    4. register certbot (if going to run certbot)
    5. turn on bind recursion for acme-challenge (if going to run certbot)
    6. call certbot
      6.1. certonly for missing certs
      6.2. skip for certs which exist in /etc/letsencrypt/archive
    7. turn off bind recursion
    8. generate snake oil certs for certs failling letsencrypt
    9. pack all the certs (including the previously uploaded, newly obtain
       from letsencrypt and snake oil) in to latest.tar
    10. packing latest.tar for the correct format to nginx
    11. move latest.tar to input/certs/{timestamp}.tar and create a symlink
        to latest.tar
    """
    def __init__(self, client, config, find_existing=False, kill_existing=False, logger=None):
        super().__init__(client, config, find_existing, kill_existing, logger)
        self.client_and_system_sites = {}
        self.sites_with_certs = []
        self.problematic_certs = {'expired_certs': [], 'snake_oil_certs': [], 'error_certs': []}
        self.tar_name = 'latest'
        self.tempdir = TemporaryDirectory()  # for extract and checking latest.tar
        if self.config['server_env'] == 'production':
            self.certbot_options = self.config['certs']['production_certbot_options']
        else:
            self.certbot_options = self.config['certs']['staging_certbot_options']

    def __del__(self):
        self.tempdir.cleanup()

    def update(self, all_sites, config, config_timestamp):
        """
        Step 1 ~ 11
        """
        self.client_and_system_sites = {**all_sites['client'], **all_sites['system']}

        # Step 1
        self.cleanup_container()

        # Step 2
        try:
            tar_path = f"./input/certs/{self.tar_name}.tar"
            tar_path = self.check_previous_certs(tar_path)
        except FileNotFoundError as err:
            self.logger.warning("Error in check_previous_certs")
            self.logger.warning(err)

        # Step 3
        try:
            with open(tar_path, "rb") as previous_certs_tar:
                self.container.put_archive("/etc/letsencrypt/", previous_certs_tar.read())
            self.logger.info(f"uploaded prev certs {tar_path} to certbot")
        except FileNotFoundError:
            self.logger.warning(f"didn't find previous certs under {tar_path}")

        # cache `ls /etc/letsencrypt/archive` result in self.sites_with_certs
        # so for checking file exist faster
        self.ls_sites_with_certs()

        # Step 6.1.
        all_skipped = True
        cert_failed_domain = []
        for domain, site in self.client_and_system_sites.items():
            # Step 6.2.
            action = self.cert_action_selector(domain)
            if action == 'skip':
                continue

            # Hitting this line means some cert isn't skipped
            # We only do step 4 and 5 if we have to call certbot
            if all_skipped:
                # Step 4
                self.register_certbot()
                # Step 5 allow recursion for bind server temporary only if necessary
                Bind(self.client, config,
                     find_existing=True, logger=self.logger).toggle_recursion(True)
                all_skipped = False

            # since we removed expired cert, we treat them the same
            # get a new cert for the expired cert to consider it as new certs
            if action == 'renew' or action == 'certonly':
                exit_code = self.certbot_certonly(domain, site)
                if exit_code != 0:
                    self.logger.warning(f"{domain} certbot exit_code: {exit_code}")
                    cert_failed_domain.append(domain)

        # Step 7
        if not all_skipped:
            Bind(self.client, config,
                 find_existing=True, logger=self.logger).toggle_recursion(False)

        if len(cert_failed_domain) == 0:
            self.logger.info("ran certbot certonly, all success")
        else:
            self.logger.warning(f"ran certbot and failed "
                                f"{len(cert_failed_domain)} certs: {str(cert_failed_domain)}")

        # Step 8
        if len(cert_failed_domain) > 0:
            self.ls_sites_with_certs()

        for no_cert_domain in cert_failed_domain:
            if no_cert_domain not in self.sites_with_certs:
                self.generate_snake_oil_certs(no_cert_domain)
            else:
                self.logger.warning(f"{no_cert_domain} failed "
                                     "but still has certs, not gen snake oil certs")

        # Step 9
        etc_ssl_sites_tarfile_name = self.save_new_certs(config_timestamp)

        # Step 10, pack it for format to upload
        self.tar_gzip(etc_ssl_sites_tarfile_name)

        # Step 11. copy this to input for next time use
        unixtime = self.copy_to_input_and_ln_latest(etc_ssl_sites_tarfile_name)

        if not all_skipped:
            self.save_renewal_conf(config_timestamp, unixtime)

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

    def generate_snake_oil_certs(self, no_cert_domain):
        """
        generate a self-signed cert for a domain that doesn't have one
        this will prevent our nginx breaks because cert is missing
        """
        # self sign one cert so we don't break nginx
        self.logger.warning(f"Gen snakeoil certs for {no_cert_domain}")
        self.container.exec_run(f"mkdir -p /etc/letsencrypt/archive/{no_cert_domain}")
        # don't change the OU=SnakeOilCert, this is used to tell if this cert is a snakeoil cert
        OU = "SnakeOilCert"
        _, output = self.container.exec_run(
            "openssl req -new -newkey rsa:2048 -days 365 -nodes -x509"
            f" -subj \"{self.config['certs']['self_sign_subj']}/OU={OU}/CN={no_cert_domain}\""
            f" -keyout /etc/letsencrypt/archive/{no_cert_domain}/privkey1.pem"
            f" -out /etc/letsencrypt/archive/{no_cert_domain}/fullchain1.pem")
        self.logger.info(output.decode())
        # add a empty file for human eye debugging (no for verfication)
        self.container.exec_run(
            f"touch -p /etc/letsencrypt/archive/{no_cert_domain}/SnakeOilCert")

    def check_previous_certs(self, latest_tar):
        """check expire and if snakeoil cert"""
        original_path = latest_tar
        path = self.tempdir.name
        now = datetime.utcnow()
        repack = False

        self.logger.info(f"Extracting prev certs to {path} for checking")
        with tarfile.open(original_path, "r") as latest_tar_file:
            latest_tar_file.extractall(path=path)

        for domain, site in self.client_and_system_sites.items():
            if site.get("uploaded_cert_bundle_name"):
                self.logger.info(f"{domain} has uploaded cert bundle, skip checking here")
                continue

            fullchain_path = os.path.join(path, 'archive', domain, "fullchain1.pem")
            key_path = os.path.join(path, 'archive', domain, "privkey1.pem")
            if not os.path.isfile(fullchain_path) or not os.path.isfile(key_path):
                self.logger.warning(f"{domain} missing cert or key, skip checking")
                shutil.rmtree(os.path.join(path, 'archive', domain))
                continue

            if not self.check_associate_cert_with_private_key(domain, fullchain_path, key_path):
                repack = True
                self.problematic_certs['error_certs'].append(domain)
                shutil.rmtree(os.path.join(path, 'archive', domain))
                self.logger.info(f"removed error certs for {domain}")
                continue

            with open(fullchain_path, "rb") as fullchain1:
                cert_bytes = fullchain1.read()
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            self.logger.info(f"subject: {cert.subject}, issuer: {cert.issuer}, "
                             f"expires: {cert.not_valid_after}")
            # cert.issuer contains SnakeOilCert
            if "SnakeOilCert" in cert.issuer.rfc4514_string():
                repack = True
                self.problematic_certs['snake_oil_certs'].append(domain)
                shutil.rmtree(os.path.join(path, 'archive', domain))
                self.logger.info(f"removed snake oil cert for {domain}")
            # cert expired
            if now > cert.not_valid_after:
                repack = True
                self.problematic_certs['expired_certs'].append(domain)
                shutil.rmtree(os.path.join(path, 'archive', domain))
                self.logger.info(f"removed expired cert for {domain}")

        self.logger.warning(f"snake_oil_certs: {self.problematic_certs['snake_oil_certs']}")
        self.logger.warning(f"expired_certs: {self.problematic_certs['expired_certs']}")
        self.logger.warning(f"error_certs: {self.problematic_certs['error_certs']}")

        # repack because we deleted some certs
        if repack:
            tar_path = os.path.join(path, 'latest_repack.tar')
            with tarfile.open(tar_path, "w") as latest_repack:
                latest_repack.add(os.path.join(path, 'archive'), arcname='archive')
        else:
            tar_path = latest_tar
        return tar_path

    def cert_action_selector(self, domain):
        # custom certs
        if self.client_and_system_sites[domain].get('uploaded_cert_bundle_name'):
            self.logger.info(f"{domain} has uploaded cert bundle, skip certbot")
            return 'skip'
        # expired certs
        if domain in self.problematic_certs['expired_certs']:
            self.logger.info(f"{domain} expired and should be renew")
            return 'renew'
        # the autodeflect-formatted ones...
        if f"{domain}.le.key" in self.sites_with_certs:
            self.logger.info(f"{domain} (.le.key) already has a cert, skip certonly")
            return 'skip'
        # the letsencrypt / deflect-next formatted ones...
        if domain in self.sites_with_certs:
            self.logger.info(f"{domain} already has a cert, skip certonly")
            return 'skip'
        return 'certonly'

    def certbot_certonly(self, domain, site, action='certonly'):
        domains_args = "-d " + " -d ".join(site['server_names'])
        self.logger.info(f"trying to get a cert for {site['server_names']}")
        self.logger.info(domains_args)
        self.logger.info(f"Using certbot options: {self.certbot_options}")
        (exit_code, output) = self.container.exec_run(
            f"certbot {action} {self.certbot_options} --non-interactive --agree-tos"
            f" --preferred-challenges dns --cert-name {domain}"
            " --authenticator certbot-dns-standalone:dns-standalone"
            " --certbot-dns-standalone:dns-standalone-address=127.0.0.1"
            f" --certbot-dns-standalone:dns-standalone-port=5053 {domains_args}"
        )
        self.logger.info(output.decode())
        return exit_code

    def ls_sites_with_certs(self):
        (exit_code, output) = self.container.exec_run("ls /etc/letsencrypt/archive")
        if exit_code == 0:
            self.sites_with_certs = output.decode().splitlines()
            self.logger.info(f"sites_with_certs: {self.sites_with_certs}")

    def register_certbot(self):
        (_, output) = self.container.exec_run(
            f"certbot register {self.certbot_options} --agree-tos --non-interactive")
        self.logger.info(output)
        self.logger.info("certbot registered")

    def cleanup_container(self):
        # XXX this is another place where certbot might try to connect to pebble before pebble
        # is accepting connections.
        # XXX should i be removing this directory? do i need to worry about
        # stale certs being here?
        self.logger.info('Cleaning /etc/letsencrypt/{archive,live,renewal}...')
        self.container.exec_run("rm -rf /etc/letsencrypt/archive")
        self.container.exec_run("rm -rf /etc/letsencrypt/live")
        self.container.exec_run("rm -rf /etc/letsencrypt/renewal")
        self.container.exec_run("mkdir -p /etc/letsencrypt/archive")

    def save_new_certs(self, config_timestamp):
        etc_ssl_sites_tarfile_name = f"./output/{config_timestamp}/etc-ssl-sites.tar"
        with open(etc_ssl_sites_tarfile_name, "wb") as tar_file:
            (chunks, _) = self.container.get_archive("/etc/letsencrypt/archive")
            for chunk in chunks:
                tar_file.write(chunk)

        # Never extract archives from untrusted sources without prior inspection. It is
        # possible that files are created outside of path, e.g. members that have
        # absolute filenames starting with "/" or filenames with two dots "..".
        with tarfile.open(etc_ssl_sites_tarfile_name, "r") as tar_file:
            tar_file.extractall(path=f"./output/{config_timestamp}/")

        return etc_ssl_sites_tarfile_name

    def tar_gzip(self, etc_ssl_sites_tarfile_name):
        gzip_proc = subprocess.run(["gzip", "--keep", "--force", etc_ssl_sites_tarfile_name],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if gzip_proc.returncode != 0:
            self.logger.warn(gzip_proc.stdout)
            self.logger.warn(gzip_proc.stderr)
            raise Exception("gzipping etc-ssl-sites.tar got non-zero exit code")

        # XXX put_archive() only accepts a tar, so...
        with tarfile.open(etc_ssl_sites_tarfile_name + ".gz.tar", "w") as tar_file:
            tar_file.add(etc_ssl_sites_tarfile_name + ".gz")

    def copy_to_input_and_ln_latest(self, etc_ssl_sites_tarfile_name):
        unixtime = str(int(time()))
        latest_certs_in_input = f"{path_to_input()}/certs/{unixtime}.tar"
        ln_target = f"{path_to_input()}/certs/{self.tar_name}.tar"

        if not os.path.isdir("./input/certs"):
            os.mkdir("./input/certs")

        shutil.copyfile(etc_ssl_sites_tarfile_name, latest_certs_in_input)
        self.logger.info(f"copied {etc_ssl_sites_tarfile_name} to {latest_certs_in_input}")
        symlink_force(latest_certs_in_input, ln_target)
        self.logger.info(f"created symlink {ln_target} -> {latest_certs_in_input}")
        return unixtime

    def save_renewal_conf(self, config_timestamp, unixtime):
        # just saving renewal for safety, not using it for now
        try:
            renewal_tarfile_name = f"output/{config_timestamp}/etc-ssl-sites-renewal.tar"
            latest_renewal_in_input = f"{path_to_input()}/certs/{unixtime}-renewal.tar"
            ln_target = f"{path_to_input()}/certs/{self.tar_name}-renewal.tar"

            with open(renewal_tarfile_name, "wb") as tar_file:
                (chunks, _) = self.container.get_archive("/etc/letsencrypt/renewal")
                for chunk in chunks:
                    tar_file.write(chunk)

            shutil.copyfile(renewal_tarfile_name, latest_renewal_in_input)
            self.logger.info(f"copied {renewal_tarfile_name} to {latest_renewal_in_input}")
            symlink_force(latest_renewal_in_input, ln_target)
            self.logger.info(f"created symlink {ln_target} -> {latest_renewal_in_input}")
        except Exception as err:
            self.logger.info(str(err))
            self.logger.info('Save renewal failed, but this is for backup only')

    def check_associate_cert_with_private_key(self, domain, cert, private_key):
        """
        :type cert: str
        :type private_key: str
        :rtype: bool
        """
        try:
            with open(private_key, "rb") as private_key_file:
                private_key_obj = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key_file.read())
        except OpenSSL.crypto.Error as err:
            self.logger.warning(err)
            self.logger.warning(f"{domain} has invalid private key")
            return False

        try:
            with open(cert, "rb") as cert_file:
                cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_file.read())
        except OpenSSL.crypto.Error as err:
            self.logger.warning(err)
            self.logger.warning(f"{domain} has invalid private certs")
            return False

        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
        context.use_privatekey(private_key_obj)
        context.use_certificate(cert_obj)
        try:
            context.check_privatekey()
            return True
        except OpenSSL.SSL.Error:
            self.logger.warning(f"{domain} key does not match with its certs")
            return False
