# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import datetime
import os
import click

from pyaml_env import parse_config
from OpenSSL.crypto import \
    load_certificate, FILETYPE_PEM, X509Store, X509StoreContext

from config_generation import (generate_banjax_config, generate_bind_config,
                               generate_edgemanage_config,
                               generate_legacy_filebeat_config,
                               generate_nginx_config, generate_kafka_filebeat_config,
                               generate_test_origin_config)
from config_generation.generate_elastic_keys import generate_new_elastic_certs
from config_generation.site_dict import get_all_sites
from orchestration.everything import (gather_info, install_base,
                                      install_controller, install_edges)
from orchestration.hosts import (docker_client_for_host, host_to_role,
                                 run_local_or_remote_noraise)
from orchestration.run_container.banjax import Banjax
from orchestration.run_container.certbot import Certbot
from orchestration.run_container.legacy_filebeat import LegacyFilebeat
from orchestration.run_container.logrotate import Logrotate
from orchestration.run_container.kafka_filebeat import KafkaFilebeat
from orchestration.run_container.base_class import (find_existing_container,
                                                    get_persisted_config)
from orchestration.run_container.elasticsearch import (Elasticsearch,
                                                       attempt_to_authenticate)
from util.decrypt_and_verify_cert_bundles import \
    main as decrypt_and_verify_cert_bundles, load_encrypted_cert, get_subject_and_alt_names
from util.fetch_site_yml import fetch_site_yml
from util.helpers import (get_config_yml_path, get_logger, hosts_arg_to_hosts,
                          path_to_output, reset_log_level, generate_selfsigned_cert,
                          expire_in_days, symlink_force)

logger = get_logger(__name__)


class AliasedGroup(click.Group):
    """
    Support for command alias
    you can call `util show-useful-curl-commands` as `util show`
    """
    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        matches = [x for x in self.list_commands(ctx)
                   if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail(f"Too many matches: {', '.join(sorted(matches))}")

    def resolve_command(self, ctx, args):
        # always return the full command name
        _, cmd, args = super().resolve_command(ctx, args)
        return cmd.name, cmd, args


@click.group(help='Welcome to deflect orchestration script',
             invoke_without_command=True, no_args_is_help=True)
@click.pass_context
@click.option('--debug', default=False, is_flag=True,
              help='Override log_level in global_config to DEBUG')
@click.option('--host', '-h', default='all',
              help='"all", "controller", "edges" or comma separated hostnames. '
                   'For example: "edge1,edge2,edge3" (subdomain name) '
                   'or full hostname "edge1.dev.deflect.network"')
@click.option('--action', '-a', default=None, help='DEPRECATED. Forward only')
@click.option('--quiet', '-q', is_flag=True, default=False, help='Do not print header')
def cli_base(ctx, debug, host, action, quiet):
    ctx.ensure_object(dict)
    if debug:
        reset_log_level('DEBUG')

    ctx.obj['debug'] = debug
    ctx.obj['config'] = parse_config(get_config_yml_path())
    ctx.obj['host'] = host
    ctx.obj['_hosts'], ctx.obj['_has_controller'] = hosts_arg_to_hosts(ctx.obj['config'], host)

    # backward compatibility, forwards --action to subcommands
    if action and not ctx.invoked_subcommand:
        # convert and get function name from string
        try:
            # function was named after old commands
            function_name = globals()[f"_{action.replace('-', '_')}"]
            click.echo(f"DEPRECATED: forwarding {action} to {function_name}...")
            ctx.invoke(function_name)
        except KeyError:
            # not found
            click.echo(f"Error: Action {action} not found, can't forward to command")
            raise click.Abort
    elif ctx.invoked_subcommand:
        # invoke normal subcommand
        if not quiet:
            click.echo("Welcome to Deflect orchestration script")
            print_hosts_and_ctx(ctx)
        ctx.obj['get_all_sites'] = get_all_sites(ctx.obj['config'])


@click.group(help='Generate stuff like config or certs', cls=AliasedGroup)
@click.pass_context
def gen(ctx):
    pass


@click.group(help='Install config or service', cls=AliasedGroup)
@click.pass_context
def install(ctx):
    pass


@click.group(help='Getting information from remote host', cls=AliasedGroup)
@click.pass_context
def get(ctx):
    pass


@click.group(help='Utility for admin', cls=AliasedGroup)
@click.pass_context
def util(ctx):
    pass


@click.group(help='SSL certs related utility', cls=AliasedGroup)
@click.pass_context
def certs(ctx):
    pass


@click.command('info', help='Fetch docker version via SSH for testing')
@click.pass_context
def _info(ctx):
    click.echo("Connecting to all hosts, this might take a while...")
    gather_info(ctx.obj['config'], ctx.obj['_hosts'])


@click.command('base', help='Install required package on target')
@click.pass_context
def _install_base(ctx):
    install_base(ctx.obj['config'], ctx.obj['_hosts'], logger)


@click.command('config', short_help='Generate config from input dir')
@click.option('--no-certs', is_flag=True, default=False,
              help='Do not run decrypt_and_verify_cert_bundles')
@click.pass_context
def _gen_config(ctx, no_certs):
    """Generate config from input dir

    This will generate config from input dir and
    write to output dir. No remote machine target
    is involved in this process.

    You can check the generated config by in the
    output/{timestamp} dir, where the {timestamp}
    is generated according to old_site.yml

    This command will ignore the --host option
    """
    click.echo("Generating config will ignore --hosts options as it does not matter")
    config = ctx.obj['config']
    all_sites, timestamp = ctx.obj['get_all_sites']

    logger.info('>>> Generating bind config...')
    generate_bind_config(config, all_sites, timestamp)

    logger.info('>>> Generating nginx config...')
    generate_nginx_config(all_sites, config, timestamp)

    logger.info('>>> Generating banjax config...')
    generate_banjax_config(config, all_sites, timestamp)

    logger.info('>>> Generating edgemanage config...')
    generate_edgemanage_config(config, all_sites, timestamp)

    if config['logging']['mode'] == 'logstash_external':
        logger.info('>>> Generating legacy-filebeat config...')
        generate_legacy_filebeat_config(config, all_sites, timestamp)

        if config['logging'].get('extra_output_kafka'):
            logger.info('>>> Generating kafka filebeat config...')
            generate_kafka_filebeat_config(config, all_sites, timestamp)

    if not no_certs:
        logger.info('>>> Decrypting and verifying cert bundles...')
        ctx.invoke(_decrypt_and_verify_cert_bundles)

    logger.info('>>> Generating test-origin config...')
    generate_test_origin_config(config, all_sites, timestamp)

    # add shortcuts to generated config
    symlink_force(
        f"{path_to_output()}/{timestamp}",
        f"{path_to_output()}/latest")


def abort_if_false(ctx, param, value):
    if not value:
        ctx.abort()


@click.command('config', short_help='Install config to target')
@click.option('--sync', is_flag=True, default=False,
              help='Install edge one by one, instead of all at once')
@click.option('--update-banjax', is_flag=True, default=False,
              help='Force restart banjax, and other related containers including: '
                   'legacy-filebeat, kafka-filebeat, logrotate')
@click.pass_context
def _install_config(ctx, sync, update_banjax):
    """Install config to target

    This will install config in output dir to target.
    By default it installs to all controller and edges
    defined in the global_config. You can change this
    by using the global --host options, like this:

    \b
        --host all
        --host edges
        --host controller
        --host edge1,edge2 (subdomain)
        --host edge1.dev.deflect.network
        --host controller,edge3
    """
    all_sites, timestamp = ctx.obj['get_all_sites']
    if ctx.obj['host'] == 'edges':
        install_edges(ctx.obj['config'], ctx.obj['config']['edges'],
                      all_sites, timestamp, sync=sync, update_banjax=update_banjax)
    elif ctx.obj['host'] == 'controller':
        install_controller(ctx.obj['config'], all_sites, timestamp)
    elif ctx.obj['host'] == 'all':
        install_controller(ctx.obj['config'], all_sites, timestamp)
        install_edges(ctx.obj['config'], ctx.obj['config']['edges'],
                      all_sites, timestamp, sync=sync, update_banjax=update_banjax)
    else:
        ctx.forward(_install_selected)


@click.command('selected', short_help='Install config to selected target')
@click.option('--sync', is_flag=True, default=False,
              help='Install edge one by one, instead of all at once')
@click.option('--yes', is_flag=True, callback=abort_if_false,
              expose_value=False,
              prompt='Please confirm the target _host is correct')
@click.option('--update-banjax', is_flag=True, default=False,
              help='Force restart banjax, and other related containers including: '
                   'legacy-filebeat, kafka-filebeat, logrotate')
@click.pass_context
def _install_selected(ctx, sync, update_banjax):
    all_sites, timestamp = ctx.obj['get_all_sites']
    if ctx.obj['_has_controller']:
        install_controller(ctx.obj['config'], all_sites, timestamp)

        # remove the controller from the list of _hosts
        for host in ctx.obj['_hosts']:
            if host['hostname'] == ctx.obj['config']['controller']['hostname']:
                ctx.obj['_hosts'].remove(host)

    install_edges(ctx.obj['config'], ctx.obj['_hosts'],
                  all_sites, timestamp, sync=sync, update_banjax=update_banjax)


@click.command('es', help='Install Elasticsearch')
@click.pass_context
def _install_es(ctx):
    _, timestamp = ctx.obj['get_all_sites']
    client = docker_client_for_host(ctx.obj['config']['controller'], config=ctx.obj['config'])
    es = Elasticsearch(client, ctx.obj['config'], find_existing=True, logger=logger)
    es.update(timestamp)


@click.command('banjax', help='Install and update banjax (force rebuild)')
@click.option('--yes', is_flag=True, callback=abort_if_false,
              expose_value=False,
              prompt='This will kill and rebuild banjax, are you sure?')
@click.pass_context
def _install_banjax(ctx):
    _, timestamp = ctx.obj['get_all_sites']
    for host in ctx.obj['_hosts']:
        client = docker_client_for_host(host, config=ctx.obj['config'])
        banjax = Banjax(client, ctx.obj['config'], kill_existing=True, logger=logger, timestamp=timestamp)
        banjax.update(timestamp)
    click.echo("Please rebuild legacy-filebeat & logrotate too after rebuilding banjax")


@click.command('legacy-filebeat', help='Install and update legacy-filebeat (force rebuild)')
@click.option('--yes', is_flag=True, callback=abort_if_false,
              expose_value=False,
              prompt='This will kill and rebuild legacy-filebeat, are you sure?')
@click.pass_context
def _install_legacy_filebeat(ctx):
    _, timestamp = ctx.obj['get_all_sites']
    for host in ctx.obj['_hosts']:
        client = docker_client_for_host(host, config=ctx.obj['config'])
        filebeat = LegacyFilebeat(client, ctx.obj['config'], kill_existing=True, logger=logger)
        filebeat.update(timestamp)


@click.command('logrotate', help='Install and update logrotate (force rebuild)')
@click.option('--yes', is_flag=True, callback=abort_if_false,
              expose_value=False,
              prompt='This will kill and rebuild logrotate, are you sure?')
@click.pass_context
def _install_logrotate(ctx):
    _, timestamp = ctx.obj['get_all_sites']
    for host in ctx.obj['_hosts']:
        client = docker_client_for_host(host, config=ctx.obj['config'])
        logrotate = Logrotate(client, ctx.obj['config'], kill_existing=True, logger=logger)
        logrotate.update(timestamp)


@click.command('kafka-filebeat', help='Install and update kafka-filebeat (force rebuild)')
@click.option('--yes', is_flag=True, callback=abort_if_false,
              expose_value=False,
              prompt='This will kill and rebuild kafka-filebeat, are you sure?')
@click.pass_context
def _install_kafka_filebeat(ctx):
    _, timestamp = ctx.obj['get_all_sites']
    for host in ctx.obj['_hosts']:
        client = docker_client_for_host(host, config=ctx.obj['config'])
        kafka_filebeat = KafkaFilebeat(client, ctx.obj['config'], kill_existing=True, logger=logger)
        kafka_filebeat.update(timestamp)


@click.command('certbot', help='Install and update certbot')
@click.pass_context
def _install_certbot(ctx):
    all_sites, timestamp = ctx.obj['get_all_sites']
    for host in ctx.obj['_hosts']:
        client = docker_client_for_host(host, config=ctx.obj['config'])
        Certbot(client, ctx.obj['config'], find_existing=True, logger=logger).update(
            all_sites, ctx.obj['config'], timestamp)


@click.command('test-es-auth', help='Attempt to authenticate with saved ES auth')
@click.pass_context
def _test_es_auth(ctx):
    attempt_to_authenticate(ctx.obj['config']['controller']['ip'], logger)


@click.command('kill-all-containers', help='Run docker kill $(docker ps -q) on target')
@click.option('--yes', is_flag=True, callback=abort_if_false,
              expose_value=False,
              prompt='Please confirm the target _host is correct')
@click.pass_context
def _kill_all_containers(ctx):
    command = "docker kill $(docker ps -q)"
    for host in ctx.obj['_hosts']:
        run_local_or_remote_noraise(ctx.obj['config'], host, command, logger)


@click.command('new-elastic-certs', help='Generate new ES certs')
@click.pass_context
def _gen_new_elastic_certs(ctx):
    generate_new_elastic_certs(ctx.obj['config'], logger)


@click.command('nginx-errors', help='Get nginx errors')
@click.pass_context
def _get_nginx_errors(ctx):
    hosts = ctx.obj['_hosts']
    config = ctx.obj['config']
    for host in hosts:
        client = docker_client_for_host(host, config=config)
        extra_label = "ngx_log_file=error-log"
        container = find_existing_container(client, "nginx-log-tailer", extra_label, config, logger)
        if not container:
            logger.info(f"===== nginx error log tailer not found on {host['hostname']}")
            continue

        logger.info(f"===== nginx error logs from {host['hostname']} =====")
        for line in container.logs().splitlines():
            logger.info(f"\t {line.decode()}")


@click.command('show-useful-curl-commands', help='Print curl commands for ES and edge testing')
@click.option('--domain', '-d', default='example.com', help='Domain for testing')
@click.option('--proto', '-p', default='https', help='HTTP protocol, https or http')
@click.pass_context
def _show_useful_curl_commands(ctx, domain, proto):
    hosts = ctx.obj['_hosts']
    config = ctx.obj['config']
    p_conf = get_persisted_config()
    elastic_password = p_conf.get('elastic_password', "<doesn't exist yet>")
    port = '443' if proto == 'https' else 80
    pebble = '--cacert persisted/pebble_ca.crt ' if config['server_env'] != 'production' else ''
    insecure = '--insecure ' if config['server_env'] != 'production' else ''

    print("# test the ES certs + creds:\n"
          f"curl -v --resolve {config['controller']['hostname']}:9200:{config['controller']['ip']} --cacert persisted/elastic_certs/ca.crt https://{config['controller']['hostname']}:9200 --user 'elastic:{elastic_password}'")

    print("\n# test a site through a specific edge:")
    for edge in hosts:
        print(f"curl --resolve test-origin.{config['system_root_zone']}:443:{edge['ip']} {pebble}{proto}://test-origin.{config['system_root_zone']}")
    for edge in hosts:
        print(f"curl --resolve {domain}:{port}:{edge['ip']} {pebble}{proto}://{domain}")
    for edge in hosts:
        print(f"curl --resolve {domain}:{port}:{edge['ip']} {insecure}{proto}://{domain}")

    print("\n# check SSL certs/header")
    for edge in hosts:
        print(f"curl -Iv --resolve {domain}:{port}:{edge['ip']} {insecure}{proto}://{domain}")


@click.command('curl-gen', help='Generate curl command for testing all site')
@click.option('--insecure', '-k', is_flag=True, default=False, help='Add insecure flag (-k) in curl, usually for dev')
@click.pass_context
def _curl_gen(ctx, insecure):
    import random
    config = ctx.obj['config']
    all_sites, timestamp = ctx.obj['get_all_sites']
    sites = {**all_sites['client'], **all_sites['system']}

    arg = "-L --write-out '[%{http_code}] %{url_effective} Time: %{time_connect}, Edge: %{remote_ip}, SSL: %{ssl_verify_result}\\n' --silent --output /dev/null --connect-timeout 5 --max-time 10"
    if insecure:
        arg = "-k " + arg

    for domain, site in sites.items():
        edge_ip = config['edges'][random.randrange(0, len(config['edges']))]['ip']
        port = '443' if site["https_request_does"] != 'nothing' else '80'
        print(f"curl {arg} --resolve {domain}:{port}:{edge_ip} {'https' if port == '443' else 'http'}://{domain}/")


@click.command('cmd', help='Run remote commands')
@click.option('--cmd', '-c', help='Commands to run')
@click.option('--yes', is_flag=True, callback=abort_if_false,
              expose_value=False,
              prompt='Please confirm the target _host and command is correct')
@click.pass_context
def _commands(ctx, cmd):
    for host in ctx.obj['_hosts']:
        run_local_or_remote_noraise(ctx.obj['config'], host, cmd, logger)


@click.command('banjax-decision-lists',
                help='Call banjax control endpoint')
@click.pass_context
def _get_banjax_decision_lists(ctx):
    command = "curl --silent --header 'Host: banjax' 127.0.0.1/decision_lists"
    run_remote_commands(ctx.obj['config'], ctx.obj['_hosts'], command)


@click.command('banjax-rate-limit-states',
               help='Call banjax control endpoint for rate limit states.')
@click.pass_context
def _get_banjax_rate_limit_states(ctx):
    command = "curl --silent --header 'Host: banjax' 127.0.0.1/rate_limit_states"
    run_remote_commands(ctx.obj['config'], ctx.obj['_hosts'], command)


@click.command('nginx-banjax-conf-versions',
               help='See the config version (from site dict) that nginx and banjax are running.')
@click.pass_context
def _get_nginx_and_banjax_config_versions(ctx):
    hosts = ctx.obj['_hosts']
    config = ctx.obj['config']
    nginx_command = "curl --silent 127.0.0.1/info"
    banjax_command = "curl --silent --header 'Host: banjax' 127.0.0.1/info"
    nginx_proc, banjax_proc = None, None
    for host in hosts:
        nginx_proc = run_local_or_remote_noraise(config, host, nginx_command, logger)
        if host_to_role(config, host) == "edge":
            banjax_proc = run_local_or_remote_noraise(config, host, banjax_command, logger)

        logger.info(f"===== nginx and banjax versions on {host['hostname']}")
        for line in nginx_proc.stdout.decode().splitlines():
            print(f"\t nginx: {line}")
        if banjax_proc:
            for line in banjax_proc.stdout.decode().splitlines():
                print(f"\t banjax: {line}")


@click.command('check-cert-expiry',
               help='Loop through all our certs and print the expiration time')
@click.pass_context
def _check_cert_expiry(ctx):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    all_sites, timestamp = ctx.obj['get_all_sites']
    sites = {**all_sites['client'], **all_sites['system']}
    latest_cert_dir = os.path.join(path_to_output(), timestamp, "archive")
    now = datetime.datetime.utcnow()
    expired = []

    for hostname, site in sites.items():
        site_dir = os.path.join(latest_cert_dir, hostname)
        if not os.path.isdir(site_dir):
            logger.info(f"site: {hostname} not found under output/archive")
            continue
        cert_bytes = None
        with open(os.path.join(site_dir, "cert1.pem"), "rb") as f:
            cert_bytes = f.read()
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        logger.info(f"subject: {cert.subject}, issuer: {cert.issuer}, "
                    f"expires: {cert.not_valid_after}, expire in days: {expire_in_days(cert.not_valid_after)}")
        if cert.not_valid_after < now:
            logger.warning(f"{hostname} cert expired")
            expired.append(hostname)

    if len(expired) > 0:
        click.echo(click.style(f"expired: {str(expired)}", fg='red'))


@click.command('site-yml', help='Fetch site.yml file from dashboard')
@click.pass_context
def _fetch_site_yml(ctx):
    fetch_site_yml(ctx.obj['config']['fetch_site_yml'], logger)


@click.command('decrypt-verify-cert', help='Decrypt and verify cert bundles')
@click.pass_context
def _decrypt_and_verify_cert_bundles(ctx):
    all_sites, timestamp = ctx.obj['get_all_sites']
    decrypt_and_verify_cert_bundles(all_sites, timestamp)


@click.command('gen-self-sign-certs', help='Generate a self sign cert')
@click.option('--name', '-n', required=True, help='Domain name for this cert')
@click.option('--alt-name', '-a', default=[], help='Alt name, seperate by comma')
@click.option('--output', '-o', default='.', help='Output path, default .')
@click.pass_context
def _gen_self_sign_certs(ctx, name, alt_name, output):
    alt_name_arr = alt_name.split(',')
    cert_pem, key_pem = generate_selfsigned_cert(name, alt_name_arr=alt_name_arr)

    with open(f"{output}/{name}.pem", "wb") as f:
        click.echo(f"Writing {output}/{name}.pem")
        f.write(cert_pem)
    with open(f"{output}/{name}.key", "wb") as f:
        click.echo(f"Writing {output}/{name}.key")
        f.write(key_pem)


@click.command('verify-cert', help='Verify input certs')
@click.option('--cert', '-c', required=True, help='Cert to verify')
@click.option('--decrypt', '-d', is_flag=True, default=False, help='Attempt to decrpyt it')
@click.pass_context
def _verify_cert(ctx, cert, decrypt):
    if decrypt:
        cert, cert_bytes = load_encrypted_cert(cert)
    else:
        cert_bytes = None
        with open(cert, "rb") as f:
            cert_bytes = f.read()
        cert = load_certificate(FILETYPE_PEM, cert_bytes)

    subject_names, alt_names = get_subject_and_alt_names(cert)
    click.echo(cert.get_subject().get_components())
    click.echo(f"subject: {subject_names}")
    click.echo(f"alt names: {alt_names}")
    click.echo(f"not_valid_after: {cert.get_notAfter()}")
    click.echo("X509StoreContext.verify_certificate()")
    store = X509Store()
    store_context = X509StoreContext(store, cert)
    store_context.verify_certificate()


def print_hosts_and_ctx(ctx):
    click.echo(f"\n* _has_controller = {ctx.obj['_has_controller']}")
    click.echo(f"* debug = {ctx.obj['debug']}")
    click.echo(f"* host = {ctx.obj['host']}")
    click.echo("* _hosts =")
    for host in ctx.obj['_hosts']:
        click.echo(f"  * {host['hostname']} ({host['ip']})")
    click.echo()


def run_remote_commands(config, hosts, command):
    for host in hosts:
        if host_to_role(config, host) == "controller":
            continue  # controller doesn't have banjax
        run_local_or_remote_noraise(config, host, command, logger)


# Generate section
gen.add_command(_gen_config)
gen.add_command(_gen_new_elastic_certs)

# Install section
install.add_command(_install_base)
install.add_command(_install_config)
install.add_command(_install_es)
install.add_command(_install_banjax)
install.add_command(_install_certbot)
install.add_command(_install_selected)
install.add_command(_install_legacy_filebeat)
install.add_command(_install_logrotate)
install.add_command(_install_kafka_filebeat)

# Get section
get.add_command(_get_nginx_errors)
get.add_command(_get_banjax_decision_lists)
get.add_command(_get_banjax_rate_limit_states)
get.add_command(_get_nginx_and_banjax_config_versions)
get.add_command(_fetch_site_yml)

# Util section
util.add_command(_info)
util.add_command(_test_es_auth)
util.add_command(_kill_all_containers)
util.add_command(_show_useful_curl_commands)
util.add_command(_commands)
util.add_command(_curl_gen)

# Certs section
certs.add_command(_check_cert_expiry)
certs.add_command(_decrypt_and_verify_cert_bundles)
certs.add_command(_gen_self_sign_certs)
certs.add_command(_verify_cert)

# Register sub-base
cli_base.add_command(gen)
cli_base.add_command(install)
cli_base.add_command(get)
cli_base.add_command(util)
cli_base.add_command(certs)


if __name__ == '__main__':
    cli_base()
