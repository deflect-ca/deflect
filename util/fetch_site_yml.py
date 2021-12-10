"""
Script to fetch site.yml from dashboard during roll-out

1. get clients.yml
2. Link clients.yml
3. copy /var/www/brainsconfig/tls_bundles/*.gpg to tls_bundles
4. check if clients.yml-revisions/clients.yml-last_used exists
5. copy current clients.yml to clients.yml-last_used if none

Ref: https://github.com/equalitie/autodeflect/blob/32bc3a3f7f3caac1b08ef94414f374ec0d1cf057/roles/dashpull/tasks/main.yml#L32
"""
import paramiko
import sys
import os
import errno

from scp import SCPClient
from os import path
from shutil import copyfile


def symlink_force(target, link_name):
    try:
        os.symlink(target, link_name)
    except OSError as e:
        if e.errno == errno.EEXIST:
            os.remove(link_name)
            os.symlink(target, link_name)
        else:
            raise e


def progress(filename, size, sent):
    sys.stdout.write("%s's progress: %.2f%%   \r" % (filename, float(sent)/float(size)*100) )


def fetch_site_yml(config, logger):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.load_system_host_keys()

    logger.debug(f"SSH Connection to {config['ssh']['host']}...")
    ssh.connect(hostname=config['ssh']['host'],
                username=config['ssh']['user'],
                port=config['ssh']['port'])

    # get dashdate
    # cmd: date +%Y%m%d%H%M%S
    stdin, stdout, stderr = ssh.exec_command('date +%Y%m%d%H%M%S')
    lines = stdout.readlines()
    dashdate = lines[0].replace('\n', '')
    logger.debug(f"dashdate: {dashdate}")

    logger.debug("Starting SCP client...")
    scp = SCPClient(ssh.get_transport(), progress=progress)

    # 1. Get clients.yml
    dst = f"{config['scp_dst']}/clients.yml-{dashdate}"
    logger.debug("scp {} to {}".format(config['scp_src'], dst))
    scp.get(config['scp_src'], dst)

    # 2. Sym link
    ln_src = dst
    ln_dst = f"{config['scp_dst']}/../old-sites.yml"
    logger.debug("ln {} to {}".format(ln_src, ln_dst))
    symlink_force(ln_src, ln_dst)

    # XXX: only copy the site TLS in client.yml
    # 3. TLS
    logger.debug("Get TLS bundles")
    scp.get(config['tls_src'], config['tls_dst'], recursive=True)

    logger.debug("Closing SCP and SSH client")
    scp.close()
    ssh.close()

    # 4. Mark last_used
    last_used = f"{config['scp_dst']}/clients.yml-last_used"
    if not path.exists(last_used):
        logger.debug("cp dst to last_used".format(dst, last_used))
        copyfile(dst, last_used)
