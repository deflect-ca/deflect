# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
import logging
import shutil
import tarfile
import os
import traceback

import yaml
from jinja2 import Template
import ast

import dns
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.MX
import dns.rdtypes.ANY.SOA
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rdtypes.ANY.TXT
import dns.rdtypes.ANY.PTR
import dns.rdtypes.IN.SRV


# todo: use configuration for the logger
from pyaml_env import parse_config

from orchestration.helpers import get_logger, get_config_yml_path

logger = get_logger(__name__, logging_level=logging.DEBUG)

# XXX this doesn't look ok, TODO: fixme


def zone_block_root(domain, filename):
    return f"" + \
        f"zone \"{domain}\" {{\n" + \
        f"    type master;\n" + \
        f"    file \"{filename}\";\n" + \
        f"}};\n"


def zone_block_acme_challenge(domain):
    return f"" + \
        f"zone \"_acme-challenge.{domain}\" {{\n" + \
        f"    type forward;\n" + \
        f"    forward only;\n" + \
        f"    forwarders {{ 127.0.0.1 port 5053; }};\n" + \
        f"}};\n\n"


def main(config, all_sites, timestamp):
    """
    Create all the zone files
    """
    # TODO: extract methods wherever possible
    # XXX this scares me.
    # maybe don't delete old stuff and just move a symlink to point to the new one?
    output_dir = f"./output/{timestamp}/etc-bind"
    output_dir_tar = f"{output_dir}.tar"
    if len(output_dir) == 0:  # TODO: fixme did we mean to check for something else here?
        raise Exception("output_dir cannot be empty")
    if os.path.isdir(output_dir):
        logger.debug(f'Removing output dir: {output_dir}')
        # XXX making extra sure this is a local dir?
        shutil.rmtree(f"./{output_dir}")
    os.mkdir(output_dir)

    sites_dir = output_dir + "/deflect"
    os.mkdir(sites_dir)

    nameserver_hostname = f"ns1.{config['controller']['hostname']}"
    nameserver_admin = f"root.{config['controller']['hostname']}"  # XXX what's this actually called?

    named_conf_string = ""

    logger.debug(f'nameserver_hostname, nameserver_admin: '
                 f'{nameserver_hostname}, {nameserver_admin}')

    # XXX controller/nameserver is special-cased here kinda sloppily. fix it later.
    named_conf_string += zone_block_root(
            config['controller']['hostname'],
            f"/etc/bind/{config['controller']['hostname']}.zone"
    )

    logger.debug('Write controller zone')
    # XXX figure out if we want to do it the dnspython way or the template way
    with open("templates/controller.zone.j2", "r") as tf:
        template = Template(tf.read())
        with open(output_dir + "/" + config['controller']['hostname'] + ".zone", "w") as zf:
            zf.write(template.render(
                name=config['controller']['hostname'],
                ip=config['controller']['ip'],
            ))

    # TODO: I keep seeing this, why two kinds of sites?
    # meh
    client_and_system_sites = {**all_sites['client'], **all_sites['system']}

    for site_name, site in client_and_system_sites.items():
        try:
            logger.debug(f'Processing site_name, site: {site_name, site}')
            zone_filename = f"deflect/{site['public_domain']}.zone"
            zone_filename_2 = "/etc/bind/" + zone_filename  # XXX fixme
            named_conf_string += zone_block_root(
                site['public_domain'], zone_filename_2)
            # todo: function
            for server_name in set(site['server_names']):
                logger.debug(f'Processing server_name: {server_name}')
                named_conf_string += zone_block_acme_challenge(server_name)

            if not hasattr(dns, 'zone'):
                logger.debug(
                    'HACKY: Something is wrong here and dns doesn\'t have zone'
                )
                from dns.zone import Zone
            zone = dns.zone.Zone(origin=dns.name.from_text(site['public_domain']))
            origin_node = zone.find_node("@", create=True)

            logger.debug(f'find_rdataset: dns.rdataclass.IN')
            soa_rdataset = origin_node.find_rdataset(
                dns.rdataclass.IN,
                rdtype=dns.rdatatype.SOA,
                create=True
            )
            # XXX gosh, i dunno if it's worth using this complicated library for
            # something so simple. i guess it catches some mistakes, though?
            rd = dns.rdtypes.ANY.SOA.SOA(
                dns.rdataclass.IN,
                dns.rdatatype.SOA,
                mname=dns.name.from_text(nameserver_hostname),
                rname=dns.name.from_text(nameserver_admin),
                serial=0,
                refresh=300,
                retry=300,
                expire=1209600,
                minimum=300
            )
            soa_rdataset.add(rd, 300)

            logger.debug(f'find_rdataset: @ NS')
            ns_rdataset = zone.find_rdataset(
                "@",
                rdtype=dns.rdatatype.NS,
                create=True
            )
            rd = dns.rdtypes.ANY.NS.NS(
                dns.rdataclass.IN,
                dns.rdatatype.NS,
                dns.name.from_text(nameserver_hostname)
            )
            ns_rdataset.add(rd, 300)

            logger.debug(f'find_rdataset: _acme-challenge NS')
            ns_rdataset = zone.find_rdataset(
                "_acme-challenge",
                rdtype=dns.rdatatype.NS,
                create=True
            )
            rd = dns.rdtypes.ANY.NS.NS(
                dns.rdataclass.IN,
                dns.rdatatype.NS,
                dns.name.from_text(nameserver_hostname)
            )
            ns_rdataset.add(rd, 300)

            logger.debug(f'find_rdataset: @ A')
            # XXX @ and example.com????
            a_rdataset = zone.find_rdataset(
                "@",
                rdtype=dns.rdatatype.A,
                create=True
            )
            for edge in config['edges']:
                if edge['dnet'] == site['dnet']:
                    logger.debug(f'Edge name: {edge_name}')
                    edge_ip = config["edge_names_to_ips"][edge_name]
                    rd = dns.rdtypes.IN.A.A(
                        dns.rdataclass.IN, dns.rdatatype.A, edge_ip)
                    a_rdataset.add(rd, 300)

            # XXX TODO: improve
            for server_name in set(site["server_names"]) - set([site_name]):
                sub_zone = server_name.replace("." + site_name, "")
                logger.debug(f'find_rdataset: sub_zone {sub_zone}, A')
                a_rdataset = zone.find_rdataset(
                    sub_zone,
                    rdtype=dns.rdatatype.A,
                    create=True
                )
                for edge in config['edges']:
                    if edge['dnet'] == site['dnet']:
                        edge_ip = config["edge_names_to_ips"][edge_name]
                        rd = dns.rdtypes.IN.A.A(
                            dns.rdataclass.IN, dns.rdatatype.A, edge_ip)
                        a_rdataset.add(rd, 300)

                logger.debug(f'find_rdataset: _acme-challenge.{sub_zone} NS')
                # XXX duplication, very very gross
                ns_rdataset = zone.find_rdataset(
                    f"_acme-challenge.{sub_zone}",
                    rdtype=dns.rdatatype.NS,
                    create=True
                )
                rd = dns.rdtypes.ANY.NS.NS(
                    dns.rdataclass.IN,
                    dns.rdatatype.NS,
                    dns.name.from_text(nameserver_hostname)
                )
                ns_rdataset.add(rd, 300)

            for name, type_and_values in site['dns_records'].items():
                for type_and_value in type_and_values:
                    type_name = type_and_value['type']

                    rdtype = None
                    rdatatype = None
                    value = None
                    rdata = None

                    if type_name == "TXT":
                        rdtype = dns.rdtypes.ANY.TXT.TXT
                        rdatatype = dns.rdatatype.TXT
                        value = ast.literal_eval(type_and_value['value']).encode()
                        rdata = rdtype(dns.rdataclass.IN, rdatatype, strings=[value])

                    elif type_name == "A":
                        rdtype = dns.rdtypes.IN.A.A
                        rdatatype = dns.rdatatype.A
                        value = type_and_value['value']
                        rdata = rdtype(dns.rdataclass.IN, rdatatype, address=value)

                    elif type_name == "AAAA":
                        rdtype = dns.rdtypes.IN.AAAA.AAAA
                        rdatatype = dns.rdatatype.AAAA
                        value = type_and_value['value']
                        rdata = rdtype(dns.rdataclass.IN, rdatatype, address=value)

                    elif type_name == "MX":
                        rdtype = dns.rdtypes.ANY.MX.MX
                        rdatatype = dns.rdatatype.MX
                        preference = type_and_value['value'][0]
                        exchange = type_and_value['value'][1]
                        rdata = rdtype(dns.rdataclass.IN, rdatatype,
                                preference=preference, exchange=dns.name.from_text(exchange))

                    elif type_name == "CNAME":
                        rdtype = dns.rdtypes.ANY.CNAME.CNAME
                        rdatatype = dns.rdatatype.CNAME
                        value = type_and_value['value']
                        rdata = rdtype(dns.rdataclass.IN, rdatatype,
                                target=dns.name.from_text(value))

                    elif type_name == "SRV":
                        rdtype = dns.rdtypes.IN.SRV.SRV
                        rdatatype = dns.rdatatype.SRV
                        priority = type_and_value['value'][0]
                        weight = type_and_value['value'][1]
                        port = type_and_value['value'][2]
                        target = type_and_value['value'][3]
                        rdata = rdtype(dns.rdataclass.IN, rdatatype,
                                priority=priority, weight=weight, port=port,
                                target=dns.name.from_text(target))

                    elif type_name == "NS":
                        rdtype = dns.rdtypes.ANY.NS.NS
                        rdatatype = dns.rdatatype.NS
                        value = type_and_value['value']
                        rdata = rdtype(dns.rdataclass.IN, rdatatype,
                                target=dns.name.from_text(value))

                    else:
                        raise Exception(f"unsupported record type {type_name}")

                    rdataset = zone.find_rdataset(
                        name,
                        rdtype=rdatatype,
                        create=True
                    )

                    rdataset.add(rdata, ttl=300)

            zone_filename = output_dir + "/" + zone_filename
            logger.debug(f'Writing zone_filename {zone_filename}')
            zone.to_file(zone_filename, relativize=True)

        except AttributeError:
            traceback.print_exc()
            logger.error(F'Could not generate zone file for {site_name, site}.')

    with open(output_dir + "/named.conf.local", "w") as f:
        logger.debug(f'Writing named_conf_string')
        f.write(named_conf_string)

    if os.path.isfile(output_dir_tar):
        logger.debug(output_dir_tar)
        os.remove(output_dir_tar)

    logger.debug(f'Writing {output_dir_tar}')
    with tarfile.open(output_dir_tar, "x") as tar:
        tar.add(output_dir, arcname=".")


if __name__ == "__main__":
    from orchestration.shared import get_all_sites

    config = parse_config(get_config_yml_path())

    all_sites, formatted_time = get_all_sites()

    main(config, all_sites, formatted_time)
