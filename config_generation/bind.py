# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
import logging
import shutil
import tarfile
import os

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

from util.helpers import get_logger, get_config_yml_path, path_to_input, path_to_output

logger = get_logger(__name__, logging_level=logging.DEBUG)


def rdata_and_type_for_txt(value):
    rdtype = dns.rdtypes.ANY.TXT.TXT
    rdatatype = dns.rdatatype.TXT
    if len(value) > 250:
        rdata = rdtype(dns.rdataclass.IN, rdatatype, strings=(value[:250], value[250:]))
    else:
        rdata = rdtype(dns.rdataclass.IN, rdatatype, strings=(value,))
    return rdata, rdatatype


def rdata_and_type_for_a(value):
    rdtype = dns.rdtypes.IN.A.A
    rdatatype = dns.rdatatype.A
    rdata = rdtype(dns.rdataclass.IN, rdatatype, address=value)
    return rdata, rdatatype


def rdata_and_type_for_aaaa(value):
    rdtype = dns.rdtypes.IN.AAAA.AAAA
    rdatatype = dns.rdatatype.AAAA
    rdata = rdtype(dns.rdataclass.IN, rdatatype, address=value)
    return rdata, rdatatype


def rdata_and_type_for_mx(value):
    rdtype = dns.rdtypes.ANY.MX.MX
    rdatatype = dns.rdatatype.MX
    preference = value[0]
    exchange = value[1]
    rdata = rdtype(
            dns.rdataclass.IN,
            rdatatype,
            preference=preference,
            exchange=dns.name.from_text(exchange)
    )
    return rdata, rdatatype


def rdata_and_type_for_cname(value):
    rdtype = dns.rdtypes.ANY.CNAME.CNAME
    rdatatype = dns.rdatatype.CNAME
    rdata = rdtype(dns.rdataclass.IN, rdatatype, target=dns.name.from_text(value))
    return rdata, rdatatype


def rdata_and_type_for_srv(value):
    rdtype = dns.rdtypes.IN.SRV.SRV
    rdatatype = dns.rdatatype.SRV
    priority = value[0]
    weight = value[1]
    port = value[2]
    target = value[3]
    rdata = rdtype(
        dns.rdataclass.IN,
        rdatatype,
        priority=priority,
        weight=weight,
        port=port,
        target=dns.name.from_text(target)
    )
    return rdata, rdatatype


def rdata_and_type_for_ns(value):
    rdtype = dns.rdtypes.ANY.NS.NS
    rdatatype = dns.rdatatype.NS
    rdata = rdtype(
        dns.rdataclass.IN,
        rdatatype,
        target=dns.name.from_text(value)
    )
    return rdata, rdatatype


def rdata_and_type_for_record(type, value):
    # the literal_eval is something to do with long values showing up as
    # adjacent strings "like" "this"
    if type == "TXT":
        return rdata_and_type_for_txt(ast.literal_eval(value).encode())
    elif type == "A":
        return rdata_and_type_for_a(value)
    elif type == "AAAA":
        return rdata_and_type_for_aaaa(value)
    elif type == "MX":
        return rdata_and_type_for_mx(value)
    elif type == "CNAME":
        return rdata_and_type_for_cname(value)
    elif type == "SRV":
        return rdata_and_type_for_srv(value)
    elif type == "NS":
        return rdata_and_type_for_ns(value)
    else:
        raise Exception(f"unsupported record type {type}")


def rdataset_for_soa(origin_node):
    return origin_node.find_rdataset(
        dns.rdataclass.IN,
        rdtype=dns.rdatatype.SOA,
        create=True
    )


def rdata_for_soa(mname, rname, serial, refresh, retry, expire, minimum):
    return dns.rdtypes.ANY.SOA.SOA(
        dns.rdataclass.IN,
        dns.rdatatype.SOA,
        mname=dns.name.from_text(mname),
        rname=dns.name.from_text(rname),
        serial=serial,
        refresh=refresh,
        retry=retry,
        expire=expire,
        minimum=minimum
    )


def rdataset_for_sub_zone_and_rdatatype(zone, sub_zone, rdatatype):
    return zone.find_rdataset(
        sub_zone,
        rdtype=rdatatype,
        create=True
    )


def add_record_rel(zone, site_name, sub_zone, type, value):
    rel_zone = relativize_name(site_name, sub_zone)
    add_record_norel(zone, rel_zone, type, value)


def add_record_norel(zone, sub_zone, type, value):
    rdata, rdatatype = rdata_and_type_for_record(type, value)
    rdataset = rdataset_for_sub_zone_and_rdatatype(zone, sub_zone, rdatatype)
    rdataset.add(rdata, ttl=300)


def add_soa(zone, mname, rname, serial, refresh, retry, expire, minimum):
    origin_node = zone.find_node("@", create=True)

    soa_rdataset = rdataset_for_soa(origin_node)
    rdata = rdata_for_soa(
            mname=mname,
            rname=rname,
            serial=serial,
            refresh=refresh,
            retry=retry,
            expire=expire,
            minimum=minimum
    )
    soa_rdataset.add(rdata, 300)


def site_to_zone(config, site_name, site):
    zone = dns.zone.Zone(origin=dns.name.from_text(site['public_domain']))

    ns_host = f"ns1.{config['system_root_zone']}"
    ns_admin = f"root.{config['system_root_zone']}"  # XXX what's this actually called?

    add_soa(
        zone,
        mname=ns_host,
        rname=ns_admin,
        serial=0,
        refresh=300,
        retry=300,
        expire=1209600,
        minimum=300
    )

    # the @ NS record (XXX could/should be more than one)
    add_record_rel(zone, site_name, site_name, "NS", ns_host)

    for alt_name in sorted(set(site["server_names"])):
        # this somehow lets bind9 forward these requests to certbot's dns-helper
        add_record_rel(zone, site_name, f"_acme-challenge.{alt_name}", "NS", ns_host)

        # it's a bit kludgy, but we say the controller is part of dnet "controller"
        # so we can specify that kibana, elasticsearch, and doh-proxy live there.
        for edge in [config['controller']] + config['edges']:
            if edge['dnet'] == site['dnet']:
                add_record_rel(zone, site_name, alt_name, "A", edge['ip'])

    for rel_zone, type_and_values in site['dns_records'].items():
        for type_and_value in type_and_values:
            add_record_norel(zone, rel_zone, type_and_value['type'], type_and_value['value'])

    return zone


def get_output_filename(sites_dir, name):
    return os.path.join(sites_dir, f"{name}.zone")


def get_etc_bind_filename(name):
    return os.path.join("/etc/bind/deflect", f"{name}.zone")


def template_named_conf(config, client_and_system_sites):
    named_conf_string = ""
    named_conf_string += zone_block_root(
            config['system_root_zone'],
    )
    for site in sorted(client_and_system_sites.values(), key=lambda s: s['public_domain']):
        named_conf_string += zone_block_root(site['public_domain'])
        for server_name in sorted(set(site['server_names'])):
            named_conf_string += zone_block_acme_challenge(server_name)

    return named_conf_string


def template_controller_zone(in_filename, out_filename, config):
    with open(in_filename, "r") as tf:
        template = Template(tf.read())
        with open(out_filename, "w") as zf:
            zf.write(template.render(
                name=config['system_root_zone'],
                ip=config['controller']['ip'],
            ))


# "example.com" -> "@"
# "www.example.com" -> "www"
def relativize_name(canonical_name, alt_name):
    if alt_name == canonical_name:
        return "@"
    else:
        return alt_name.replace("." + canonical_name, "")


def zone_block_root(domain):
    filename = get_etc_bind_filename(domain)
    template = Template("""
zone "{{domain}}" {
    type master;
    file "{{filename}}";
};
    """)
    return template.render(domain=domain, filename=filename)


def zone_block_acme_challenge(domain):
    template = Template("""
zone "_acme-challenge.{{domain}}" {
    type forward;
    forward only;
    forwarders { 127.0.0.1 port 5053; };
};
    """)
    return template.render(domain=domain)


def generate_bind_config(config, all_sites, timestamp):
    """
    Create all the zone files
    """
    if not hasattr(dns, 'zone'):
        logger.debug(
            'HACKY: Something is wrong here and dns doesn\'t have zone'
        )
        from dns.zone import Zone

    output_dir = f"{path_to_output()}/{timestamp}/etc-bind"
    output_dir_tar = f"{output_dir}.tar"
    if len(output_dir) == 0:  # TODO: fixme did we mean to check for something else here?
        raise Exception("output_dir cannot be empty")
    if os.path.isdir(output_dir):
        logger.debug(f'Removing output dir: {output_dir}')
        # XXX making extra sure this is a local dir?
        shutil.rmtree(f"{output_dir}")
    os.mkdir(output_dir)
    sites_dir = os.path.join(output_dir, "deflect")
    os.mkdir(sites_dir)

    # XXX fix this pattern
    client_and_system_sites = {**all_sites['client'], **all_sites['system']}

    # this config file points at all the zone files
    named_conf = template_named_conf(config, client_and_system_sites)
    with open(os.path.join(output_dir, "named.conf.local"), "w") as f:
        f.write(named_conf)

    # XXX using a jinja template here, but using dnspython for everything else
    in_filename = f"{path_to_input()}/templates/controller.zone.j2"
    out_filename = get_output_filename(sites_dir, config['system_root_zone'])
    template_controller_zone(in_filename, out_filename, config)

    # write out a zone file for each site
    for site_name, site in client_and_system_sites.items():
        zone = site_to_zone(config, site_name, site)
        zone.to_file(get_output_filename(sites_dir, site_name), relativize=True, sorted=True)

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

    generate_bind_config(config, all_sites, formatted_time)
