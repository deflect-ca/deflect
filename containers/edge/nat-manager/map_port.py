# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import iptc
import pprint
import argparse
import sys
import aiohttp
from aiohttp import web
import asyncio

# iptables -t nat -I OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 8000
# docker run 127.0.0.1:8000:8080 <image v1>
# # time passes
# docker run 127.0.0.1:8001:8080 <image v2>
# iptables -t nat -I OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 8001
# iptables -t nat -D OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 8000 # delete old rule. existing connections aren't interrupted
# # nginx can expose an "active connections" metric, so wait for that to go to zero
# docker stop <container v1>


def print_nat_chains_and_rules():
    pprint.pprint(iptc.easy.dump_table('nat', ipv6=False))

def redirect_public_to_private_port_rule(public_port, private_port):
    return {
            'protocol': 'tcp',
            'tcp': {
                'dport': str(public_port)
            },
            'target': {
                'REDIRECT': {
                    'to-ports': str(private_port)
                }
            },
            'addrtype': {'dst-type': 'LOCAL'}  # XXX is this right?
    }

# these names...
def redirect_loopback_rule(public_port, private_port):
    return {
            'protocol': 'tcp',
            'tcp': {
                'dport': str(public_port)
            },
            'out-interface': 'lo',
            'target': {
                'REDIRECT': {
                    'to-ports': str(private_port)
                }
            },
            'addrtype': {'dst-type': 'LOCAL'}  # XXX is this right?
    }

def insert_new_redirect_rule(chain, rule):
    iptc.easy.insert_rule('nat', chain, rule)

def insert_new_redirect_rules(public_port, private_port):
    new_rule1 = redirect_public_to_private_port_rule(public_port, private_port)
    insert_new_redirect_rule('PREROUTING', new_rule1)

    new_rule2 = redirect_loopback_rule(public_port, private_port)
    insert_new_redirect_rule('OUTPUT', new_rule2)

def remove_old_redirect_rule(chain, rule):
    while True:
        try:
            iptc.easy.delete_rule('nat', chain, rule)
        except iptc.ip4tc.IPTCError:
            print("no more matching rules")
            break
        else:
            print("deleted an old rule")

def remove_old_redirect_rules(public_port, private_port):
    old_rule1 = redirect_public_to_private_port_rule(public_port, private_port)
    remove_old_redirect_rule('PREROUTING', old_rule1)

    old_rule2 = redirect_loopback_rule(public_port, private_port)
    remove_old_redirect_rule('OUTPUT', old_rule2)

async def handle(request):
    return web.Response(text="hello")

async def self_test():
    app = web.Application()
    app.add_routes([web.get('/', handle)])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 6969)
    await site.start()

    timeout = aiohttp.ClientTimeout(total=5)  # 5 seconds

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get('http://localhost:69') as resp:
                print(resp.status)
    except aiohttp.ClientConnectorError:
        print("could not connect to external port before doing the NAT. this is good and expected")
    else:
        print("ERROR! we should not have been able to connect to the external port before doing the NAT")

    print("$$$$$$$$$$$ BEFORE NAT $$$$$$$$$$$$$$$$")
    print_nat_chains_and_rules()

    loopback_rule = redirect_loopback_rule(69, 6969)
    insert_new_redirect_rule('OUTPUT', loopback_rule)

    print("$$$$$$$$$$$ AFTER NAT $$$$$$$$$$$$$$$$")
    print_nat_chains_and_rules()

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get('http://localhost:69') as resp:
                print(resp.status)
    except aiohttp.ClientConnectorError:
        print("ERROR! the NAT didn't work. bad.")
    else:
        print("the NAT worked. good.")

    remove_old_redirect_rule('OUTPUT', loopback_rule)

    print("$$$$$$$$$$$ AFTER REMOVING NAT $$$$$$$$$$$$$$$$")
    print_nat_chains_and_rules()

    await runner.cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-port", dest='public_port', type=int, required=True)
    parser.add_argument("--add-private-port", dest='add_private_port', type=int)
    parser.add_argument("--remove-private-port", dest='remove_private_port', type=int)
    args, unknown_args = parser.parse_known_args()

    if (args.add_private_port is None) and (args.remove_private_port is None):
        print("need one or both of --add-private-port or --remove-private-port")
        sys.exit(-1)

    # loop = asyncio.get_event_loop()
    # loop.run_until_complete(self_test())
    print(args)

    # print("BEFORE")
    # print_nat_chains_and_rules()

    if args.add_private_port is not None:
        insert_new_redirect_rules(args.public_port, args.add_private_port)

    if args.remove_private_port is not None:
        remove_old_redirect_rules(args.public_port, args.remove_private_port)

    # print("AFTER")
    # print_nat_chains_and_rules()
