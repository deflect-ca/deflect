# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.


import logging
import shutil
import glob
import os
import tarfile

# todo: use configuration for the logger
from pyaml_env import parse_config

from orchestration.helpers import get_logger

logger = get_logger(__name__, logging_level=logging.DEBUG)

# XXX filenames might have these numbers appended: banjax-next.test.me.uk-0001

# this is just for the LE certs (most from autodeflect, and some from deflect-next).
# deflect-next does its own decryption for the uploaded bundles.


def main(formatted_time):
    autodeflect_certs_dir = "/opt/deflect/modules/autodeflect/certs/letsencrypt/"
    local_certs_dir = f"input/certs/{formatted_time}/"

    if os.path.isdir(local_certs_dir):
        print(f"removing existing local_certs_dir: {local_certs_dir}")
        shutil.rmtree(f"./{local_certs_dir}")  # XXX danger if unset?
    os.mkdir(local_certs_dir)

    # copy from /opt/deflect/modules/autodeflect/certs/letsencrypt/*
    ssl_dir = "/opt/deflect/edges/dnet1/usr/local/trafficserver/conf/ssl/"

    for cert in glob.glob(f"{ssl_dir}/*.crt"):
        shutil.copy(cert, local_certs_dir)

    for key in glob.glob(f"{ssl_dir}/*.key"):
        shutil.copy(key, local_certs_dir)

    for cert in glob.glob(f"{autodeflect_certs_dir}/*.crt"):
        shutil.copy(cert, local_certs_dir)

    for cert in glob.glob(f"{autodeflect_certs_dir}/non-auto/*.crt"):
        shutil.copy(cert, local_certs_dir)

    for key in glob.glob(f"{autodeflect_certs_dir}/*.key"):
        shutil.copy(key, local_certs_dir)

    for key in glob.glob(f"{autodeflect_certs_dir}/non-auto/*.key"):
        shutil.copy(key, local_certs_dir)


    # autodeflect certs: make fullchain if it doesn't exist

    # XXX re-think
    # TODO: @joe: 2021-06-29_09:19:33 is this a previous formatted time?
    prev_dirs_to_check = [
        f"{local_certs_dir}/*.cert.crt",
        "output/2021-06-29_09:19:33/archive/*"
    ]
    for prev_dir_to_check in prev_dirs_to_check:
        in_certs = glob.glob(prev_dir_to_check)
        print(f"previous run dir: {prev_dir_to_check}")

        for in_cert in in_certs:
            if not os.path.isfile(in_cert):
                continue

            in_chain = in_cert.replace(".cert.crt", ".chain.crt")

            cert = ""
            chain = ""

            with open(in_cert, "r") as f:
                cert = f.read()
            with open(in_chain, "r") as f:
                chain = f.read()

            out_fullchain = local_certs_dir + in_cert.split("/")[-1].replace(
                ".cert.crt", ".fullchain.crt"
            )
            if os.path.isfile(out_fullchain):
                print(
                    f"not overwriting existing fullchain for {out_fullchain}"
                )
                continue
            with open(out_fullchain, "w") as f:
                f.write(cert + chain)

            # XXX omg figure out wtf this is
            if "non-auto-le" in in_cert:
                in_key = in_cert.replace(".cert.crt", ".key")
                os.rename(in_key,        in_key.replace("non-auto-", ""))
                os.rename(in_cert,       in_cert.replace("non-auto-", ""))
                os.rename(in_chain,      in_chain.replace("non-auto-", ""))
                os.rename(out_fullchain, out_fullchain.replace("non-auto-", ""))


    # deflect-next certs: convert to the autodeflect format if necessary

    # TODO: refactor
    previous_run_dir = sorted(glob.glob("output/*"))[-2]
    print(f"previous run dir: {previous_run_dir}")
    in_dirs = glob.glob(f"{previous_run_dir}/archive/*")

    for in_dir in in_dirs:
        # XXX oh god
        if not os.path.isdir(in_dir):
            continue

        domain = in_dir.split("/")[-1]
        if os.path.isfile(f"{local_certs_dir}/{domain}.le.fullchain.crt"):
            print(f"not overwriting existing cert for {domain}")
            continue

        print(f"using LE cert from deflect-next for {domain}")

        with open(f"{local_certs_dir}/{domain}.le.fullchain.crt", "w") as f1:
            with open(f"{in_dir}/fullchain1.pem", "r") as f2:
                f1.write(f2.read())

        with open(f"{local_certs_dir}/{domain}.le.key", "w") as f1:
            with open(f"{in_dir}/privkey1.pem", "r") as f2:
                f1.write(f2.read())

    if os.path.isfile(f"input/certs/{formatted_time}.tar"):
        print(f"removing existing TODAY-certs.tar: input/certs/{formatted_time}.tar")
        os.remove(f"input/certs/{formatted_time}.tar")

    with tarfile.open(f"input/certs/{formatted_time}.tar", "x") as tar:
        tar.add(local_certs_dir, arcname="archive")


if __name__ == "__main__":
    from orchestration.shared import get_all_sites

    config = parse_config('input/current/config.yml')

    all_sites, formatted_time = get_all_sites()

    main(formatted_time)
