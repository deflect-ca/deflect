# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.


from __future__ import absolute_import
from setuptools import setup

# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# README as the long description
with open(path.join(here, 'orchestration/README.md'), encoding='utf-8') as f:
    long_description = f.read()

REQUIREMENTS = [i.strip() for i in open('requirements.txt').readlines()]
tests_require = [
    'pytest',
    'mock',
]

setup(name='deflect',
      version='0.0.1',
      description='Provides the orchestration functionality for Deflect-next',
      long_description=long_description,
      tests_require=tests_require,
      extras_require={
          'test': tests_require,
      },
      test_suite='pytest.collector',
      install_requires=REQUIREMENTS,
      include_package_data=True,
      package_dir={'': '.'},
      packages=[
          'orchestration',
          'config_generation',
          'util',
      ],
      entry_points='''
        [console_scripts]
        deflect=main:cli_base
    ''',
      )
