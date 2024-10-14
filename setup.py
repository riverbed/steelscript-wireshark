# Copyright (c) 2019-2024 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""
steelscript.wireshark
====================
Extract metrics from pcap files

"""
from glob import glob
from setuptools import setup, find_packages

setup_args = {
    'name':                'steelscript.wireshark',
    'version':             '24.10.1',
    'author':              'Riverbed Technology',
    'author_email':        'eng-github@riverbed.com',
    'url':                 'http://pythonhosted.org/steelscript',
    'license':             'MIT',
    'description':         'Extract metrics from pcap files',

    'long_description': """SteelScript for Wireshark
=========================

SteelScript is a collection of libraries and scripts in Python and JavaScript
for interacting with Riverbed Technology devices.

For a complete guide to installation, see:

http://pythonhosted.org/steelscript/
    """,

    'packages': find_packages(exclude=('gitpy_versioning',)),
    'zip_safe': False,

    'install_requires': (
        'steelscript>=24.2.0',
        'python-dateutil',
        'tzlocal',
    ),

    'extras_require': None,
    'test_suite': '',
    'include_package_data': True,

    'entry_points': {
        'portal.plugins': [
            'wireshark = steelscript.wireshark.appfwk.plugin:Plugin'
        ],
    },

    'data_files': (
        ('share/doc/steelscript/docs/wireshark', glob('docs/*')),
        ('share/doc/steelscript/examples/wireshark', glob('examples/*')),
    ),

    'python_requires': '>3.9.0',

    'classifiers': [
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.12',
        'Topic :: Software Development',
        'Topic :: System :: Networking',
    ],
}

setup(**setup_args)
