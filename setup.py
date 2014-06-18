# Copyright (c) 2014 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""
steelscript.wireshark
====================
Extract metrics from pcap files

"""
from setuptools import setup, find_packages
from gitpy_versioning import get_version

install_requires = (
    'steelscript.appfwk',
    'tzlocal',
)

setup_args = {
    'name':                'steelscript.wireshark',
    'namespace_packages':  ['steelscript'],
    'version':             get_version(),

    # Update the following as needed
    'author':              'Riverbed Technology',
    'author_email':        'eng-github@riverbed.com',
    'url':                 'http://pythonhosted.org/steelscript',
    'license':             'MIT',
    'description':         'Extract metrics from pcap files',

    'long_description': """SteelScript for Wireshark
=========================

SteelScript is a collection of libraries and scripts in Python and JavaScript for
interacting with Riverbed Technology devices.

For a complete guide to installation, see:

http://pythonhosted.org/steelscript/
    """,

    'packages': find_packages(exclude=('gitpy_versioning',)),
    'zip_safe': False,
    'install_requires': install_requires,
    'extras_require': None,
    'test_suite': '',
    'include_package_data': True,
    'entry_points': {
        # Uncomment these lines to enable steel commands for this module
        # 'steel.commands': [
        #     'wireshark = steelscript.wireshark.commands'
        # ],
        'portal.plugins': [
            'wireshark = steelscript.wireshark.appfwk.plugin:Plugin'
        ],
    },

    'classifiers': (
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Topic :: Software Development'
    ),
}

setup(**setup_args)
