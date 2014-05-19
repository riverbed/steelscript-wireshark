# Copyright (c) 2014 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

import pkg_resources

from steelscript.appfwk.apps.plugins import Plugin as AppsPlugin


class Plugin(AppsPlugin):
    title = 'Wireshark plugin'
    description = 'Extract metrics from pcap files'
    version = pkg_resources.get_distribution('steelscript.wireshark').version
    author = 'Christopher J. White'

    enabled = True
    can_disable = True

    devices = ['devices']
    datasources = ['datasources']
    reports = ['reports']
