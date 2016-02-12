#!/usr/bin/env python

# Copyright (c) 2015 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.


"""
This example script shows how to get basic details about a pcap file.
"""

import os

from steelscript.common.app import Application
from steelscript.common.datautils import Formatter
from steelscript.wireshark.core.pcap import PcapFile


class PcapInfo(Application):
    """Simple PCAP query application."""

    def add_positional_args(self):
        self.add_positional_arg('pcap_path', 'File path to pcap file')

    def validate_args(self):
        super(PcapInfo, self).validate_args()

        path = self.options.pcap_path

        if path is None or not os.path.exists(path):
            self.parser.error('Must pass absolute path to PCAP file.')

    def main(self):
        pcap = PcapFile(self.options.pcap_path)
        info = pcap.info()

        Formatter.print_table([(k, unicode(v, errors='replace')) for k, v
                               in info.iteritems()],
                              headers=['Key', 'Value'])

if __name__ == '__main__':
    PcapInfo().run()
