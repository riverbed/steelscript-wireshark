#!/usr/bin/env python

# Copyright (c) 2015 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.


"""
This example script shows how to utilize the query mechanism to get
basic info about a pcap file.
"""

import os

from steelscript.common.app import Application
from steelscript.common.datautils import Formatter
from steelscript.wireshark.core.pcap import PcapFile


class PcapInfo(Application):

    def __init__(self, *args, **kwargs):
        super(PcapInfo, self).__init__(*args, **kwargs)

    def add_options(self, parser):
        super(PcapInfo, self).add_options(parser)
        self.add_standard_options(conn=False)
        parser.add_option('-f', '--pcap-path',
                          help='path to pcap file')
        parser.add_option('-c', '--columns',
                          help='Comma-separated list of Wireshark columns '
                               'to return. Defaults to a basic set of '
                               'frame time and data length per packet.',
                          default='frame.time_epoch,ip.len')
        parser.add_option('-m', '--max-rows', default=50,
                          help='Max number of rows to print out.  Defaults '
                               'to 50.')

    def validate_args(self):
        super(PcapInfo, self).validate_args()

        path = self.options.pcap_path

        if path is None or not os.path.exists(path):
            self.parser.error('Must pass absolute path to PCAP file.')

    def main(self):
        columns = self.options.columns.split(',')
        pcap = PcapFile(self.options.pcap_path)
        data = pcap.query(columns)

        data_out = data[:self.options.max_rows]

        Formatter.print_table(data_out, headers=columns)

if __name__ == '__main__':
    PcapInfo().run()
