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
    """Simple PCAP Info application."""

    def add_positional_args(self):
        self.add_positional_arg('pcap_path', 'File path to pcap file')

    def add_options(self, parser):
        super(PcapInfo, self).add_options(parser)
        parser.add_option('-c', '--columns',
                          help='Comma-separated list of Wireshark columns '
                               'to return. Defaults to a basic set of '
                               'frame time and data length per packet.',
                          default='frame.time_epoch,ip.len')
        parser.add_option('-m', '--max-rows', default=50,
                          help='Max number of rows to print out.  Defaults '
                               'to 50.')
        parser.add_option('-j', '--join', dest='join', default='FULL',
                          help='The type of join to be used to construct the '
                               'table. Possible values: FULL, INNER')

    def validate_args(self):
        super(PcapInfo, self).validate_args()

        path = self.options.pcap_path
        join = self.options.join

        if path is None or not os.path.exists(path):
            self.parser.error('Must pass absolute path to PCAP file.')
        if join is not None and join not in ['FULL', 'INNER']:
            self.parser.error('Join must be either FULL or INNER.')

    def main(self):
        columns = self.options.columns.split(',')
        pcap = PcapFile(self.options.pcap_path)
        data = pcap.query(columns)

        if self.options.join == 'INNER':
            data = [row for row in data if None not in row]

        if not data:
            print('No rows found matching your input')

        max_rows = int(self.options.max_rows)
        data_out = data[:max_rows]

        Formatter.print_table(data_out, headers=columns)

if __name__ == '__main__':
    PcapInfo().run()
