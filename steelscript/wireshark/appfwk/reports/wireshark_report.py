# Copyright (c) 2014 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""
This file defines a single report of multiple tables and widgets.

The typical structure is as follows:

    report = Report.create('Wireshark Report')
    report.add_section()

    table = SomeTable.create(name, table_options...)
    table.add_column(name, column_options...)
    table.add_column(name, column_options...)
    table.add_column(name, column_options...)

    report.add_widget(yui3.TimeSeriesWidget, table, name, width=12)

See the documeantion or sample plugin for more details
"""

from steelscript.appfwk.apps.report.models import Report, Section
from steelscript.appfwk.apps.datasource.models import Column

import steelscript.appfwk.apps.report.modules.yui3 as yui3

from steelscript.wireshark.appfwk.datasources.wireshark_source \
    import WiresharkColumn, WiresharkTable, WiresharkInfoTable

######################################################################
#
# PCAP analysis
#

report = Report(title="PCAP Analysis", position=1)
report.save()

report.add_section()

#
# Table: Pcap info
#

table = WiresharkInfoTable.create('pcap-info')

table.add_column('Attribute', datatype='string', iskey=True)
table.add_column('Value', datatype='string')

report.add_widget(yui3.TableWidget, table, 'PCAP Info', width=12, height=200)

#
# Table: Process Pcap files
#

table = WiresharkTable.create('pcap', resample=True,
                              resolution='1m', resolutions=['1s','1m'])

table.add_column('pkttime', datatype=Column.DATATYPE_TIME, iskey=True,
                 field='frame.time_epoch')
table.add_column('iplen', field='ip.len')

table.add_column('iplen-bits', synthetic=True,
                 compute_expression='8*{iplen}',
                 resample_operation='sum')
table.add_column('max-iplen', synthetic=True,
                 compute_expression='{iplen}',
                 resample_operation='max')
table.add_column('min-iplen', synthetic=True,
                 compute_expression='{iplen}',
                 resample_operation='min')
table.add_column('limit_100', synthetic=True,
                 compute_expression='100',
                 resample_operation='min')

# Compute 95th percentile
table.add_column('iplen_95', synthetic=True, label="95%",
                 compute_expression='{iplen}.quantile(0.95)',
                 compute_post_resample=True)

# Compute 80th percentile
table.add_column('iplen_80', synthetic=True, label="80%",
                 compute_expression='{iplen}.quantile(0.80)',
                 compute_post_resample=True)

# Compute rolling average (EWMA algo)
table.add_column('iplen_ewma', synthetic=True, label="Moving Avg",
                 compute_expression='pandas.stats.moments.ewma({iplen}, span=20)',
                 compute_post_resample=True)


report.add_widget(yui3.TimeSeriesWidget, table, "IP Bytes over Time",
                  width=12, height=400,
                  cols=['iplen', 'iplen_95', 'iplen_80', 'iplen_ewma'])
