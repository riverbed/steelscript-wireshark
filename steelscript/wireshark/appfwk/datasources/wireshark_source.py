# Copyright (c) 2014 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""
A data source for querying data from pcap files via tshark
"""

import logging
import threading
import subprocess
import shlex
import os

import pandas

from django.forms.widgets import FileInput

from steelscript.appfwk.apps.datasource.models \
    import DatasourceTable, TableField, Column, TableQueryBase
from steelscript.appfwk.apps.datasource.forms \
    import FileSelectField, fields_add_resolution

import local_settings

logger = logging.getLogger(__name__)
lock = threading.Lock()


class WiresharkColumn(Column):
    class Meta:
        proxy = True

    COLUMN_OPTIONS = {'field': None,
                      'fieldtype': 'string',  # float, int, time
                      'operation': 'sum'}
    #_required = ['field']


def fields_add_pcapfile(obj, keyword='pcapfile', initial=None):
    field = TableField(keyword='pcapfile',
                       label='PCAP File',
                       field_cls=FileSelectField,
                       field_kwargs={'widget': FileInput})
    field.save()
    obj.fields.add(field)


def fields_add_filterexpr(obj,
                          keyword='wireshark_filterexpr',
                          initial=None
                          ):
    field = (TableField
             (keyword = keyword,
              label = 'WireShark Filter Expression',
              help_text = ('Traffic expression using WireShark Display '
                           'Filter syntax'),
              initial = initial,
              required = False))
    field.save()
    obj.fields.add(field)

class WiresharkTable(DatasourceTable):

    class Meta:
        proxy = True

    # When a custom column is used, it must be linked
    _column_class = 'WiresharkColumn'
    _query_class = 'WiresharkQuery'

    TABLE_OPTIONS = { }
    FIELD_OPTIONS = { 'resolution': '1m',
                      'resolutions': ('1s', '1m', '15min', '1h') }

    def post_process_table(self, field_options):
        #
        # Add criteria fields that are required by this table
        #
        fields_add_resolution(obj=self,
                              initial=field_options['resolution'],
                              resolutions=field_options['resolutions'])
        fields_add_pcapfile(obj=self)
        fields_add_filterexpr(obj=self)


def tofloat(x):
    try:
        return float(x)
    except:
        return 0


def toint(x):
    try:
        return int(x)
    except:
        return 0


def totimeint(s):
    (a, b) = s.split(".")
    return int(a) * 1000000000 + int(b)


class WiresharkQuery(TableQueryBase):

    def run(self):
        table = self.table
        columns = table.get_columns(synthetic=False)

        pcapfile = self.job.criteria.pcapfile

        if not pcapfile:
            raise ValueError("No pcap file specified")
        elif not os.path.exists(pcapfile):
            raise ValueError("No such file: %s" % pcapfile)


        if not hasattr(local_settings, 'TSHARK_PATH'):
            raise ValueError('Please set local_settings.TSHARK_PATH '
                             'to the proper path to the tshark executable')

        command = ('{tshark} -r {pcap} -T fields -E occurrence=f -E separator=,'
                   .format(tshark=local_settings.TSHARK_PATH,
                           pcap=pcapfile))
        filterexpr = self.job.criteria.wireshark_filterexpr
        if filterexpr not in ('', None):
            command = command + (" -R '%s'" % filterexpr)

        keys = []
        basecolnames = []  # list of colummns
        # dict by field name of the base (or first) column to use this field
        fields = {}
        ops = {}
        for tc in columns:
            tc_options = tc.options
            if tc_options.field in fields.keys():
                # Asking for the same field name twice doesn't work, but
                # is useful when aggregating and choosing a different operation
                # like "min", or "max".  Will populate these columns later
                continue
            command = command + (" -e %s" % tc_options.field)
            fields[tc_options.field] = tc.name
            basecolnames.append(tc.name)
            if tc.iskey:
                keys.append(tc.name)
            else:
                ops[tc.name] = tc_options.operation

        msg = "tshark command: %s" % command
        #print msg
        logger.debug(msg)
        proc = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE)

        data = []
        while proc.poll() is None:
            line = proc.stdout.readline().rstrip()
            if not line:
                continue
            cols = line.split(',')
            if len(cols) != len(basecolnames):
                logger.error("Could not parse line: %s" % line)
                continue
            data.append(cols)

        df = pandas.DataFrame(data, columns=basecolnames)
        # At this point we have a dataframe with the one column for each
        # unique field (the first column to reference the field)

        if table.rows > 0:
            df = df[:table.rows]

        logger.info("Data returned (first 3 rows...):\n%s", df[:3])

        # Convert the data into the right format
        for tc in columns:
            if tc.name not in basecolnames:
                continue
            tc_options = tc.options
            if tc_options.fieldtype == "float":
                df[tc.name] = df[tc.name].map(tofloat)
            elif tc_options.fieldtype == "int":
                df[tc.name] = df[tc.name].map(toint)
            elif tc.datatype == "time":
                df[tc.name] = pandas.DatetimeIndex(df[tc.name].map(totimeint))

        colnames = [col.name for col in columns]
        self.data = df.ix[:,colnames].values.tolist()

        return True
