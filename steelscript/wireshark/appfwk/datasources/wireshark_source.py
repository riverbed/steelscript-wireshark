# Copyright (c) 2014 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""
A data source for querying data from pcap files via tshark
"""

import logging
import os

import pandas

from django.forms.widgets import FileInput
from django import forms
from django.conf import settings

from steelscript.wireshark.core.pcap import PcapFile

from steelscript.appfwk.apps.datasource.models \
    import DatasourceTable, TableField, Column, TableQueryBase
from steelscript.appfwk.apps.datasource.forms \
    import FileSelectField, fields_add_resolution, fields_add_time_selection

logger = logging.getLogger(__name__)


class WiresharkColumn(Column):
    class Meta:
        proxy = True

    COLUMN_OPTIONS = {'field': None,
                      'operation': 'sum'}
    #_required = ['field']


def fields_add_pcapfile(obj, keyword='pcapfilename',
                        label='PCAP File', initial=None,
                        astextfield=False):
    """Add a PCAP file selection field.

    :param bool astextfield: If True, use a text field instead of a
        file selection field.  The text value is interpreted as
        a file on the server.

    """

    kwargs = {}
    if not astextfield:
        kwargs['field_cls'] = FileSelectField
        kwargs['field_kwargs'] = {'widget': FileInput}

    field = TableField(keyword=keyword,
                       label=label,
                       **kwargs)
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

    TABLE_OPTIONS = {}
    FIELD_OPTIONS = {'resolution': '1m',
                     'resolutions': ('1s', '1m', '15min', '1h'),
                     'pcapfile_astextfield': False}

    def post_process_table(self, field_options):
        #
        # Add criteria fields that are required by this table
        #
        TableField.create(keyword='entire_pcap', obj=self,
                          field_cls=forms.BooleanField,
                          label='Entire PCAP',
                          initial=True,
                          required=False)

        fields_add_time_selection(self, show_start=True, show_end=True,
                                  show_duration=False)
        fields_add_resolution(obj=self,
                              initial=field_options['resolution'],
                              resolutions=field_options['resolutions'])
        fields_add_pcapfile(
            obj=self, astextfield=field_options['pcapfile_astextfield'])
        fields_add_filterexpr(obj=self)


class WiresharkQuery(TableQueryBase):

    def run(self):
        criteria = self.job.criteria
        table = self.table
        columns = table.get_columns(synthetic=False)

        pcapfilename = criteria.pcapfilename

        if not pcapfilename:
            raise ValueError("No pcap file specified")
        elif not os.path.exists(pcapfilename):
            raise ValueError("No such file: %s" % pcapfilename)

        if not hasattr(settings, 'TSHARK_PATH'):
            raise ValueError('Please set local_settings.TSHARK_PATH '
                             'to the proper path to the tshark executable')

        pcapfile = PcapFile(pcapfilename)

        fieldnames = []
        basecolnames = []  # list of colummns
        # dict by field name of the base (or first) column to use this field
        fields = {}
        for tc in columns:
            tc_options = tc.options
            if tc_options.field in fields.keys():
                # Asking for the same field name twice doesn't work, but
                # is useful when aggregating and choosing a different operation
                # like "min", or "max".  Will populate these columns later
                continue
            fields[tc_options.field] = tc.name
            fieldnames.append(tc_options.field)
            basecolnames.append(tc.name)

        if criteria.entire_pcap:
            starttime = None
            endtime = None
        else:
            starttime = criteria.starttime
            endtime = criteria.endtime

        data = pcapfile.query(
            fieldnames,
            starttime=starttime,
            endtime=endtime,
            filterexpr = criteria.wireshark_filterexpr,
            use_tshark_fields=True)

        if len(data) == 0:
            self.data = None
            return True

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
            if tc.datatype == "time":
                df[tc.name] = pandas.DatetimeIndex(df[tc.name])

        colnames = [col.name for col in columns]
        self.data = df.ix[:,colnames].values.tolist()

        return True


class WiresharkInfoTable(DatasourceTable):

    class Meta:
        proxy = True

    _query_class = 'WiresharkInfoQuery'

    TABLE_OPTIONS = { }
    FIELD_OPTIONS = { }

    def post_process_table(self, field_options):
        fields_add_pcapfile(obj=self)


class WiresharkInfoQuery(TableQueryBase):

    def run(self):
        criteria = self.job.criteria

        pcapfilename = criteria.pcapfilename

        if not pcapfilename:
            raise ValueError("No pcap file specified")
        elif not os.path.exists(pcapfilename):
            raise ValueError("No such file: %s" % pcapfilename)

        if not hasattr(settings, 'TSHARK_PATH'):
            raise ValueError('Please set local_settings.TSHARK_PATH '
                             'to the proper path to the tshark executable')


        pcapfile = PcapFile(pcapfilename)
        pcapfile.info()
        self.data = [['Start time', str(pcapfile.starttime)],
                     ['End time', str(pcapfile.endtime)],
                     ['Number of packets', pcapfile.numpackets]]
        return True
