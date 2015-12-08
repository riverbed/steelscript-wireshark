# Copyright (c) 2015 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""
A data source for querying data from pcap files via tshark
"""

import logging
import os
import math
import copy
import pandas
import shutil
import subprocess
import multiprocessing

from django import forms
from django.conf import settings
from django.forms.widgets import FileInput

from steelscript.wireshark.core.pcap import PcapFile

from steelscript.appfwk.apps.datasource.models \
    import DatasourceTable, TableField, Column, TableQueryBase
from steelscript.appfwk.apps.datasource.forms \
    import FileSelectField, fields_add_resolution, fields_add_time_selection
from steelscript.appfwk.apps.jobs import QueryComplete, QueryContinue, Job
from steelscript.appfwk.apps.datasource.modules.analysis import \
    AnalysisQuery, AnalysisException, AnalysisTable
from steelscript.appfwk.apps.datasource.models import Table

logger = logging.getLogger(__name__)


SPLIT_DIR = '/tmp/split_pcaps'


class WiresharkColumn(Column):
    class Meta:
        proxy = True

    COLUMN_OPTIONS = {'field': None,
                      'operation': 'sum'}


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
             (keyword=keyword,
              label='WireShark Filter Expression',
              help_text=('Traffic expression using WireShark Display '
                         'Filter syntax'),
              initial=initial,
              required=False))
    field.save()
    obj.fields.add(field)


class WiresharkTable(DatasourceTable):

    class Meta:
        proxy = True

    # When a custom column is used, it must be linked
    _column_class = 'WiresharkColumn'
    _query_class = 'WiresharkQuery'

    TABLE_OPTIONS = {'show_upload': True,
                     'show_entire_pcap': True}
    FIELD_OPTIONS = {'resolution': '1m',
                     'resolutions': ('1s', '1m', '15min', '1h'),
                     'pcapfile_astextfield': False}

    def post_process_table(self, field_options):
        #
        # Add criteria fields that are required by this table
        #
        if self.options.show_entire_pcap:
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

        if self.options.show_upload:
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
            filterexpr=criteria.wireshark_filterexpr,
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
        self.data = df.ix[:, colnames].values.tolist()

        return True


class WiresharkInfoTable(DatasourceTable):

    class Meta:
        proxy = True

    _query_class = 'WiresharkInfoQuery'

    TABLE_OPTIONS = {}
    FIELD_OPTIONS = {}

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


class WiresharkPcapTable(AnalysisTable):
    """This table processes downloaded or uploaded PCAP files.
    For the downloaded case, this table looks at the dependant
    table to determine where to find the PCAP file to analyze.
    It also supports uploading a PCAP file to analyze. When
    processing the PCAP file, this table might split the file
    to optimize performance based on the split_threshold table
    option.
    """
    class Meta:
        proxy = True

    _column_class = 'WiresharkColumn'
    _query_class = 'WiresharkPcapQuery'

    TABLE_OPTIONS = {'split_threshold': 0,
                     }

    FIELD_OPTIONS = {'resolution': '1s',
                     'resolutions': ('1s', '1m', '15min', '1h')}


class WiresharkPcapQuery(AnalysisQuery):

    def split_pcap(self):
        cpu_num = multiprocessing.cpu_count()
        per_file = int(math.ceil(self.pkt_num/cpu_num))

        if not os.path.exists(SPLIT_DIR):
            os.mkdir(SPLIT_DIR)
        os.mkdir(self.output_dir)

        cmd = 'editcap -c %s %s %s/' % (per_file, self.filename,
                                        self.output_dir)
        subprocess.Popen(cmd, shell=True).wait()

    @property
    def file_handle(self):
        """Return the basename of the path without extension.
        If filename is 'a/b/c.d', return 'c'.
        """
        return os.path.basename(self.filename).rsplit('.', 1)[0]

    def analyze(self, jobs=None):

        criteria = self.job.criteria

        if jobs:
            job = jobs.values()[0]
            if job.status == Job.ERROR:
                raise AnalysisException("%s for getting pcap file failed: %s"
                                        % (job, job.message))
            criteria.entire_pcap = True
            self.filename = job.data()['filename'][0]
        else:
            self.filename = criteria.pcapfilename

        pcap = PcapFile(self.filename)

        try:
            pcap_info = pcap.info()
        except ValueError:
            raise AnalysisException("No packets in %s" % self.filename)

        logger.debug("%s: File info %s" % (self.__class__.__name__, pcap_info))

        self.pkt_num = int(pcap_info['Number of packets'])

        min_pkt_num = self.table.options.split_threshold

        wt = Table.from_ref(self.table.options.related_tables['wireshark'])

        depjobs = {}
        if self.pkt_num < min_pkt_num:
            # No need to split the pcap file
            criteria.pcapfilename = self.filename
            criteria.entire_pcap = True
            job = Job.create(table=wt, criteria=criteria,
                             update_progress=False, parent=self.job)

            depjobs[job.id] = job

            logger.debug("%s starting single job" % self.__class__.__name__)
            return QueryContinue(self.collect, depjobs)

        self.output_dir = os.path.join(SPLIT_DIR, self.file_handle)
        self.split_pcap()

        split_files = os.listdir(self.output_dir)

        if not split_files:
            raise AnalysisException('No pcap file found after splitting %s'
                                    % self.filename)

        for split in split_files:
            # use wireshark table
            ws_criteria = copy.copy(criteria)
            ws_criteria.pcapfilename = os.path.join(self.output_dir, split)

            # for ease of removing the split directory in collect func
            ws_criteria.output_dir = self.output_dir

            job = Job.create(table=wt, criteria=ws_criteria,
                             update_progress=False, parent=self.job)

            depjobs[job.id] = job

        logger.debug("%s starting multiple jobs" % self.__class__.__name__)

        return QueryContinue(self.collect, jobs=depjobs)

    def collect(self, jobs=None):
        dfs = []

        # Removing the temporary split directory if it exists
        output_dir = getattr(jobs.values()[0].criteria, 'output_dir', None)
        if output_dir and os.path.exists(output_dir):
            shutil.rmtree(output_dir)

        for jid, job in jobs.iteritems():
            if job.status == Job.ERROR:
                raise AnalysisException("%s for pcap file %s failed: %s"
                                        % (job, job.criteria.pcapfilename,
                                           job.message))
            subdf = job.data()
            if subdf is None:
                continue
            dfs.append(subdf)

        if not dfs:
            logger.debug("%s: no data is collected" % self.__class__.__name__)
            return QueryComplete(None)

        df = pandas.concat(dfs, ignore_index=True)

        logger.debug("%s: Query ended." % self.__class__.__name__)

        return QueryComplete(df)
