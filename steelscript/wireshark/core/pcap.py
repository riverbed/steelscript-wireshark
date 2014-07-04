# Copyright (c) 2014 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

import os
import re
import cPickle
import logging
import shlex
import subprocess
import datetime
import tempfile
import pytz
import tzlocal

from dateutil.parser import parse as dateutil_parse
from collections import namedtuple

from steelscript.common.timeutils import parse_timedelta
from steelscript.wireshark.core.exceptions import *


logger = logging.getLogger(__name__)

local_tz = tzlocal.get_localzone()

class PcapFile(object):

    def __init__(self, filename):
        self.filename = filename

        self._info = None
        self.starttime = None
        self.endtime = None

    def info(self):
        if self._info is None:

            cmd = ['capinfos', '-A', '-m', '-T', self.filename]
            logger.info('subprocess: %s' % ' '.join(cmd))
            capinfos = subprocess.check_output(cmd)
            hdrs, vals = (capinfos.split('\n')[:2])
            self._info = dict(zip(hdrs.split(','), vals.split(',')))

            self.starttime = (dateutil_parse(self._info['Start time'])
                              .replace(tzinfo=local_tz))
            self.endtime = (dateutil_parse(self._info['End time'])
                            .replace(tzinfo=local_tz))

            self.numpackets = int(self._info['Number of packets'])

        return self._info

    def export(self, filename,
               starttime=None, endtime=None, duration=None):

        cmd = ['editcap']

        if starttime is not None:
            if isinstance(starttime, basestring):
                starttime = dateutil_parse(starttime)

        if endtime is not None:
            if isinstance(endtime, basestring):
                endtime = dateutil_parse(endtime)

        if duration is not None:
            if isinstance(duration, basestring):
                duration = parse_timedelta(duration)

            if starttime:
                endtime = starttime + duration
            elif endtime:
                starttime = endtime - duration
            else:
                raise ValueError("Must specify either starttime or "
                                 "endtime with duration")

        if starttime is not None:
            cmd.extend(['-A', (starttime
                               .strftime('%Y-%m-%d %H:%M:%S'))])

        if endtime is not None:
            cmd.extend(['-B', (endtime
                               .strftime('%Y-%m-%d %H:%M:%S'))])

        cmd.append(self.filename)
        cmd.append(filename)

        logger.info('subprocess: %s' % ' '.join(cmd))
        o = subprocess.check_output(cmd)

        return PcapFile(filename)

    def delete(self):
        if os.path.exists(self.filename):
            os.unlink(self.filename)

        self.filename = None

    def query(self, fieldnames, filterexpr=None,
              starttime=None, endtime=None, duration=None,
              use_tshark_fields=True,
              occurrence='f',
              as_dataframe=False):

        if not self.filename:
            raise ValueError('No filename')

        cmd = ['tshark', '-r', self.filename,
               '-T', 'fields',
               '-E', 'occurrence=%s' % occurrence,
               '-E', 'aggregator=,']

        if starttime or endtime:
            logger.info("Creating temp pcap file for timerange: %s-%s" % (starttime, endtime))
            (fd, filename) = tempfile.mkstemp(suffix='.pcap')
            os.close(fd)
            p = self.export(filename,
                            starttime=starttime,
                            endtime=endtime,
                            duration=duration)
            logger.info("Issuing query on temp pcap file")
            res = p.query(fieldnames, filterexpr=filterexpr,
                          use_tshark_fields=use_tshark_fields,
                          occurrence=occurrence,
                          as_dataframe=as_dataframe)
            #p.delete()
            return res

        if filterexpr not in [None, '']:
            cmd.extend(['-R', filterexpr])

        fields = []
        for n in fieldnames:
            if use_tshark_fields:
                tf = TSharkFields.instance()
                if n in tf.protocols:
                    # Allow protocols as a field, but convert to a string
                    # rather than attempt to parse it
                    fields.append(TSharkField(n, '', 'FT_STRING', n))

                elif n in tf.fields:
                    fields.append(tf.fields[n])

                else:
                    raise InvalidField(n)


            cmd.extend(['-e', n])

        logger.info('subprocess: %s' % ' '.join(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        data = []
        errors = 0
        while proc.poll() is None:
            line = proc.stdout.readline().rstrip()
            if not line:
                continue
            cols = line.split('\t')
            if len(cols) < len(fieldnames):
                cols.extend([None]*(len(fieldnames) - len(cols)))
            elif len(cols) > len(fieldnames):
                logger.error("Could not parse line: '%s'" % line)
                errors = errors + 1
                if errors > 20:
                    return
                continue

            if use_tshark_fields:
                newcols = []
                for i,col in enumerate(cols):
                    t = fields[i].datatype
                    if col == '' or col is None:
                        col = None
                    elif t == datetime.datetime:
                        col = (dateutil_parse(col)
                               .replace(tzinfo=local_tz))
                    elif fields[i].name == 'frame.time_epoch':
                        col = (datetime.datetime.utcfromtimestamp(float(col))
                               .replace(tzinfo=pytz.utc)
                               .astimezone(local_tz))
                    else:
                        col = t(col)
                    newcols.append(col)
                data.append(newcols)
            else:
                data.append(cols)

        if as_dataframe:
            if len(data) > 0:
                import pandas
                df = pandas.DataFrame(data, columns=fieldnames)
                return df
            else:
                return None
        else:
            return data

class TSharkField(object):

    __slots__ = ['name', 'desc', 'datatype', 'datatype_str', 'protocol']

    def __init__(self, name, desc, datatype, protocol):
        self.name = name
        self.desc = desc
        self.protocol = protocol
        self.datatype_str = datatype

        if re.match('FT_U?INT64.*', datatype):
            self.datatype = long
        elif re.match('FT_(U?INT.*|FRAMENUM)', datatype):
            self.datatype = int
        elif re.match('FT_(FLOAT|DOUBLE|RELATIVE_TIME)', datatype):
            self.datatype = float
        elif re.match('FT_ABSOLUTE_TIME', datatype):
            self.datatype = datetime.datetime
        else:
            self.datatype = str

    def __str__(self):
        return '<TSharkField %s, %s>' % (self.name, self.datatype_str)

    def __repr__(self):
        return str(self)

    def __getstate__(self):
        return [self.name, self.desc, self.datatype_str,
                self.datatype, self.protocol]

    def __setstate__(self, state):
        (self.name, self.desc, self.datatype_str,
         self.datatype, self.protocol) = state

class TSharkFields(object):

    CACHEFILE = os.path.join(os.path.expanduser('~'), '.steelscript',
                             'tshark_fields')
    CACHEFILE_VERSION = 1

    _instance = None

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = TSharkFields()
        return cls._instance

    def __init__(self):
        self.protocols = None
        self.fields = None
        self.load()

    def load(self, force=False, ignore_cache=False, protocols=None):
        """Load"""
        if self.protocols and not force:
            return

        if not ignore_cache and os.path.exists(self.CACHEFILE):
            with open(self.CACHEFILE, 'rb') as f:
                version = cPickle.load(f)
                if version == self.CACHEFILE_VERSION:
                    self.protocols, self.fields = cPickle.load(f)
                    return
            logger.info("Cache file version mistmatch")

        cmd = ['tshark', '-G', 'fields']

        logger.info('subprocess: %s' % ' '.join(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        data = []
        self.protocols = {}
        self.fields = {}
        while proc.poll() is None:
            line = proc.stdout.readline().rstrip()
            if not line:
                continue
            fields = line.split('\t')
            if fields[0] == 'P':
                (t, desc, name) = fields[:3]
                if protocols is not None and name not in protocols:
                    continue
                self.protocols[name] = desc
            elif fields[0] == 'F':
                (t, desc, name, datatype, protocol) = fields[:5]
                if protocols is not None and protocol not in protocols:
                    continue
                self.fields[name] = TSharkField(name, desc, datatype, protocol)

        with open(self.CACHEFILE, 'wb', 2) as f:
            cPickle.dump(self.CACHEFILE_VERSION, f)
            cPickle.dump([self.protocols, self.fields], f)

    def find(self, name=None, name_re=None,
             desc=None, desc_re=None,
             protocol=None, protocol_re=None):
        fields = []
        for field in self.fields.values():
            if ( (name is not None and name != field.name) or
                 (name_re is not None and not re.search(name_re, field.name)) or
                 (desc is not None and desc != field.desc) or
                 (desc_re is not None and not re.search(desc_re, field.desc)) or
                 (protocol is not None and protocol != field.protocol) or
                 (protocol_re is not None and
                  not re.search(protocol_re, field.protocol))):
                continue
            fields.append(field)
        return fields
