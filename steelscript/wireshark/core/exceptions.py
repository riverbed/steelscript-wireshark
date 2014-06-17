# Copyright (c) 2014 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.


class WiresharkException(Exception):
    pass


class InvalidField(WiresharkException):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return "Invalid Wireshark field: %s" % self.name
