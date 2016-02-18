Riverbed SteelScript for SteelCentral Wireshark 
===============================================

This package provides device specific bindings for interacting
with Riverbed SteelCentral Wireshark devices as part of the Riverbed
SteelScript for Python.

`CLICK HERE TO VIEW DOCS AND GET STARTED <https://support.riverbed.com/apis/steelscript/wireshark/getting-started.html>`_
----------------------------------------

Example Usage
-------------
The following example shows how to use ``pcap_query.py`` to gain insights on how your HTTP traffic is flowing. 
``pcap_query.py`` can be found inside the ``steelscript-workspace/wireshark-examples/`` directory.

.. code-block:: bash

   $ python pcap_query.py my_http_pcap_file.pcap \
     -c "http.request.uri,http.request.method,http.response.code,http.server,http.prev_request_in,http.time"

returns:

================     ===================     ==================    =============    ====================    =========
http.request.uri     http.request.method     http.response.code    http.server      http.prev_request_in    http.time
================     ===================     ==================    =============    ====================    =========
/                    GET                     None                  None             None                    None
None                 None                    200                   Apache/2.2.14    None                    0.080266
/favicon.ico         GET                     None                  None             5                       None
None                 None                    404                   Apache/2.2.14    5                       0.041042
/bhratach            GET                     None                  None             9                       None
None                 None                    301                   Apache/2.2.14    9                       0.000346
/bhratach/           GET                     None                  None             13                      None
None                 None                    200                   Apache/2.2.14    13                      0.066848
================     ===================     ==================    =============    ====================    =========


License
-------

Copyright (c) 2015 Riverbed Technology, Inc.

SteelScript-Wireshark is licensed under the terms and conditions of the MIT
License accompanying the software ("License").  SteelScript-Wireshark is
distributed "AS IS" as set forth in the License.
