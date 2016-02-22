Getting Started
===============

Quick Start
-----------

1. Run ``steel mkworkspace`` to create a directory that contains all the SteelScript example scripts.
2. Navigate to ``steelscript-workspace/wireshark-examples/``. There you will find all steelscript-wireshark example scripts.
3. Run ``python pcap_info.py <path-to-your-pcap-file>``. This will print out the pcap file's basic details, similar to the following:

=================================    =======================================
Key                                  Value
=================================    =======================================
File encapsulation                   Ethernet
RIPEMD160                            64855625794452b0d0a5624f004104189a11c8b8
Packet size limit                    65535
Capture duration (seconds)           7.344911
Data byte rate (bytes/sec)           34769.11
Number of packets                    388
File name                            tutorial.pcap
...etc...                            ...etc...
=================================    =======================================

4. Copy one of the example scripts to use as a template. Customize it to fit your needs.

More information on API's `available here <pcap-api.html>`_.


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

