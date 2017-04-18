¡This Project has moved!
====================
Please find the latest commits for sdt at [https://git.psu.edu/sysman/ServiceDiscoveryTool](https://git.psu.edu/sysman/ServiceDiscoveryTool)


macOS Service Discovery Tool
=============================

Python3 script that formats DHCP Request and BSDP Inform packets, broadcasts them on the local network, and then reports the responses. Responses provide insight into the DHCP and NetBoot services clients are able to reach.

Requirements
-----------

**Python3** - Python3 provides better handling of bytes objects

**Admin Privileges** - This script requires sudo rights

Usage
-----

**Run program with: python3 /path/to/sdt.py**

usage: sdt.py [-h] [-d] [-b] [-p PLISTPATH] [-t1]

Check, Print, and Save DHCP & BSDP Information.

optional arguments:
  -h, --help            Show this help message and exit
  -d, --dhcp            Send DHCP Broadcast and process results.
  -b, --bsdp            Send BSDP Inform and process results.
  -p PLISTPATH, -plist PLISTPATH
                        Path to plist for saving results to plist. Default:
                        /Library/Preferences/org.network.plist
  -t1, --testOne        Test code with stored BSDP response from OS X Server,
                        writing to /tmp/org.network.plist.

Installation Instructions
-------------------------
The sdt.py script can be downloaded and placed anywhere on the system. It can be triggered manually or run with a LaunchDaemon.

Logging
-------
The script writes a plist to /Library/Preferences/org.network.plist by default.

Feedback
--------
Please feel free to create pull requests or issues for this project. Suggestions for improvement are most welcome.
