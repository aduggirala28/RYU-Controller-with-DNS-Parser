# RYU-Controller-with-DNS-Parser
SDN Controller code in Python. Every DNS Packet is forwarded to the controller  and the controller 
checks for prohibited sites against a database. If the site is prohibited it drops the packet.If not, it is allowed to go
through with rules
being establish with the usual l2-learning process.
The base code is the simple_switch_13.py 
which comes with RYU installation. RYU doesn't provide a DNS packet parser. 
The parser was made with Python DPKT library.
